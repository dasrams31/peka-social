#!/usr/bin/env python3
"""
Peka -- Threads-style microblogging.
Single file, stdlib only (http.server, sqlite3, hashlib, secrets).
Tor-friendly: zero external resources, all CSS/JS inline, system fonts only.
Core works with JS disabled; JS is progressive enhancement only.
"""
import hashlib
import html
import os
import re
import secrets
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
DB_PATH = os.path.join(DATA_DIR, 'peka.db')
PORT = int(os.environ.get('PORT', '18092'))
HOST = '127.0.0.1'

PBKDF2_ITER = 200_000
SESSION_DAYS = 30
MAX_BODY = 64 * 1024
PAGE_SIZE = 20

RE_USER = re.compile(r'^[a-z0-9_]{3,20}$')
ID_BULAN = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
            'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

# in-memory per-IP rate limits: {(ip, action): [timestamps]}
RL = {}


# ---------------- db ----------------
def db():
    os.makedirs(DATA_DIR, exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    c = db()
    c.execute('PRAGMA journal_mode=WAL')
    c.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        display_name TEXT NOT NULL,
        bio TEXT NOT NULL DEFAULT '',
        salt TEXT NOT NULL,
        pw_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        csrf TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL,
        body TEXT NOT NULL,
        parent_id INTEGER,
        created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS likes (
        user_id INTEGER NOT NULL,
        post_id INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (user_id, post_id)
    );
    CREATE TABLE IF NOT EXISTS reposts (
        user_id INTEGER NOT NULL,
        post_id INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (user_id, post_id)
    );
    CREATE TABLE IF NOT EXISTS follows (
        follower_id INTEGER NOT NULL,
        followee_id INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (follower_id, followee_id)
    );
    CREATE INDEX IF NOT EXISTS idx_posts_parent ON posts(parent_id);
    CREATE INDEX IF NOT EXISTS idx_posts_user ON posts(user_id);
    CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL,
        actor_id INTEGER NOT NULL,
        kind TEXT NOT NULL,
        post_id INTEGER,
        created_at INTEGER NOT NULL,
        read_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS bookmarks (
        user_id INTEGER NOT NULL,
        post_id INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (user_id, post_id)
    );
    CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_bookmarks_user ON bookmarks(user_id, created_at DESC);
    CREATE TABLE IF NOT EXISTS dms (
        id INTEGER PRIMARY KEY,
        sender_id INTEGER NOT NULL,
        recipient_id INTEGER NOT NULL,
        body TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        read_at INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_dms_pair ON dms(sender_id, recipient_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_dms_recip ON dms(recipient_id, read_at);
    ''')
    try:
        c.execute('ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0')
    except Exception:
        pass
    for col in ("ALTER TABLE posts ADD COLUMN edited_at INTEGER",
                "ALTER TABLE posts ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0"):
        try:
            c.execute(col)
        except Exception:
            pass
    c.commit()
    c.close()


# ---------------- helpers ----------------
def now():
    return int(time.time())


def esc(s):
    return html.escape(s if s is not None else '', quote=True)


RE_MENTION = re.compile(r'(?<!\w)@([a-z0-9_]{3,20})')
RE_TAG = re.compile(r'(?<!\w)#([A-Za-z0-9_]{2,40})')


def render_body(body):
    """Escape text, then linkify @mentions and #hashtags."""
    h = esc(body)
    h = RE_MENTION.sub(lambda m: '<a href="/@%s" class="hl">@%s</a>' % (m.group(1), m.group(1)), h)
    h = RE_TAG.sub(lambda m: '<a href="/tag/%s" class="hl">#%s</a>' % (m.group(1).lower(), m.group(1)), h)
    return h


def extract_tags(body):
    return {m.group(1).lower() for m in RE_TAG.finditer(body or '')}


def notify(c, user_id, actor_id, kind, post_id=None):
    if not user_id or user_id == actor_id:
        return
    c.execute('INSERT INTO notifications (user_id, actor_id, kind, post_id, created_at)'
              ' VALUES (?,?,?,?,?)', (user_id, actor_id, kind, post_id, now()))


def dm_unread_count(c, user_id):
    row = c.execute('SELECT COUNT(*) FROM dms WHERE recipient_id=? AND read_at IS NULL',
                    (user_id,)).fetchone()
    return row[0] if row else 0


def process_mentions(c, body, author_id, post_id):
    for m in RE_MENTION.finditer(body or ''):
        u = c.execute('SELECT id FROM users WHERE username=?', (m.group(1),)).fetchone()
        if u:
            notify(c, u['id'], author_id, 'mention', post_id)


def unread_count(c, user_id):
    row = c.execute('SELECT COUNT(*) FROM notifications WHERE user_id=? AND read_at IS NULL',
                    (user_id,)).fetchone()
    return row[0] if row else 0


def rel_time(ts):
    d = now() - int(ts)
    if d < 60:
        return 'just now'
    if d < 3600:
        return '%d min' % (d // 60)
    if d < 86400:
        return '%d hr' % (d // 3600)
    if d < 7 * 86400:
        return '%d d' % (d // 86400)
    t = time.localtime(int(ts))
    return '%d %s %d' % (t.tm_mday, ID_BULAN[t.tm_mon - 1], t.tm_year)


def full_date(ts):
    t = time.localtime(int(ts))
    return '%d %s %d' % (t.tm_mday, ID_BULAN[t.tm_mon - 1], t.tm_year)


def hash_pw(pw, salt_hex):
    salt = bytes.fromhex(salt_hex)
    h = hashlib.pbkdf2_hmac('sha256', pw.encode('utf-8'), salt, PBKDF2_ITER)
    return h.hex()


AVATAR_COLORS = ['#3b5bdb', '#2f9e44', '#e67700', '#d6336c',
                 '#0c8599', '#7048e8', '#a61e4d', '#5c940d']


def avatar_color(username):
    h = int(hashlib.sha256(username.encode()).hexdigest(), 16)
    return AVATAR_COLORS[h % len(AVATAR_COLORS)]


def rl_ok(ip, action, limit, window=3600):
    t = time.time()
    key = (ip, action)
    lst = [x for x in RL.get(key, []) if t - x < window]
    if len(lst) >= limit:
        RL[key] = lst
        return False
    lst.append(t)
    RL[key] = lst
    return True


def new_session(c, user_id):
    token = secrets.token_hex(32)
    csrf = secrets.token_hex(16)
    t = now()
    c.execute('INSERT INTO sessions (token, user_id, csrf, created_at, expires_at)'
              ' VALUES (?,?,?,?,?)',
              (token, user_id, csrf, t, t + SESSION_DAYS * 86400))
    c.commit()
    return token, csrf


def get_session_user(c, cookie_header):
    if not cookie_header:
        return None, None
    token = None
    for part in cookie_header.split(';'):
        part = part.strip()
        if part.startswith('peka_session='):
            token = part[len('peka_session='):].strip()
            break
    if not token or not re.fullmatch(r'[0-9a-f]{64}', token):
        return None, None
    row = c.execute('SELECT s.token, s.user_id, s.csrf, u.id, u.username,'
                    ' u.display_name, u.is_admin FROM sessions s JOIN users u ON u.id=s.user_id'
                    ' WHERE s.token=? AND s.expires_at>?',
                    (token, now())).fetchone()
    if not row:
        return None, None
    user = {'id': row['id'], 'username': row['username'],
            'display_name': row['display_name'],
            'is_admin': bool(row['is_admin']),
            'unread': unread_count(c, row['id']),
            'dm_unread': dm_unread_count(c, row['id'])}
    sess = {'token': row['token'], 'csrf': row['csrf']}
    return user, sess


# ---------------- html ----------------
CSS = """
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0d0d0e;--panel:#151517;--panel2:#1c1c1f;--border:#232326;--border2:#323237;
--text:#f4f4f5;--muted:#9c9ca6;--faint:#63636c;--red:#f43f5e;--green:#34d399;--link:#8ab4ff}
html{-webkit-text-size-adjust:100%}
body{background:var(--bg);color:var(--text);
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
line-height:1.5;font-size:15px;-webkit-font-smoothing:antialiased}
a{color:inherit;text-decoration:none}
button{font-family:inherit}
.wrap{max-width:640px;margin:0 auto;min-height:100vh;
border-left:1px solid var(--border);border-right:1px solid var(--border);background:var(--bg)}
@media(max-width:660px){.wrap{border-left:none;border-right:none}}
.topbar{position:sticky;top:0;z-index:20;background:rgba(13,13,14,.88);
backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
border-bottom:1px solid var(--border)}
.topbar-in{max-width:640px;margin:0 auto;display:flex;align-items:center;
justify-content:space-between;padding:10px 16px;gap:8px}
.wordmark{font-size:21px;font-weight:800;letter-spacing:-.03em;flex:none}
.wordmark .dot{color:var(--faint)}
.nav{display:flex;gap:2px;align-items:center;overflow-x:auto;scrollbar-width:none}
.nav::-webkit-scrollbar{display:none}
.nav a{padding:7px 12px;border-radius:999px;color:var(--muted);font-weight:600;
font-size:13.5px;white-space:nowrap;transition:background .15s,color .15s;position:relative}
.nav a:hover{background:var(--panel2);color:var(--text)}
.nav a.on{color:var(--text);background:var(--panel2)}
.tabs{display:flex;border-bottom:1px solid var(--border);background:var(--bg)}
.tabs a{flex:1;text-align:center;padding:13px 8px;font-weight:700;color:var(--muted);
border-bottom:2px solid transparent;font-size:14px;transition:color .15s}
.tabs a:hover{color:var(--text)}
.tabs a.on{color:var(--text);border-bottom-color:var(--text)}
.compose{display:flex;gap:12px;padding:16px;border-bottom:1px solid var(--border)}
.compose form{flex:1;min-width:0}
textarea{width:100%;background:transparent;border:none;color:var(--text);
font-size:16px;font-family:inherit;resize:vertical;min-height:48px;outline:none;line-height:1.5}
textarea::placeholder{color:var(--faint)}
.crow{display:flex;justify-content:flex-end;align-items:center;gap:10px;margin-top:10px}
.ccount{color:var(--faint);font-size:13px;font-variant-numeric:tabular-nums}
button.btn{background:var(--text);color:#0d0d0e;border:none;border-radius:999px;
padding:8px 20px;font-weight:700;font-size:14px;cursor:pointer;
transition:transform .1s,opacity .15s}
button.btn:hover{opacity:.88}
button.btn:active{transform:scale(.97)}
button.btn:disabled{opacity:.35;cursor:default;transform:none}
.post{display:flex;gap:12px;padding:15px 16px;border-bottom:1px solid var(--border);
transition:background .15s}
a .post:hover,div.post:hover{background:#111112}
.avatar{flex:none;width:42px;height:42px;border-radius:50%;display:flex;
align-items:center;justify-content:center;font-weight:700;font-size:17px;color:#fff;
letter-spacing:-.02em}
.pbody{flex:1;min-width:0}
.phead{display:flex;align-items:baseline;gap:6px;flex-wrap:wrap}
.phead .nm{font-weight:700;font-size:14.5px;letter-spacing:-.01em}
.phead .nm:hover{text-decoration:underline}
.phead .un{color:var(--faint);font-size:13px}
.phead .tm{color:var(--faint);font-size:12.5px;margin-left:auto;flex:none;
font-variant-numeric:tabular-nums}
.repostline{color:var(--faint);font-size:12.5px;margin-bottom:6px;font-weight:600}
.ptext{white-space:pre-wrap;word-wrap:break-word;overflow-wrap:break-word;
margin:3px 0 10px;font-size:15px;line-height:1.55}
.actions{display:flex;gap:2px;align-items:center;margin-left:-8px}
.act{background:none;border:none;color:var(--faint);cursor:pointer;display:flex;
align-items:center;gap:6px;font-size:12.5px;padding:7px 10px;border-radius:999px;
transition:background .15s,color .15s;font-variant-numeric:tabular-nums}
.act svg{width:18px;height:18px;transition:transform .15s}
.act:hover{background:rgba(138,180,255,.09);color:var(--link)}
.act:hover svg{transform:scale(1.08)}
.act.liked{color:var(--red)}
.act.liked:hover{background:rgba(244,63,94,.09)}
.act.reposted{color:var(--green)}
.act.reposted:hover{background:rgba(52,211,153,.09)}
.act.bookmarked{color:var(--green)}
.act.danger:hover{color:var(--red);background:rgba(244,63,94,.09)}
.empty{padding:56px 24px;text-align:center;color:var(--faint);font-size:14px}
.pager{display:flex;justify-content:center;gap:10px;padding:18px}
.pager a{padding:8px 20px;border:1px solid var(--border2);border-radius:999px;
font-size:13.5px;font-weight:600;color:var(--muted);transition:border-color .15s,color .15s}
.pager a:hover{border-color:var(--muted);color:var(--text)}
.profile{padding:22px 18px 14px;border-bottom:1px solid var(--border)}
.prow{display:flex;justify-content:space-between;align-items:flex-start;gap:14px}
.pname{font-size:21px;font-weight:800;letter-spacing:-.02em}
.puser{color:var(--faint);font-size:14px;margin:3px 0 10px}
.pbio{white-space:pre-wrap;word-wrap:break-word;margin:10px 0;font-size:14.5px;line-height:1.55}
.pmeta{color:var(--faint);font-size:13px;display:flex;gap:16px;flex-wrap:wrap;margin-top:10px}
.pmeta b{color:var(--text);font-variant-numeric:tabular-nums}
.bioform textarea{background:var(--panel);border:1px solid var(--border2);
border-radius:12px;padding:12px;margin:10px 0;min-height:64px;font-size:14px;
transition:border-color .15s}
.bioform textarea:focus{border-color:var(--muted)}
.formbox{max-width:400px;margin:48px auto;padding:0 22px}
.formbox h1{font-size:26px;margin-bottom:8px;letter-spacing:-.02em;font-weight:800}
.formbox p.sub{color:var(--muted);margin-bottom:24px;font-size:14px}
.field{margin-bottom:16px}
.field label{display:block;font-size:12.5px;font-weight:600;margin-bottom:7px;color:var(--muted)}
.field input{width:100%;background:var(--panel);border:1px solid var(--border2);
border-radius:12px;padding:13px 14px;color:var(--text);font-size:15px;font-family:inherit;
transition:border-color .15s}
.field input:focus{outline:none;border-color:var(--muted)}
.err{background:rgba(244,63,94,.08);border:1px solid rgba(244,63,94,.35);color:#fda4b4;
padding:12px 16px;border-radius:12px;margin-bottom:18px;font-size:14px}
.searchbar{padding:14px 16px;border-bottom:1px solid var(--border);display:flex;gap:8px}
.searchbar input{flex:1;background:var(--panel);border:1px solid var(--border2);
border-radius:999px;padding:11px 18px;color:var(--text);font-size:15px;font-family:inherit;
transition:border-color .15s;min-width:0}
.searchbar input:focus{outline:none;border-color:var(--muted)}
.urow{display:flex;gap:12px;align-items:center;padding:13px 16px;
border-bottom:1px solid var(--border);transition:background .15s}
.urow:hover{background:#111112}
.urow .who{flex:1;min-width:0}
.detail-head{padding:14px 16px;border-bottom:1px solid var(--border);
color:var(--faint);font-size:13px;font-weight:600}
.detail-head a{font-weight:700;color:var(--text)}
.detail-head a:hover{text-decoration:underline}
.replybox{border-bottom:1px solid var(--border)}
.hl{color:var(--link);font-weight:600}
.hl:hover{text-decoration:underline}
.badge{display:inline-block;min-width:19px;height:19px;line-height:19px;
text-align:center;font-size:11px;font-weight:700;background:var(--red);
color:#fff;border-radius:10px;padding:0 6px;margin-left:5px;vertical-align:1px;
font-variant-numeric:tabular-nums}
.pinbadge{display:inline-block;font-size:10.5px;font-weight:700;letter-spacing:.04em;
text-transform:uppercase;color:var(--green);border:1px solid rgba(52,211,153,.4);
border-radius:5px;padding:2px 7px;margin-bottom:6px}
.edited{color:var(--faint);font-size:12px}
.notif{display:flex;gap:12px;padding:14px 16px;border-bottom:1px solid var(--border);
transition:background .15s;align-items:flex-start}
.notif:hover{background:#111112}
.notif.unread{background:#131316;box-shadow:inset 2px 0 0 var(--red)}
.notif .nt{font-size:14px;line-height:1.5}
.notif .nm2{font-weight:700}
.notif .nm2:hover{text-decoration:underline}
.ptitle{font-size:19px;font-weight:800;padding:18px 16px 6px;letter-spacing:-.02em}
.tagbox{display:flex;flex-wrap:wrap;gap:8px;padding:12px 16px 16px}
.tagchip{border:1px solid var(--border2);border-radius:999px;padding:7px 14px;
font-size:13.5px;font-weight:600;background:var(--panel);color:var(--muted);
transition:border-color .15s,color .15s}
.tagchip:hover{border-color:var(--muted);color:var(--text)}
.tagchip .tm{font-size:12px}
.setrow{padding:18px 16px;border-bottom:1px solid var(--border)}
.setrow label{display:block;font-size:12.5px;font-weight:600;margin-bottom:7px;color:var(--muted)}
.setrow input{width:100%;background:var(--panel);border:1px solid var(--border2);
color:var(--text);border-radius:12px;padding:12px 14px;font-size:15px;font-family:inherit;
transition:border-color .15s}
.setrow input:focus{outline:none;border-color:var(--muted)}
.setrow a{font-weight:600;font-size:14px}
.setrow a:hover{text-decoration:underline}
.footer{padding:28px 16px 36px;text-align:center;color:var(--faint);font-size:12px}
a:focus-visible,button:focus-visible,input:focus-visible,textarea:focus-visible{
outline:2px solid var(--link);outline-offset:2px}
@media(max-width:480px){
.post{padding:13px 14px}
.compose{padding:13px 14px}
.nav a{padding:7px 10px;font-size:13px}
.pname{font-size:19px}
}
.adminbadge{display:inline-block;font-size:10px;font-weight:800;letter-spacing:.05em;
background:var(--text);color:#0d0d0e;border-radius:4px;padding:2px 6px;vertical-align:2px}
.dmthread{padding:16px;display:flex;flex-direction:column;gap:8px;max-width:640px}
.dmrow{display:flex}
.dmrow.mine{justify-content:flex-end}
.dmbubble{max-width:78%;background:var(--panel2);border:1px solid var(--border);
border-radius:16px;padding:10px 14px;font-size:14.5px;line-height:1.5;
white-space:pre-wrap;word-wrap:break-word}
.dmrow.mine .dmbubble{background:#2a2a30;border-color:#2a2a30}
.dmtime{font-size:11px;color:var(--faint);margin-top:4px;font-variant-numeric:tabular-nums}
.dmcompose{position:sticky;bottom:0;background:rgba(13,13,14,.92);
backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
border-top:1px solid var(--border);padding:12px 16px}
.dmcompose form{display:flex;gap:8px}
.dmcompose input[name=body]{flex:1;background:var(--panel);border:1px solid var(--border2);
border-radius:999px;padding:12px 18px;color:var(--text);font-size:16px;font-family:inherit;
min-width:0;transition:border-color .15s}
.dmcompose input[name=body]:focus{outline:none;border-color:var(--muted)}
@media(max-width:480px){
.post{padding:14px}
.compose{padding:14px}
.nav a{padding:8px 11px;font-size:13px}
.pname{font-size:19px}
.act{padding:10px 12px;font-size:13px;min-height:44px}
.act svg{width:20px;height:20px}
button.btn{padding:10px 22px;min-height:44px}
.topbar-in{padding:10px 12px}
.dmcompose{padding:10px 12px}
.dmbubble{max-width:86%}
textarea{font-size:16px}
.searchbar input{font-size:16px}
.setrow input{font-size:16px}
.field input{font-size:16px}
}
"""

ICON_REPLY = ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"'
              ' stroke-width="2"><path d="M21 12a8 8 0 0 1-8 8H5l-2 2V12a8 8 0 0 1 8-8h2a8 8 0 0 1 8 8z"/></svg>')
ICON_REPOST = ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"'
               ' stroke-width="2"><path d="M17 2l4 4-4 4"/><path d="M3 11v-1a4 4 0 0 1 4-4h14"/>'
               '<path d="M7 22l-4-4 4-4"/><path d="M21 13v1a4 4 0 0 1-4 4H3"/></svg>')
ICON_LIKE = ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"'
             ' stroke-width="2"><path d="M12 21C7 16.5 3 13 3 8.8 3 6 5.2 4 7.8 4c1.7 0 3.2.9 4.2 2.3C13 4.9 14.5 4 16.2 4 18.8 4 21 6 21 8.8c0 4.2-4 7.7-9 12.2z"/></svg>')
ICON_LIKE_FILL = ('<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 21C7 16.5 3 13 3 8.8 3 6 5.2 4 7.8 4c1.7 0 3.2.9 4.2 2.3C13 4.9 14.5 4 16.2 4 18.8 4 21 6 21 8.8c0 4.2-4 7.7-9 12.2z"/></svg>')
ICON_BOOKMARK = ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"'
                 ' stroke-width="2"><path d="M6 3h12v18l-6-4-6 4z"/></svg>')


def avatar_html(username, size=40):
    return ('<div class="avatar" style="background:%s">%s</div>'
            % (avatar_color(username), esc(username[0].upper())))


def page(title, user, body_html, nav='beranda'):
    if user:
        nb = user.get('unread', 0)
        bell = 'Notifications' + ('<span class="badge">%d</span>' % nb if nb else '')
        dm = user.get('dm_unread', 0)
        msg = 'Messages' + ('<span class="badge">%d</span>' % dm if dm else '')
        nav_html = ('<a href="/" class="%s">Home</a>'
                    '<a href="/jelajahi" class="%s">Explore</a>'
                    '<a href="/notifikasi" class="%s">%s</a>'
                    '<a href="/dm" class="%s">%s</a>'
                    '<a href="/cari" class="%s">Search</a>'
                    '<a href="/@%s" class="%s">Profile</a>') % (
                        'on' if nav == 'beranda' else '',
                        'on' if nav == 'jelajahi' else '',
                        'on' if nav == 'notifikasi' else '', bell,
                        'on' if nav == 'dm' else '', msg,
                        'on' if nav == 'cari' else '',
                        esc(user['username']),
                        'on' if nav == 'profil' else '')
    else:
        nav_html = ('<a href="/" class="%s">Home</a>'
                    '<a href="/jelajahi" class="%s">Explore</a>'
                    '<a href="/cari" class="%s">Search</a>'
                    '<a href="/masuk">Log in</a>') % (
                        'on' if nav == 'beranda' else '',
                        'on' if nav == 'jelajahi' else '',
                        'on' if nav == 'cari' else '')
    return ('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>%s - Peka</title><style>%s</style></head>'
            '<body><div class="wrap">'
            '<div class="topbar"><div class="topbar-in">'
            '<a class="wordmark" href="/">Peka<span class="dot">.</span></a>'
            '<nav class="nav">%s</nav>'
            '</div></div>%s'
            '<div class="footer">Peka &mdash; simple microblogging over Tor</div>'
            '</div>'
            '<script>'
            'document.querySelectorAll("textarea[name=body]").forEach(function(t){'
            'var c=t.closest("form").querySelector(".ccount");'
            'if(!c)return;'
            'function u(){var r=500-t.value.length;c.textContent=r;}'
            't.addEventListener("input",u);u();});'
            '</script>'
            '</body></html>') % (esc(title), CSS, nav_html, body_html)


def fmt_count(n):
    n = int(n)
    if n >= 1000000:
        return '%.1fM' % (n / 1000000)
    if n >= 1000:
        return '%.1fK' % (n / 1000)
    return str(n)


def act_form(action, post_id, csrf, nxt, inner, cls=''):
    return ('<form method="post" action="%s" style="display:inline">'
            '<input type="hidden" name="csrf" value="%s">'
            '<input type="hidden" name="id" value="%d">'
            '<input type="hidden" name="next" value="%s">'
            '<button type="submit" class="act %s">%s</button></form>'
            ) % (action, esc(csrf), post_id, esc(nxt), cls, inner)


def post_row(r, user, csrf, nxt, show_reposter=True):
    """r: sqlite Row with post fields + counts + author/reposter info."""
    author_link = '/@' + r['username']
    admin_badge = (' <span class="adminbadge">ADMIN</span>' if r.get('author_admin') else '')
    head = ('<div class="phead"><a class="nm" href="%s">%s</a>%s'
            '<span class="un">@%s</span>'
            '<span class="tm">%s</span></div>') % (
                author_link, esc(r['display_name']), admin_badge,
                esc(r['username']), esc(rel_time(r['sort_time'])))
    repost_line = ''
    if show_reposter and r['reposter_name']:
        repost_line = ('<div class="repostline">%s reposted</div>'
                       % esc(r['reposter_name']))
    detail_link = '/utas/%d' % r['post_id']
    edited = ('<span class="edited"> - edited</span>' if r.get('edited_at') else '')
    pinbadge = ('<span class="pinbadge">Pinned</span>' if r.get('pinned') else '')
    actions = ['<a class="act" href="%s">%s<span>%s</span></a>'
               % (detail_link, ICON_REPLY, fmt_count(r['n_reply']))]
    if user:
        rp_cls = 'reposted' if r['reposted_by_me'] else ''
        rp_icon = ICON_REPOST
        actions.append(act_form('/repost', r['post_id'], csrf, nxt,
                                '%s<span>%s</span>' % (rp_icon, fmt_count(r['n_repost'])),
                                rp_cls))
        lk_cls = 'liked' if r['liked_by_me'] else ''
        lk_icon = ICON_LIKE_FILL if r['liked_by_me'] else ICON_LIKE
        actions.append(act_form('/suka', r['post_id'], csrf, nxt,
                                '%s<span>%s</span>' % (lk_icon, fmt_count(r['n_like'])),
                                lk_cls))
        bk_cls = 'bookmarked' if r.get('bookmarked_by_me') else ''
        actions.append(act_form('/bookmark', r['post_id'], csrf, nxt,
                                ICON_BOOKMARK, bk_cls))
        if r['author_id'] == user['id']:
            actions.append('<a class="act" href="/edit?id=%d&next=%s">Edit</a>'
                           % (r['post_id'], esc(nxt)))
            pin_label = 'Unpin' if r.get('pinned') else 'Pin'
            actions.append(act_form('/pin', r['post_id'], csrf, nxt, pin_label, ''))
            actions.append(act_form('/hapus', r['post_id'], csrf, nxt,
                                    'Delete', 'danger'))
        elif user.get('is_admin'):
            actions.append(act_form('/hapus', r['post_id'], csrf, nxt,
                                    'Mod delete', 'danger'))
    else:
        actions.append('<span class="act">%s<span>%s</span></span>'
                       % (ICON_REPOST, fmt_count(r['n_repost'])))
        actions.append('<span class="act">%s<span>%s</span></span>'
                       % (ICON_LIKE, fmt_count(r['n_like'])))
    return ('<article class="post">%s<div class="pbody">%s%s%s'
            '<a href="%s" style="display:block"><div class="ptext">%s%s</div></a>'
            '<div class="actions">%s</div>'
            '</div></article>') % (
                avatar_html(r['username']), repost_line, pinbadge, head,
                detail_link, render_body(r['body']), edited, ''.join(actions))


def compose_box(csrf, user=None, parent_id=None, placeholder='Start a thread...'):
    hid = ''
    if parent_id:
        hid = '<input type="hidden" name="parent_id" value="%d">' % parent_id
    av = avatar_html(user['username']) if user else ''
    return ('<div class="compose">%s<form method="post" action="/tulis">'
            '<input type="hidden" name="csrf" value="%s">%s'
            '<textarea name="body" maxlength="500" placeholder="%s" required></textarea>'
            '<div class="crow"><span class="ccount">500</span>'
            '<button class="btn" type="submit">Post</button></div>'
            '</form></div>') % (av, esc(csrf), hid, esc(placeholder))


# ---------------- queries ----------------
FEED_SQL = '''
SELECT f.kind, f.post_id, f.author_id, u.username, u.display_name, u.is_admin AS author_admin,
       f.body, f.edited_at, f.pinned, f.sort_time, f.reposter_id, ru.username AS reposter_name,
       (SELECT COUNT(*) FROM likes l WHERE l.post_id=f.post_id) AS n_like,
       (SELECT COUNT(*) FROM reposts r WHERE r.post_id=f.post_id) AS n_repost,
       (SELECT COUNT(*) FROM posts ch WHERE ch.parent_id=f.post_id) AS n_reply
FROM (
  SELECT 'post' AS kind, p.id AS post_id, p.user_id AS author_id,
         p.body, p.edited_at, p.pinned, p.created_at AS sort_time, NULL AS reposter_id
  FROM posts p WHERE p.parent_id IS NULL
  UNION ALL
  SELECT 'repost', p.id, p.user_id, p.body, p.edited_at, p.pinned, r.created_at, r.user_id
  FROM reposts r JOIN posts p ON p.id=r.post_id WHERE p.parent_id IS NULL
) f
JOIN users u ON u.id=f.author_id
LEFT JOIN users ru ON ru.id=f.reposter_id
'''

POST_SQL = '''
SELECT p.id AS post_id, p.user_id AS author_id, u.username, u.display_name, u.is_admin AS author_admin,
       p.body, p.edited_at, p.pinned, p.created_at AS sort_time, p.parent_id,
       NULL AS reposter_name, NULL AS reposter_id, 'post' AS kind,
       (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) AS n_like,
       (SELECT COUNT(*) FROM reposts r WHERE r.post_id=p.id) AS n_repost,
       (SELECT COUNT(*) FROM posts ch WHERE ch.parent_id=p.id) AS n_reply
FROM posts p JOIN users u ON u.id=p.user_id
'''

ERRS = {
    'u_taken': 'Username is already taken.',
    'u_bad': 'Username must be 3-20 chars: lowercase letters, numbers, underscore.',
    'd_bad': 'Display name is required, max 40 characters.',
    'p_short': 'Password must be at least 8 characters.',
    'p_mismatch': 'Password confirmation does not match.',
    'rl': 'Too many attempts. Try again in an hour.',
    'bad_login': 'Wrong username or password.',
}


class Handler(BaseHTTPRequestHandler):
    server_version = 'Peka/1.0'

    def log_message(self, fmt, *args):
        pass  # keep logs quiet; uncomment for debugging

    # ----- plumbing -----
    def send_html(self, code, body, cookie=None):
        data = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, loc, cookie=None):
        self.send_response(303)
        self.send_header('Location', loc)
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()

    def parse_form(self):
        try:
            n = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            n = 0
        if n > MAX_BODY or n < 0:
            return None
        raw = self.rfile.read(n) if n else b''
        return parse_qs(raw.decode('utf-8', 'replace'), keep_blank_values=True)

    def csrf_ok(self, form):
        if not self.user or not self.sess:
            return False
        t = form.get('csrf', [''])[0]
        return secrets.compare_digest(t, self.sess['csrf'])

    def safe_next(self, form):
        nxt = form.get('next', ['/'])[0]
        if nxt.startswith('/') and not nxt.startswith('//') and '\\' not in nxt:
            return nxt
        return '/'

    def ip(self):
        return self.client_address[0]

    def err_page(self, code, msg):
        u = getattr(self, 'user', None)
        self.send_html(code, page('Error', u,
                                  '<div class="empty"><h2>%s</h2></div>' % esc(msg)))

    # ----- dispatch -----
    def do_GET(self):
        self.dispatch(False)

    def do_POST(self):
        self.dispatch(True)

    def dispatch(self, is_post):
        parsed = urlparse(self.path)
        self.ppath = parsed.path
        self.query = parse_qs(parsed.query)
        try:
            self.c = db()
        except Exception:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b'database unavailable')
            return
        try:
            self.user, self.sess = get_session_user(
                self.c, self.headers.get('Cookie'))
            if is_post:
                self.route_post()
            else:
                self.route_get()
        except BrokenPipeError:
            pass
        except Exception:
            try:
                self.err_page(500, 'An internal server error occurred.')
            except BrokenPipeError:
                pass
        finally:
            self.c.close()

    # ----- GET routes -----
    def route_get(self):
        p = self.ppath
        if p == '/':
            return self.handle_feed()
        if p == '/cari':
            return self.handle_search()
        if p == '/masuk':
            return self.handle_auth_page('masuk')
        if p == '/daftar':
            return self.handle_auth_page('daftar')
        if p == '/profil':
            if self.user:
                return self.redirect('/@' + self.user['username'])
            return self.redirect('/masuk')
        if p.startswith('/@'):
            return self.handle_profile(p[2:])
        if p.startswith('/utas/'):
            return self.handle_detail(p[len('/utas/'):])
        if p == '/notifikasi':
            return self.handle_notifikasi()
        if p == '/jelajahi':
            return self.handle_jelajahi()
        if p == '/bookmark':
            return self.handle_bookmarks()
        if p == '/pengaturan':
            return self.handle_pengaturan()
        if p == '/edit':
            return self.handle_edit()
        if p.startswith('/tag/'):
            return self.handle_tag(p[len('/tag/'):])
        if p == '/dm':
            return self.handle_dm_inbox()
        if p.startswith('/dm/'):
            return self.handle_dm_thread(p[len('/dm/'):])
        self.err_page(404, 'Page not found.')

    def feed_items(self, where, params, limit, offset):
        c = self.c
        me = self.user['id'] if self.user else None
        rows = c.execute(FEED_SQL + where +
                         ' ORDER BY f.sort_time DESC, f.post_id DESC LIMIT ? OFFSET ?',
                         params + [limit, offset]).fetchall()
        liked, reposted, bookmarked = set(), set(), set()
        if me:
            liked = {r[0] for r in
                     c.execute('SELECT post_id FROM likes WHERE user_id=?', (me,))}
            reposted = {r[0] for r in
                        c.execute('SELECT post_id FROM reposts WHERE user_id=?', (me,))}
            bookmarked = {r[0] for r in
                          c.execute('SELECT post_id FROM bookmarks WHERE user_id=?', (me,))}
        items, seen = [], set()
        for row in rows:
            d = dict(row)
            if d['post_id'] in seen:
                continue
            seen.add(d['post_id'])
            d['liked_by_me'] = d['post_id'] in liked
            d['reposted_by_me'] = d['post_id'] in reposted
            d['bookmarked_by_me'] = d['post_id'] in bookmarked
            items.append(d)
        return items

    def handle_feed(self):
        tab = self.query.get('tab', ['semua'])[0]
        if tab not in ('semua', 'mengikuti'):
            tab = 'semua'
        try:
            pg = max(1, int(self.query.get('page', ['1'])[0]))
        except ValueError:
            pg = 1
        where, params = '', []
        if tab == 'mengikuti':
            if not self.user:
                return self.redirect('/masuk')
            me = self.user['id']
            fids = [r[0] for r in self.c.execute(
                'SELECT followee_id FROM follows WHERE follower_id=?', (me,))]
            fids.append(me)
            ph = ','.join('?' * len(fids))
            where = ('WHERE (f.author_id IN (%s) OR f.reposter_id IN (%s))'
                     % (ph, ph))
            params = fids + fids
        items = self.feed_items(where, params, PAGE_SIZE + 11,
                                (pg - 1) * PAGE_SIZE)
        shown = items[:PAGE_SIZE]
        has_next = len(items) > PAGE_SIZE
        nxt = '/?tab=%s&page=%d' % (tab, pg)
        csrf = self.sess['csrf'] if self.sess else ''
        body = ('<div class="tabs">'
                '<a href="/?tab=semua" class="%s">All</a>'
                '<a href="/?tab=mengikuti" class="%s">Following</a></div>') % (
                    'on' if tab == 'semua' else '',
                    'on' if tab == 'mengikuti' else '')
        if self.user:
            body += compose_box(csrf, self.user)
        else:
            body += ('<div class="empty">Log in or sign up to start writing threads. '
                     '<a href="/masuk" style="font-weight:700;text-decoration:underline">Log in</a></div>')
        if not shown:
            body += '<div class="empty">No threads here yet.</div>'
        for d in shown:
            body += post_row(d, self.user, csrf, nxt)
        if pg > 1 or has_next:
            prev = ('<a href="/?tab=%s&page=%d">Previous</a>' % (tab, pg - 1)
                    if pg > 1 else '')
            nex = ('<a href="/?tab=%s&page=%d">Next</a>' % (tab, pg + 1)
                   if has_next else '')
            body += '<div class="pager">%s%s</div>' % (prev, nex)
        self.send_html(200, page('Home', self.user, body, 'beranda'))

    def handle_search(self):
        q = self.query.get('q', [''])[0].strip()[:40]
        csrf = self.sess['csrf'] if self.sess else ''
        nxt = '/cari?q=' + q.replace(' ', '+') if q else '/cari'
        body = ('<form class="searchbar" method="get" action="/cari">'
                '<input name="q" maxlength="40" placeholder="Search people..." value="%s">'
                '<button class="btn" type="submit">Search</button></form>') % esc(q)
        if q:
            like = '%' + q.replace('%', '').replace('_', '') + '%'
            rows = self.c.execute(
                'SELECT id, username, display_name, bio FROM users '
                'WHERE username LIKE ? OR display_name LIKE ? LIMIT 20',
                (like, like)).fetchall()
            if not rows:
                body += '<div class="empty">No results found for "%s".</div>' % esc(q)
            for r in rows:
                btn = ''
                if self.user and r['id'] != self.user['id']:
                    f = self.c.execute(
                        'SELECT 1 FROM follows WHERE follower_id=? AND followee_id=?',
                        (self.user['id'], r['id'])).fetchone()
                    lbl = 'Unfollow' if f else 'Follow'
                    btn = ('<form method="post" action="/ikuti">'
                           '<input type="hidden" name="csrf" value="%s">'
                           '<input type="hidden" name="username" value="%s">'
                           '<input type="hidden" name="next" value="%s">'
                           '<button class="btn" type="submit">%s</button></form>'
                           ) % (esc(csrf), esc(r['username']), esc(nxt), lbl)
                body += ('<div class="urow">%s<div class="who">'
                         '<a href="/@%s"><b>%s</b></a> '
                         '<span style="color:var(--muted)">@%s</span>'
                         '<div style="color:var(--muted);font-size:13px">%s</div>'
                         '</div>%s</div>') % (
                    avatar_html(r['username']), esc(r['username']),
                    esc(r['display_name']), esc(r['username']),
                    esc(r['bio'][:80]), btn)
        self.send_html(200, page('Search', self.user, body, 'cari'))

    def handle_auth_page(self, which):
        if self.user:
            return self.redirect('/')
        err = self.query.get('err', [''])[0]
        emsg = ERRS.get(err, '')
        ehtml = '<div class="err">%s</div>' % esc(emsg) if emsg else ''
        if which == 'masuk':
            form = ('<h1>Log in to Peka</h1><p class="sub">Welcome back.</p>'
                    '%s<form method="post" action="/masuk">'
                    '<div class="field"><label>Username</label>'
                    '<input name="username" maxlength="20" required></div>'
                    '<div class="field"><label>Password</label>'
                    '<input type="password" name="password" required></div>'
                    '<button class="btn" type="submit" style="width:100%%">Log in</button>'
                    '</form><p class="sub" style="margin-top:16px">Don\'t have an account? '
                    '<a href="/daftar" style="font-weight:700;text-decoration:underline">Sign up</a></p>')
        else:
            form = ('<h1>Sign up for Peka</h1><p class="sub">Free, no email required.</p>'
                    '%s<form method="post" action="/daftar">'
                    '<div class="field"><label>Username (3-20, lowercase/numbers/_)</label>'
                    '<input name="username" maxlength="20" required></div>'
                    '<div class="field"><label>Display name</label>'
                    '<input name="display_name" maxlength="40" required></div>'
                    '<div class="field"><label>Password (min 8 chars)</label>'
                    '<input type="password" name="password" required></div>'
                    '<div class="field"><label>Confirm password</label>'
                    '<input type="password" name="password2" required></div>'
                    '<button class="btn" type="submit" style="width:100%%">Sign up</button>'
                    '</form><p class="sub" style="margin-top:16px">Already have an account? '
                    '<a href="/masuk" style="font-weight:700;text-decoration:underline">Log in</a></p>')
        self.send_html(200, page('Log in' if which == 'masuk' else 'Sign up',
                                 None, '<div class="formbox">' + (form % ehtml) + '</div>'))

    def handle_profile(self, username):
        username = username.split('/')[0].split('?')[0]
        if not RE_USER.fullmatch(username or ''):
            return self.err_page(404, 'User not found.')
        c = self.c
        u = c.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        if not u:
            return self.err_page(404, 'User not found.')
        tab = self.query.get('tab', ['utas'])[0]
        if tab not in ('utas', 'balasan', 'suka'):
            tab = 'utas'
        me = self.user['id'] if self.user else None
        is_me = bool(me and me == u['id'])
        n_utas = c.execute('SELECT COUNT(*) FROM posts WHERE user_id=? AND parent_id IS NULL',
                           (u['id'],)).fetchone()[0]
        n_followers = c.execute('SELECT COUNT(*) FROM follows WHERE followee_id=?',
                                (u['id'],)).fetchone()[0]
        n_following = c.execute('SELECT COUNT(*) FROM follows WHERE follower_id=?',
                                (u['id'],)).fetchone()[0]
        is_following = False
        if me and not is_me:
            is_following = bool(c.execute(
                'SELECT 1 FROM follows WHERE follower_id=? AND followee_id=?',
                (me, u['id'])).fetchone())
        csrf = self.sess['csrf'] if self.sess else ''
        nxt = '/@' + username + '?tab=' + tab
        # header
        if is_me:
            action = ('<form method="post" action="/bio">'
                      '<input type="hidden" name="csrf" value="%s">'
                      '<div class="bioform"><textarea name="bio" maxlength="160" '
                      'placeholder="Write a short bio...">%s</textarea>'
                      '<button class="btn" type="submit">Save bio</button></div></form>'
                      '<form method="post" action="/keluar" style="margin-top:8px">'
                      '<input type="hidden" name="csrf" value="%s">'
                      '<button class="btn" type="submit">Log out</button></form><div style="margin-top:8px"><a href="/pengaturan">Settings</a> - <a href="/bookmark">Bookmarks</a></div>') % (
                          esc(csrf), esc(u['bio']), esc(csrf))
        elif self.user:
            lbl = 'Unfollow' if is_following else 'Follow'
            action = ('<form method="post" action="/ikuti">'
                      '<input type="hidden" name="csrf" value="%s">'
                      '<input type="hidden" name="username" value="%s">'
                      '<input type="hidden" name="next" value="%s">'
                      '<button class="btn" type="submit">%s</button></form>'
                      '<div style="margin-top:8px"><a href="/dm/%s">Message</a></div>') % (
                          esc(csrf), esc(username), esc(nxt), lbl, esc(username))
        else:
            action = ''
        body = ('<div class="profile"><div class="prow"><div>'
                '<div style="display:flex;gap:12px;align-items:center">%s'
                '<div><div class="pname">%s</div>'
                '<div class="puser">@%s</div></div></div>'
                '<div class="pbio">%s</div>'
                '<div class="pmeta"><span><b>%d</b> followers</span>'
                '<span><b>%d</b> following</span>'
                '<span>Joined %s</span></div>'
                '</div><div>%s</div></div></div>') % (
                    avatar_html(username), esc(u['display_name']), esc(username),
                    esc(u['bio']), n_followers, n_following,
                    esc(full_date(u['created_at'])), action)
        body += ('<div class="tabs">'
                 '<a href="/@%s?tab=utas" class="%s">Threads</a>'
                 '<a href="/@%s?tab=balasan" class="%s">Replies</a>'
                 '<a href="/@%s?tab=suka" class="%s">Likes</a></div>') % (
                    esc(username), 'on' if tab == 'utas' else '',
                    esc(username), 'on' if tab == 'balasan' else '',
                    esc(username), 'on' if tab == 'suka' else '')
        liked, reposted, bookmarked = set(), set(), set()
        if me:
            liked = {r[0] for r in c.execute(
                'SELECT post_id FROM likes WHERE user_id=?', (me,))}
            reposted = {r[0] for r in c.execute(
                'SELECT post_id FROM reposts WHERE user_id=?', (me,))}
            bookmarked = {r[0] for r in c.execute(
                'SELECT post_id FROM bookmarks WHERE user_id=?', (me,))}
        if tab == 'utas':
            rows = c.execute(POST_SQL + ' WHERE p.user_id=? AND p.parent_id IS NULL'
                             ' ORDER BY p.pinned DESC, p.created_at DESC, p.id DESC LIMIT 60', (u['id'],)).fetchall()
        elif tab == 'balasan':
            rows = c.execute(
                '''SELECT p.id AS post_id, p.user_id AS author_id, u.username,
                          u.display_name, p.body, p.created_at AS sort_time,
                          p.parent_id, NULL AS reposter_name, NULL AS reposter_id,
                          'post' AS kind, pu.username AS parent_user,
                          (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) AS n_like,
                          (SELECT COUNT(*) FROM reposts r WHERE r.post_id=p.id) AS n_repost,
                          (SELECT COUNT(*) FROM posts ch WHERE ch.parent_id=p.id) AS n_reply
                   FROM posts p JOIN users u ON u.id=p.user_id
                   JOIN posts par ON par.id=p.parent_id
                   JOIN users pu ON pu.id=par.user_id
                   WHERE p.user_id=? AND p.parent_id IS NOT NULL
                   ORDER BY p.created_at DESC, p.id DESC LIMIT 60''', (u['id'],)).fetchall()
        else:
            rows = c.execute(
                POST_SQL.replace('p.created_at AS sort_time',
                                 'l.created_at AS sort_time')
                .replace('FROM posts p JOIN users u ON u.id=p.user_id',
                         'FROM likes l JOIN posts p ON p.id=l.post_id '
                         'JOIN users u ON u.id=p.user_id')
                + ' WHERE l.user_id=? ORDER BY l.created_at DESC, l.post_id DESC LIMIT 60',
                (u['id'],)).fetchall()
        if not rows:
            body += '<div class="empty">Nothing here yet.</div>'
        for row in rows:
            d = dict(row)
            d['liked_by_me'] = d['post_id'] in liked
            d['reposted_by_me'] = d['post_id'] in reposted
            d['bookmarked_by_me'] = d['post_id'] in bookmarked
            extra = ''
            if tab == 'balasan' and d.get('parent_user'):
                extra = ('<div class="repostline" style="padding:10px 16px 0">'
                         'Replying to <a href="/@%s" style="font-weight:700">@%s</a></div>'
                         ) % (esc(d['parent_user']), esc(d['parent_user']))
            body += extra + post_row(d, self.user, csrf, nxt)
        self.send_html(200, page('@' + username, self.user, body,
                                 'profil' if is_me else 'beranda'))

    def handle_detail(self, pid):
        try:
            pid = int(pid)
        except ValueError:
            return self.err_page(404, 'Thread not found.')
        c = self.c
        row = c.execute(POST_SQL + ' WHERE p.id=?', (pid,)).fetchone()
        if not row:
            return self.err_page(404, 'Thread not found.')
        me = self.user['id'] if self.user else None
        liked, reposted = set(), set()
        if me:
            liked = {r[0] for r in c.execute(
                'SELECT post_id FROM likes WHERE user_id=?', (me,))}
            reposted = {r[0] for r in c.execute(
                'SELECT post_id FROM reposts WHERE user_id=?', (me,))}
        d = dict(row)
        d['liked_by_me'] = d['post_id'] in liked
        d['reposted_by_me'] = d['post_id'] in reposted
        d['bookmarked_by_me'] = False
        if me:
            d['bookmarked_by_me'] = bool(c.execute(
                'SELECT 1 FROM bookmarks WHERE user_id=? AND post_id=?',
                (me, d['post_id'])).fetchone())
        csrf = self.sess['csrf'] if self.sess else ''
        nxt = '/utas/%d' % pid
        body = ('<div class="detail-head"><a href="/">Home</a> / Thread</div>'
                + post_row(d, self.user, csrf, nxt))
        if self.user:
            body += ('<div class="replybox">' +
                     compose_box(csrf, self.user, parent_id=pid,
                                 placeholder='Write a reply...') + '</div>')
        body += '<div class="detail-head">Replies</div>'
        reps = c.execute(POST_SQL + ' WHERE p.parent_id=?'
                         ' ORDER BY p.created_at ASC, p.id ASC LIMIT 200', (pid,)).fetchall()
        if not reps:
            body += '<div class="empty">No replies yet.</div>'
        for r in reps:
            rd = dict(r)
            rd['liked_by_me'] = rd['post_id'] in liked
            rd['reposted_by_me'] = rd['post_id'] in reposted
            rd['bookmarked_by_me'] = d['bookmarked_by_me']
            body += post_row(rd, self.user, csrf, nxt)
        self.send_html(200, page('Thread', self.user, body))

    # ----- new feature handlers -----
    def _post_dicts(self, rows):
        c = self.c
        me = self.user['id'] if self.user else None
        liked, reposted, bookmarked = set(), set(), set()
        if me:
            liked = {r[0] for r in c.execute('SELECT post_id FROM likes WHERE user_id=?', (me,))}
            reposted = {r[0] for r in c.execute('SELECT post_id FROM reposts WHERE user_id=?', (me,))}
            bookmarked = {r[0] for r in c.execute('SELECT post_id FROM bookmarks WHERE user_id=?', (me,))}
        items = []
        for row in rows:
            d = dict(row)
            d['liked_by_me'] = d['post_id'] in liked
            d['reposted_by_me'] = d['post_id'] in reposted
            d['bookmarked_by_me'] = d['post_id'] in bookmarked
            items.append(d)
        return items

    def handle_notifikasi(self):
        if not self.user:
            return self.redirect('/masuk')
        c = self.c
        me = self.user['id']
        rows = c.execute(
            'SELECT n.id, n.kind, n.post_id, n.created_at, n.read_at,'
            ' u.username AS actor_name, u.display_name AS actor_display'
            ' FROM notifications n JOIN users u ON u.id=n.actor_id'
            ' WHERE n.user_id=? ORDER BY n.created_at DESC LIMIT 50',
            (me,)).fetchall()
        c.execute('UPDATE notifications SET read_at=? WHERE user_id=? AND read_at IS NULL',
                  (now(), me))
        c.commit()
        self.user['unread'] = 0
        body = '<h2 class="ptitle">Notifications</h2>'
        if not rows:
            body += '<div class="empty">Nothing here yet.</div>'
        for r in rows:
            actor = '<a class="nm2" href="/@%s">%s</a>' % (esc(r['actor_name']), esc(r['actor_display']))
            if r['kind'] == 'like':
                txt = '%s liked your thread' % actor
                link = '/utas/%d' % r['post_id']
            elif r['kind'] == 'repost':
                txt = '%s reposted your thread' % actor
                link = '/utas/%d' % r['post_id']
            elif r['kind'] == 'reply':
                txt = '%s replied to your thread' % actor
                link = '/utas/%d' % r['post_id']
            elif r['kind'] == 'mention':
                txt = '%s mentioned you' % actor
                link = '/utas/%d' % r['post_id']
            elif r['kind'] == 'dm':
                txt = '%s sent you a message' % actor
                link = '/dm/' + r['actor_name']
            else:
                txt = '%s followed you' % actor
                link = '/@' + r['actor_name']
            body += ('<a href="%s"><div class="notif%s"><div>%s</div>'
                     '<div class="nt">%s<br><span class="tm">%s</span></div></div></a>') % (
                         esc(link), '' if r['read_at'] else ' unread',
                         avatar_html(r['actor_name'], 36), txt, esc(rel_time(r['created_at'])))
        self.send_html(200, page('Notifications', self.user, body, 'notifikasi'))

    def handle_tag(self, tag):
        tag = tag.lower()
        if not re.fullmatch(r'[a-z0-9_]{2,40}', tag):
            return self.err_page(404, 'Page not found.')
        c = self.c
        rows = c.execute(POST_SQL + ' WHERE p.parent_id IS NULL'
                         ' ORDER BY p.created_at DESC LIMIT 500').fetchall()
        items = [d for d in self._post_dicts(rows)
                 if tag in extract_tags(d['body'])]
        csrf = self.sess['csrf'] if self.sess else ''
        nxt = '/tag/' + tag
        body = '<h2 class="ptitle">#%s</h2>' % esc(tag)
        if not items:
            body += '<div class="empty">No threads with this hashtag yet.</div>'
        for d in items[:40]:
            body += post_row(d, self.user, csrf, nxt)
        self.send_html(200, page('#' + tag, self.user, body))

    def handle_bookmarks(self):
        if not self.user:
            return self.redirect('/masuk')
        c = self.c
        rows = c.execute(POST_SQL + ' WHERE p.id IN'
                         ' (SELECT post_id FROM bookmarks WHERE user_id=?)'
                         ' ORDER BY p.created_at DESC, p.id DESC LIMIT 60',
                         (self.user['id'],)).fetchall()
        items = self._post_dicts(rows)
        csrf = self.sess['csrf']
        nxt = '/bookmark'
        body = '<h2 class="ptitle">Bookmarks</h2>'
        if not items:
            body += '<div class="empty">No bookmarks yet. Tap the bookmark icon on any thread.</div>'
        for d in items:
            body += post_row(d, self.user, csrf, nxt)
        self.send_html(200, page('Bookmarks', self.user, body))

    def handle_edit(self):
        if not self.user:
            return self.redirect('/masuk')
        try:
            pid = int(self.query.get('id', ['0'])[0])
        except ValueError:
            return self.err_page(404, 'Page not found.')
        r = self.c.execute('SELECT id, user_id, body FROM posts WHERE id=?', (pid,)).fetchone()
        if not r or r['user_id'] != self.user['id']:
            return self.err_page(404, 'Page not found.')
        csrf = self.sess['csrf']
        nxt = self.query.get('next', ['/'])[0]
        body = ('<h2 class="ptitle">Edit thread</h2>'
                '<div class="compose"><form method="post" action="/edit">'
                '<input type="hidden" name="csrf" value="%s">'
                '<input type="hidden" name="id" value="%d">'
                '<input type="hidden" name="next" value="%s">'
                '<textarea name="body" maxlength="500" rows="4">%s</textarea>'
                '<div class="crow"><span class="ccount"></span>'
                '<button class="btn" type="submit">Save</button></div>'
                '</form></div>') % (esc(csrf), pid, esc(nxt), esc(r['body']))
        self.send_html(200, page('Edit thread', self.user, body))

    def post_edit(self):
        form = self.parse_form()
        if form is None:
            return self.err_page(413, 'Data too large.')
        nxt = self.safe_next(form) if form else '/'
        if not self.user or not self.csrf_ok(form):
            return self.redirect('/masuk')
        try:
            pid = int(form.get('id', ['0'])[0])
        except ValueError:
            return self.redirect(nxt)
        body = form.get('body', [''])[0].strip()
        if not body or len(body) > 500:
            return self.redirect(nxt)
        r = self.c.execute('SELECT user_id FROM posts WHERE id=?', (pid,)).fetchone()
        if not r or r['user_id'] != self.user['id']:
            return self.redirect(nxt)
        self.c.execute('UPDATE posts SET body=?, edited_at=? WHERE id=?',
                       (body, now(), pid))
        process_mentions(self.c, body, self.user['id'], pid)
        self.c.commit()
        self.redirect(nxt)

    def post_bookmark(self):
        form = self.parse_form()
        if form is None:
            return self.err_page(413, 'Data too large.')
        nxt = self.safe_next(form) if form else '/'
        if not self.user or not self.csrf_ok(form):
            return self.redirect('/masuk')
        try:
            pid = int(form.get('id', ['0'])[0])
        except ValueError:
            return self.redirect(nxt)
        if not self.c.execute('SELECT 1 FROM posts WHERE id=?', (pid,)).fetchone():
            return self.redirect(nxt)
        me = self.user['id']
        if self.c.execute('SELECT 1 FROM bookmarks WHERE user_id=? AND post_id=?',
                          (me, pid)).fetchone():
            self.c.execute('DELETE FROM bookmarks WHERE user_id=? AND post_id=?', (me, pid))
        else:
            self.c.execute('INSERT INTO bookmarks (user_id, post_id, created_at)'
                           ' VALUES (?,?,?)', (me, pid, now()))
        self.c.commit()
        self.redirect(nxt)

    def post_pin(self):
        form = self.parse_form()
        if form is None:
            return self.err_page(413, 'Data too large.')
        nxt = self.safe_next(form) if form else '/'
        if not self.user or not self.csrf_ok(form):
            return self.redirect('/masuk')
        try:
            pid = int(form.get('id', ['0'])[0])
        except ValueError:
            return self.redirect(nxt)
        me = self.user['id']
        r = self.c.execute('SELECT user_id, pinned FROM posts WHERE id=?', (pid,)).fetchone()
        if not r or r['user_id'] != me:
            return self.redirect(nxt)
        if r['pinned']:
            self.c.execute('UPDATE posts SET pinned=0 WHERE id=?', (pid,))
        else:
            self.c.execute('UPDATE posts SET pinned=0 WHERE user_id=?', (me,))
            self.c.execute('UPDATE posts SET pinned=1 WHERE id=?', (pid,))
        self.c.commit()
        self.redirect(nxt)

    def handle_jelajahi(self):
        c = self.c
        week = now() - 7 * 86400
        rows = c.execute(POST_SQL +
                         ' WHERE p.parent_id IS NULL AND p.created_at>?'
                         ' ORDER BY ((SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id)'
                         ' + 2*(SELECT COUNT(*) FROM reposts r WHERE r.post_id=p.id)'
                         ' + (SELECT COUNT(*) FROM posts ch WHERE ch.parent_id=p.id)) DESC,'
                         ' p.created_at DESC LIMIT 20', (week,)).fetchall()
        items = self._post_dicts(rows)
        tag_counts = {}
        for r in c.execute('SELECT body FROM posts WHERE created_at>? ORDER BY created_at DESC LIMIT 500',
                           (week,)):
            for tg in extract_tags(r['body']):
                tag_counts[tg] = tag_counts.get(tg, 0) + 1
        top_tags = sorted(tag_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
        csrf = self.sess['csrf'] if self.sess else ''
        nxt = '/jelajahi'
        body = '<h2 class="ptitle">Trending tags</h2>'
        if top_tags:
            body += '<div class="tagbox">' + ''.join(
                '<a class="tagchip" href="/tag/%s">#%s <span class="tm">%d</span></a>' % (tg, tg, n)
                for tg, n in top_tags) + '</div>'
        else:
            body += '<div class="empty">No hashtags this week yet.</div>'
        body += '<h2 class="ptitle">Trending threads</h2>'
        if not items:
            body += '<div class="empty">Nothing trending yet.</div>'
        for d in items:
            body += post_row(d, self.user, csrf, nxt)
        self.send_html(200, page('Explore', self.user, body, 'jelajahi'))

    def handle_pengaturan(self):
        if not self.user:
            return self.redirect('/masuk')
        csrf = self.sess['csrf']
        u = self.c.execute('SELECT display_name, bio FROM users WHERE id=?',
                           (self.user['id'],)).fetchone()
        body = ('<h2 class="ptitle">Settings</h2>'
                '<div class="setrow"><form method="post" action="/pengaturan">'
                '<input type="hidden" name="csrf" value="%s">'
                '<label>Display name (3-40 chars)</label>'
                '<input name="display_name" maxlength="40" value="%s" style="margin-bottom:10px">'
                '<label>Bio (max 160 chars)</label>'
                '<input name="bio" maxlength="160" value="%s" style="margin-bottom:10px">'
                '<button class="btn" type="submit">Save profile</button></form></div>'
                '<div class="setrow"><form method="post" action="/pengaturan/password">'
                '<input type="hidden" name="csrf" value="%s">'
                '<label>Current password</label>'
                '<input type="password" name="current_pw" style="margin-bottom:10px">'
                '<label>New password (min 8 chars)</label>'
                '<input type="password" name="new_pw" style="margin-bottom:10px">'
                '<button class="btn" type="submit">Change password</button></form></div>'
                '<div class="setrow"><a href="/bookmark">My bookmarks</a></div>') % (
                    esc(csrf), esc(u['display_name']), esc(u['bio']), esc(csrf))
        self.send_html(200, page('Settings', self.user, body))

    def post_pengaturan(self):
        form = self.parse_form()
        if form is None:
            return self.err_page(413, 'Data too large.')
        if not self.user or not self.csrf_ok(form):
            return self.redirect('/masuk')
        name = form.get('display_name', [''])[0].strip()[:40]
        bio = form.get('bio', [''])[0].strip()[:160]
        if len(name) < 3:
            return self.err_page(400, 'Display name too short.')
        self.c.execute('UPDATE users SET display_name=?, bio=? WHERE id=?',
                       (name, bio, self.user['id']))
        self.c.commit()
        self.user['display_name'] = name
        self.redirect('/pengaturan')

    def post_password(self):
        form = self.parse_form()
        if form is None:
            return self.err_page(413, 'Data too large.')
        if not self.user or not self.csrf_ok(form):
            return self.redirect('/masuk')
        cur_pw = form.get('current_pw', [''])[0]
        new_pw = form.get('new_pw', [''])[0]
        u = self.c.execute('SELECT salt, pw_hash FROM users WHERE id=?',
                           (self.user['id'],)).fetchone()
        if hash_pw(cur_pw, u['salt']) != u['pw_hash']:
            return self.err_page(400, 'Current password is wrong.')
        if len(new_pw) < 8:
            return self.err_page(400, 'New password must be at least 8 characters.')
        salt = secrets.token_hex(16)
        self.c.execute('UPDATE users SET salt=?, pw_hash=? WHERE id=?',
                       (salt, hash_pw(new_pw, salt), self.user['id']))
        self.c.commit()
        self.redirect('/pengaturan')

    # ----- DM handlers -----
    def handle_dm_inbox(self):
        if not self.user:
            return self.redirect('/masuk')
        c = self.c
        me = self.user['id']
        rows = c.execute(
            'SELECT CASE WHEN sender_id=? THEN recipient_id ELSE sender_id END AS other_id,'
            ' MAX(created_at) AS last_at,'
            ' SUM(CASE WHEN recipient_id=? AND read_at IS NULL THEN 1 ELSE 0 END) AS unread_n'
            ' FROM dms WHERE sender_id=? OR recipient_id=?'
            ' GROUP BY other_id ORDER BY last_at DESC LIMIT 50',
            (me, me, me, me)).fetchall()
        body = '<h2 class="ptitle">Messages</h2>'
        if not rows:
            body += '<div class="empty">No conversations yet.<br>Visit someone\'s profile and tap Message.</div>'
        for r in rows:
            u = c.execute('SELECT username, display_name FROM users WHERE id=?',
                          (r['other_id'],)).fetchone()
            if not u:
                continue
            last = c.execute(
                'SELECT body, sender_id, created_at FROM dms'
                ' WHERE (sender_id=? AND recipient_id=?) OR (sender_id=? AND recipient_id=?)'
                ' ORDER BY created_at DESC, id DESC LIMIT 1',
                (me, r['other_id'], r['other_id'], me)).fetchone()
            preview = (('You: ' if last['sender_id'] == me else '') + last['body'])[:80]
            badge = '<span class="badge">%d</span>' % r['unread_n'] if r['unread_n'] else ''
            body += ('<a href="/dm/%s"><div class="notif%s"><div>%s</div>'
                     '<div class="nt"><span class="nm2">%s</span> %s<br>'
                     '<span style="color:var(--faint)">%s</span> '
                     '<span class="tm">%s</span></div></div></a>') % (
                         esc(u['username']), '' if not r['unread_n'] else ' unread',
                         avatar_html(u['username'], 40), esc(u['display_name']), badge,
                         esc(preview), esc(rel_time(last['created_at'])))
        self.send_html(200, page('Messages', self.user, body, 'dm'))

    def handle_dm_thread(self, username):
        if not self.user:
            return self.redirect('/masuk')
        username = username.split('/')[0].split('?')[0]
        if not RE_USER.fullmatch(username or ''):
            return self.err_page(404, 'User not found.')
        c = self.c
        u = c.execute('SELECT id, username, display_name FROM users WHERE username=?',
                      (username,)).fetchone()
        if not u or u['id'] == self.user['id']:
            return self.err_page(404, 'User not found.')
        me = self.user['id']
        msgs = c.execute(
            'SELECT id, sender_id, body, created_at FROM dms'
            ' WHERE (sender_id=? AND recipient_id=?) OR (sender_id=? AND recipient_id=?)'
            ' ORDER BY created_at ASC, id ASC LIMIT 200',
            (me, u['id'], u['id'], me)).fetchall()
        c.execute('UPDATE dms SET read_at=? WHERE recipient_id=? AND sender_id=? AND read_at IS NULL',
                  (now(), me, u['id']))
        c.commit()
        self.user['dm_unread'] = dm_unread_count(c, me)
        csrf = self.sess['csrf']
        body = ('<div class="detail-head"><a href="/dm">Messages</a> / %s</div>'
                '<div class="dmthread">') % esc(u['display_name'])
        if not msgs:
            body += '<div class="empty">No messages yet. Say hello.</div>'
        for m in msgs:
            mine = m['sender_id'] == me
            body += ('<div class="dmrow %s"><div class="dmbubble">%s'
                     '<div class="dmtime">%s</div></div></div>') % (
                         'mine' if mine else 'theirs', esc(m['body']),
                         esc(rel_time(m['created_at'])))
        body += '</div>'
        body += ('<div class="dmcompose"><form method="post" action="/dm/kirim">'
                 '<input type="hidden" name="csrf" value="%s">'
                 '<input type="hidden" name="username" value="%s">'
                 '<input name="body" maxlength="1000" placeholder="Write a message..." '
                 'required autocomplete="off">'
                 '<button class="btn" type="submit">Send</button></form></div>') % (
                     esc(csrf), esc(username))
        self.send_html(200, page('Message ' + u['display_name'], self.user, body, 'dm'))

    def post_dm(self):
        form = self.parse_form()
        if form is None:
            return self.err_page(413, 'Data too large.')
        if not self.user or not self.csrf_ok(form):
            return self.redirect('/masuk')
        if not rl_ok(self.ip(), 'dm', 60):
            return self.err_page(429, 'Too many messages. Try again later.')
        username = form.get('username', [''])[0].strip()
        body = form.get('body', [''])[0].strip()
        if not body or len(body) > 1000:
            return self.redirect('/dm/' + username if username else '/dm')
        u = self.c.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone()
        me = self.user['id']
        if not u or u['id'] == me:
            return self.redirect('/dm')
        self.c.execute('INSERT INTO dms (sender_id, recipient_id, body, created_at)'
                       ' VALUES (?,?,?,?)', (me, u['id'], body, now()))
        notify(self.c, u['id'], me, 'dm')
        self.c.commit()
        self.redirect('/dm/' + username)

    # ----- POST routes -----
    def route_post(self):
        p = self.ppath
        if p == '/daftar':
            return self.post_daftar()
        if p == '/masuk':
            return self.post_masuk()
        if p == '/keluar':
            return self.post_keluar()
        if p == '/tulis':
            return self.post_tulis()
        if p == '/hapus':
            return self.post_hapus()
        if p == '/suka':
            return self.post_toggle('likes')
        if p == '/repost':
            return self.post_toggle('reposts')
        if p == '/ikuti':
            return self.post_ikuti()
        if p == '/bio':
            return self.post_bio()
        if p == '/bookmark':
            return self.post_bookmark()
        if p == '/pin':
            return self.post_pin()
        if p == '/edit':
            return self.post_edit()
        if p == '/pengaturan':
            return self.post_pengaturan()
        if p == '/pengaturan/password':
            return self.post_password()
        if p == '/dm/kirim':
            return self.post_dm()
        self.err_page(404, 'Page not found.')

    def post_daftar(self):
        form = self.parse_form()
        if form is None:
            return self.err_page(413, 'Data too large.')
        if not rl_ok(self.ip(), 'register', 5):
            return self.redirect('/daftar?err=rl')
        g = lambda k: form.get(k, [''])[0].strip()
        username, display, pw, pw2 = g('username'), g('display_name'), \
            form.get('password', [''])[0], form.get('password2', [''])[0]
        if not RE_USER.fullmatch(username):
            return self.redirect('/daftar?err=u_bad')
        if not display or len(display) > 40:
            return self.redirect('/daftar?err=d_bad')
        if len(pw) < 8:
            return self.redirect('/daftar?err=p_short')
        if pw != pw2:
            return self.redirect('/daftar?err=p_mismatch')
        c = self.c
        if c.execute('SELECT 1 FROM users WHERE username=?', (username,)).fetchone():
            return self.redirect('/daftar?err=u_taken')
        salt = secrets.token_hex(16)
        cur = c.execute('INSERT INTO users (username, display_name, bio, salt, pw_hash, created_at)'
                        ' VALUES (?,?,?,?,?,?)',
                        (username, display, '', salt, hash_pw(pw, salt), now()))
        uid = cur.lastrowid
        token, _ = new_session(c, uid)
        cookie = ('peka_session=%s; HttpOnly; SameSite=Lax; Path=/; Max-Age=%d'
                  % (token, SESSION_DAYS * 86400))
        self.redirect('/', cookie)

    def post_masuk(self):
        form = self.parse_form()
        if form is None:
            return self.err_page(413, 'Data too large.')
        if not rl_ok(self.ip(), 'login', 20):
            return self.redirect('/masuk?err=rl')
        g = lambda k: form.get(k, [''])[0].strip()
        username, pw = g('username'), form.get('password', [''])[0]
        u = self.c.execute('SELECT * FROM users WHERE username=?',
                           (username,)).fetchone()
        if not u or not secrets.compare_digest(hash_pw(pw, u['salt']), u['pw_hash']):
            return self.redirect('/masuk?err=bad_login')
        token, _ = new_session(self.c, u['id'])
        cookie = ('peka_session=%s; HttpOnly; SameSite=Lax; Path=/; Max-Age=%d'
                  % (token, SESSION_DAYS * 86400))
        self.redirect('/', cookie)

    def post_keluar(self):
        form = self.parse_form()
        if form is None:
            return self.err_page(413, 'Data too large.')
        if self.user and self.sess and self.csrf_ok(form):
            self.c.execute('DELETE FROM sessions WHERE token=?',
                           (self.sess['token'],))
            self.c.commit()
        self.redirect('/', 'peka_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0')

    def post_tulis(self):
        form = self.parse_form()
        if form is None:
            return self.err_page(413, 'Data too large.')
        if not self.user or not self.csrf_ok(form):
            return self.redirect('/masuk')
        if not rl_ok(self.ip(), 'post', 30):
            return self.err_page(429, 'Too many posts. Try again later.')
        body = form.get('body', [''])[0].strip()
        if not body or len(body) > 500:
            return self.redirect('/')
        parent = None
        if form.get('parent_id', [''])[0].strip():
            try:
                parent = int(form['parent_id'][0])
            except ValueError:
                return self.redirect('/')
            if not self.c.execute('SELECT 1 FROM posts WHERE id=?',
                                  (parent,)).fetchone():
                return self.redirect('/')
        cur = self.c.execute('INSERT INTO posts (user_id, body, parent_id, created_at)'
                               ' VALUES (?,?,?,?)',
                               (self.user['id'], body, parent, now()))
        pid = cur.lastrowid
        if parent:
            pa = self.c.execute('SELECT user_id FROM posts WHERE id=?', (parent,)).fetchone()
            if pa:
                notify(self.c, pa['user_id'], self.user['id'], 'reply', parent)
        process_mentions(self.c, body, self.user['id'], pid)
        self.c.commit()
        self.redirect('/utas/%d' % parent if parent else '/')

    def post_hapus(self):
        form = self.parse_form()
        if form is None:
            return self.err_page(413, 'Data too large.')
        nxt = self.safe_next(form) if form else '/'
        if not self.user or not self.csrf_ok(form):
            return self.redirect('/masuk')
        try:
            pid = int(form.get('id', ['0'])[0])
        except ValueError:
            return self.redirect(nxt)
        p = self.c.execute('SELECT user_id FROM posts WHERE id=?', (pid,)).fetchone()
        if not p or (p['user_id'] != self.user['id'] and not self.user.get('is_admin')):
            return self.redirect(nxt)
        c = self.c
        c.execute('''WITH RECURSIVE del(id) AS (
                       SELECT ? UNION SELECT p.id FROM posts p JOIN del d ON p.parent_id=d.id
                     ) DELETE FROM likes WHERE post_id IN (SELECT id FROM del)''', (pid,))
        c.execute('''WITH RECURSIVE del(id) AS (
                       SELECT ? UNION SELECT p.id FROM posts p JOIN del d ON p.parent_id=d.id
                     ) DELETE FROM reposts WHERE post_id IN (SELECT id FROM del)''', (pid,))
        c.execute('''WITH RECURSIVE del(id) AS (
                       SELECT ? UNION SELECT p.id FROM posts p JOIN del d ON p.parent_id=d.id
                     ) DELETE FROM posts WHERE id IN (SELECT id FROM del)''', (pid,))
        c.commit()
        self.redirect('/')

    def post_toggle(self, table):
        form = self.parse_form()
        if form is None:
            return self.err_page(413, 'Data too large.')
        nxt = self.safe_next(form) if form else '/'
        if not self.user or not self.csrf_ok(form):
            return self.redirect('/masuk')
        try:
            pid = int(form.get('id', ['0'])[0])
        except ValueError:
            return self.redirect(nxt)
        if not self.c.execute('SELECT 1 FROM posts WHERE id=?', (pid,)).fetchone():
            return self.redirect(nxt)
        me = self.user['id']
        c = self.c
        if c.execute('SELECT 1 FROM %s WHERE user_id=? AND post_id=?' % table,
                     (me, pid)).fetchone():
            c.execute('DELETE FROM %s WHERE user_id=? AND post_id=?' % table,
                      (me, pid))
        else:
            c.execute('INSERT INTO %s (user_id, post_id, created_at) VALUES (?,?,?)'
                      % table, (me, pid, now()))
            pa = c.execute('SELECT user_id FROM posts WHERE id=?', (pid,)).fetchone()
            if pa:
                notify(c, pa['user_id'], me,
                       'like' if table == 'likes' else 'repost', pid)
        c.commit()
        self.redirect(nxt)

    def post_ikuti(self):
        form = self.parse_form()
        if form is None:
            return self.err_page(413, 'Data too large.')
        nxt = self.safe_next(form) if form else '/'
        if not self.user or not self.csrf_ok(form):
            return self.redirect('/masuk')
        username = form.get('username', [''])[0].strip()
        u = self.c.execute('SELECT id FROM users WHERE username=?',
                           (username,)).fetchone()
        me = self.user['id']
        if not u or u['id'] == me:
            return self.redirect(nxt)
        c = self.c
        if c.execute('SELECT 1 FROM follows WHERE follower_id=? AND followee_id=?',
                     (me, u['id'])).fetchone():
            c.execute('DELETE FROM follows WHERE follower_id=? AND followee_id=?',
                      (me, u['id']))
        else:
            c.execute('INSERT INTO follows (follower_id, followee_id, created_at)'
                      ' VALUES (?,?,?)', (me, u['id'], now()))
            notify(c, u['id'], me, 'follow')
        c.commit()
        self.redirect(nxt)

    def post_bio(self):
        form = self.parse_form()
        if form is None:
            return self.err_page(413, 'Data too large.')
        if not self.user or not self.csrf_ok(form):
            return self.redirect('/masuk')
        bio = form.get('bio', [''])[0].strip()[:160]
        self.c.execute('UPDATE users SET bio=? WHERE id=?', (bio, self.user['id']))
        self.c.commit()
        self.redirect('/@' + self.user['username'])


def main():
    try:
        init_db()
    except Exception as e:
        print('DB init failed: %s' % e)
        raise SystemExit(1)
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    srv.daemon_threads = True
    print('Peka listening on http://%s:%d' % (HOST, PORT), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
