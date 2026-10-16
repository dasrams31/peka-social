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
    ''')
    c.commit()
    c.close()


# ---------------- helpers ----------------
def now():
    return int(time.time())


def esc(s):
    return html.escape(s if s is not None else '', quote=True)


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
                    ' u.display_name FROM sessions s JOIN users u ON u.id=s.user_id'
                    ' WHERE s.token=? AND s.expires_at>?',
                    (token, now())).fetchone()
    if not row:
        return None, None
    user = {'id': row['id'], 'username': row['username'],
            'display_name': row['display_name']}
    sess = {'token': row['token'], 'csrf': row['csrf']}
    return user, sess


# ---------------- html ----------------
CSS = """
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#101010;--panel:#161616;--border:#2b2b2b;--text:#ececec;
--muted:#9a9a9a;--btn:#242424;--red:#ff3b5c;--green:#35c46f}
body{background:var(--bg);color:var(--text);
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
line-height:1.45;font-size:15px}
a{color:inherit;text-decoration:none}
.wrap{max-width:620px;margin:0 auto;min-height:100vh;
border-left:1px solid var(--border);border-right:1px solid var(--border);
background:var(--bg)}
@media(max-width:640px){.wrap{border-left:none;border-right:none}}
.topbar{position:sticky;top:0;z-index:20;background:#101010;
border-bottom:1px solid var(--border)}
.topbar-in{max-width:620px;margin:0 auto;display:flex;align-items:center;
justify-content:space-between;padding:12px 16px}
.wordmark{font-size:22px;font-weight:800;letter-spacing:-.5px}
.wordmark .dot{color:var(--muted)}
.nav{display:flex;gap:4px}
.nav a{padding:8px 12px;border-radius:8px;color:var(--muted);font-weight:600;font-size:14px}
.nav a:hover{background:var(--btn);color:var(--text)}
.nav a.on{color:var(--text)}
.tabs{display:flex;border-bottom:1px solid var(--border)}
.tabs a{flex:1;text-align:center;padding:12px;font-weight:700;color:var(--muted);
border-bottom:2px solid transparent;font-size:14px}
.tabs a.on{color:var(--text);border-bottom-color:var(--text)}
.compose{display:flex;gap:12px;padding:14px 16px;border-bottom:1px solid var(--border)}
.compose form{flex:1}
textarea{width:100%;background:transparent;border:none;color:var(--text);
font-size:15px;font-family:inherit;resize:vertical;min-height:44px;outline:none}
textarea::placeholder{color:var(--muted)}
.crow{display:flex;justify-content:flex-end;align-items:center;gap:10px;margin-top:8px}
.ccount{color:var(--muted);font-size:13px}
button.btn{background:var(--text);color:#101010;border:none;border-radius:999px;
padding:8px 18px;font-weight:700;font-size:14px;cursor:pointer;font-family:inherit}
button.btn:hover{opacity:.9}
button.btn:disabled{opacity:.4;cursor:default}
.post{display:flex;gap:12px;padding:14px 16px;border-bottom:1px solid var(--border)}
.avatar{flex:none;width:40px;height:40px;border-radius:50%;display:flex;
align-items:center;justify-content:center;font-weight:700;font-size:17px;color:#fff}
.pbody{flex:1;min-width:0}
.phead{display:flex;align-items:baseline;gap:6px;flex-wrap:wrap}
.phead .nm{font-weight:700;font-size:14px}
.phead .un{color:var(--muted);font-size:13px}
.phead .tm{color:var(--muted);font-size:13px;margin-left:auto;flex:none}
.repostline{color:var(--muted);font-size:13px;margin-bottom:6px}
.ptext{white-space:pre-wrap;word-wrap:break-word;margin:2px 0 8px}
.actions{display:flex;gap:4px;align-items:center}
.act{background:none;border:none;color:var(--muted);cursor:pointer;display:flex;
align-items:center;gap:5px;font-size:13px;padding:6px 8px;border-radius:8px;font-family:inherit}
.act:hover{background:var(--btn);color:var(--text)}
.act svg{width:18px;height:18px}
.act.liked{color:var(--red)}
.act.reposted{color:var(--green)}
.act.danger:hover{color:var(--red)}
.empty{padding:48px 20px;text-align:center;color:var(--muted)}
.pager{display:flex;justify-content:center;gap:12px;padding:16px}
.pager a{padding:8px 16px;border:1px solid var(--border);border-radius:999px;
font-size:14px;font-weight:600}
.pager a:hover{background:var(--btn)}
.profile{padding:20px 16px 12px;border-bottom:1px solid var(--border)}
.prow{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}
.pname{font-size:20px;font-weight:800}
.puser{color:var(--muted);font-size:14px;margin:2px 0 8px}
.pbio{white-space:pre-wrap;word-wrap:break-word;margin:8px 0;font-size:14px}
.pmeta{color:var(--muted);font-size:13px;display:flex;gap:14px;flex-wrap:wrap;margin-top:8px}
.pmeta b{color:var(--text)}
.bioform textarea{background:var(--panel);border:1px solid var(--border);
border-radius:10px;padding:10px;margin:8px 0;min-height:60px}
.formbox{max-width:420px;margin:40px auto;padding:0 20px}
.formbox h1{font-size:24px;margin-bottom:6px}
.formbox p.sub{color:var(--muted);margin-bottom:20px;font-size:14px}
.field{margin-bottom:14px}
.field label{display:block;font-size:13px;font-weight:600;margin-bottom:6px;color:var(--muted)}
.field input{width:100%;background:var(--panel);border:1px solid var(--border);
border-radius:10px;padding:12px;color:var(--text);font-size:15px;font-family:inherit}
.field input:focus{outline:none;border-color:var(--muted)}
.err{background:#3a1418;border:1px solid #7a2430;color:#ffb3bd;padding:10px 14px;
border-radius:10px;margin-bottom:16px;font-size:14px}
.searchbar{padding:14px 16px;border-bottom:1px solid var(--border);display:flex;gap:8px}
.searchbar input{flex:1;background:var(--panel);border:1px solid var(--border);
border-radius:999px;padding:10px 16px;color:var(--text);font-size:15px;font-family:inherit}
.urow{display:flex;gap:12px;align-items:center;padding:12px 16px;
border-bottom:1px solid var(--border)}
.urow .who{flex:1;min-width:0}
.detail-head{padding:14px 16px;border-bottom:1px solid var(--border);
color:var(--muted);font-size:13px}
.detail-head a{font-weight:700;color:var(--text)}
.replybox{border-bottom:1px solid var(--border)}
.footer{padding:24px;text-align:center;color:var(--muted);font-size:12px}
"""

ICON_REPLY = ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"'
              ' stroke-width="2"><path d="M21 12a8 8 0 0 1-8 8H5l-2 2V12a8 8 0 0 1 8-8h2a8 8 0 0 1 8 8z"/></svg>')
ICON_REPOST = ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"'
               ' stroke-width="2"><path d="M17 2l4 4-4 4"/><path d="M3 11v-1a4 4 0 0 1 4-4h14"/>'
               '<path d="M7 22l-4-4 4-4"/><path d="M21 13v1a4 4 0 0 1-4 4H3"/></svg>')
ICON_LIKE = ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"'
             ' stroke-width="2"><path d="M12 21C7 16.5 3 13 3 8.8 3 6 5.2 4 7.8 4c1.7 0 3.2.9 4.2 2.3C13 4.9 14.5 4 16.2 4 18.8 4 21 6 21 8.8c0 4.2-4 7.7-9 12.2z"/></svg>')
ICON_LIKE_FILL = ('<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 21C7 16.5 3 13 3 8.8 3 6 5.2 4 7.8 4c1.7 0 3.2.9 4.2 2.3C13 4.9 14.5 4 16.2 4 18.8 4 21 6 21 8.8c0 4.2-4 7.7-9 12.2z"/></svg>')


def avatar_html(username, size=40):
    return ('<div class="avatar" style="background:%s">%s</div>'
            % (avatar_color(username), esc(username[0].upper())))


def page(title, user, body_html, nav='beranda'):
    if user:
        nav_html = ('<a href="/" class="%s">Home</a>'
                    '<a href="/cari" class="%s">Search</a>'
                    '<a href="/@%s" class="%s">Profile</a>') % (
                        'on' if nav == 'beranda' else '',
                        'on' if nav == 'cari' else '',
                        esc(user['username']),
                        'on' if nav == 'profil' else '')
    else:
        nav_html = ('<a href="/" class="%s">Home</a>'
                    '<a href="/cari" class="%s">Search</a>'
                    '<a href="/masuk">Log in</a>') % (
                        'on' if nav == 'beranda' else '',
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
        return '%.1f jt' % (n / 1000000)
    if n >= 1000:
        return '%.1f rb' % (n / 1000)
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
    head = ('<div class="phead"><a class="nm" href="%s">%s</a>'
            '<span class="un">@%s</span>'
            '<span class="tm">%s</span></div>') % (
                author_link, esc(r['display_name']),
                esc(r['username']), esc(rel_time(r['sort_time'])))
    repost_line = ''
    if show_reposter and r['reposter_name']:
        repost_line = ('<div class="repostline">%s reposted</div>'
                       % esc(r['reposter_name']))
    detail_link = '/utas/%d' % r['post_id']
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
        if r['author_id'] == user['id']:
            actions.append(act_form('/hapus', r['post_id'], csrf, nxt,
                                    'Delete', 'danger'))
    else:
        actions.append('<span class="act">%s<span>%s</span></span>'
                       % (ICON_REPOST, fmt_count(r['n_repost'])))
        actions.append('<span class="act">%s<span>%s</span></span>'
                       % (ICON_LIKE, fmt_count(r['n_like'])))
    return ('<article class="post">%s<div class="pbody">%s%s'
            '<a href="%s" style="display:block"><div class="ptext">%s</div></a>'
            '<div class="actions">%s</div>'
            '</div></article>') % (
                avatar_html(r['username']), repost_line, head,
                detail_link, esc(r['body']), ''.join(actions))


def compose_box(csrf, parent_id=None, placeholder='Start a thread...'):
    hid = ''
    if parent_id:
        hid = '<input type="hidden" name="parent_id" value="%d">' % parent_id
    return ('<div class="compose"><form method="post" action="/tulis">'
            '<input type="hidden" name="csrf" value="%s">%s'
            '<textarea name="body" maxlength="500" placeholder="%s" required></textarea>'
            '<div class="crow"><span class="ccount">500</span>'
            '<button class="btn" type="submit">Post</button></div>'
            '</form></div>') % (esc(csrf), hid, esc(placeholder))


# ---------------- queries ----------------
FEED_SQL = '''
SELECT f.kind, f.post_id, f.author_id, u.username, u.display_name,
       f.body, f.sort_time, f.reposter_id, ru.username AS reposter_name,
       (SELECT COUNT(*) FROM likes l WHERE l.post_id=f.post_id) AS n_like,
       (SELECT COUNT(*) FROM reposts r WHERE r.post_id=f.post_id) AS n_repost,
       (SELECT COUNT(*) FROM posts ch WHERE ch.parent_id=f.post_id) AS n_reply
FROM (
  SELECT 'post' AS kind, p.id AS post_id, p.user_id AS author_id,
         p.body, p.created_at AS sort_time, NULL AS reposter_id
  FROM posts p WHERE p.parent_id IS NULL
  UNION ALL
  SELECT 'repost', p.id, p.user_id, p.body, r.created_at, r.user_id
  FROM reposts r JOIN posts p ON p.id=r.post_id WHERE p.parent_id IS NULL
) f
JOIN users u ON u.id=f.author_id
LEFT JOIN users ru ON ru.id=f.reposter_id
'''

POST_SQL = '''
SELECT p.id AS post_id, p.user_id AS author_id, u.username, u.display_name,
       p.body, p.created_at AS sort_time, p.parent_id,
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
        self.err_page(404, 'Page not found.')

    def feed_items(self, where, params, limit, offset):
        c = self.c
        me = self.user['id'] if self.user else None
        rows = c.execute(FEED_SQL + where +
                         ' ORDER BY f.sort_time DESC, f.post_id DESC LIMIT ? OFFSET ?',
                         params + [limit, offset]).fetchall()
        liked, reposted = set(), set()
        if me:
            liked = {r[0] for r in
                     c.execute('SELECT post_id FROM likes WHERE user_id=?', (me,))}
            reposted = {r[0] for r in
                        c.execute('SELECT post_id FROM reposts WHERE user_id=?', (me,))}
        items, seen = [], set()
        for row in rows:
            d = dict(row)
            if d['post_id'] in seen:
                continue
            seen.add(d['post_id'])
            d['liked_by_me'] = d['post_id'] in liked
            d['reposted_by_me'] = d['post_id'] in reposted
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
            body += compose_box(csrf)
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
                      '<button class="btn" type="submit">Log out</button></form>') % (
                          esc(csrf), esc(u['bio']), esc(csrf))
        elif self.user:
            lbl = 'Unfollow' if is_following else 'Follow'
            action = ('<form method="post" action="/ikuti">'
                      '<input type="hidden" name="csrf" value="%s">'
                      '<input type="hidden" name="username" value="%s">'
                      '<input type="hidden" name="next" value="%s">'
                      '<button class="btn" type="submit">%s</button></form>') % (
                          esc(csrf), esc(username), esc(nxt), lbl)
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
        liked, reposted = set(), set()
        if me:
            liked = {r[0] for r in c.execute(
                'SELECT post_id FROM likes WHERE user_id=?', (me,))}
            reposted = {r[0] for r in c.execute(
                'SELECT post_id FROM reposts WHERE user_id=?', (me,))}
        if tab == 'utas':
            rows = c.execute(POST_SQL + ' WHERE p.user_id=? AND p.parent_id IS NULL'
                             ' ORDER BY p.created_at DESC, p.id DESC LIMIT 60', (u['id'],)).fetchall()
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
        csrf = self.sess['csrf'] if self.sess else ''
        nxt = '/utas/%d' % pid
        body = ('<div class="detail-head"><a href="/">Home</a> / Thread</div>'
                + post_row(d, self.user, csrf, nxt))
        if self.user:
            body += ('<div class="replybox">' +
                     compose_box(csrf, parent_id=pid,
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
            body += post_row(rd, self.user, csrf, nxt)
        self.send_html(200, page('Thread', self.user, body))

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
        self.c.execute('INSERT INTO posts (user_id, body, parent_id, created_at)'
                       ' VALUES (?,?,?,?)',
                       (self.user['id'], body, parent, now()))
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
        if not p or p['user_id'] != self.user['id']:
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
