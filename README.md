# Peka

Threads-style microblogging app, written as a **single Python file** (`app.py`)
using only the **stdlib** (`http.server`, `sqlite3`, `hashlib`, `secrets`).
No pip, no frameworks, no dependencies.

Designed to run as a **Tor hidden service** (`.onion`, plain HTTP):
all CSS/JS inline, system font stack, zero external resources, zero CDNs,
zero trackers, zero webfonts. Core read/write features work **without
JavaScript** (plain HTML forms); JS is progressive enhancement only
(character counter).

## Run

```bash
PORT=18092 python3 app.py
```

- `PORT` from env, default `18092`.
- Binds **only** `127.0.0.1` (do not change to `0.0.0.0`).
- SQLite database auto-created at `data/peka.db` (WAL mode) on start.

## As a Tor hidden service

On a server running Tor, add to `/etc/tor/torrc`:

```
HiddenServiceDir /var/lib/tor/peka-social/
HiddenServicePort 80 127.0.0.1:18092
```

Copy your `hs_ed25519_secret_key` (+ `hostname` file) into that directory,
`chown debian-tor`, restart tor. The `.onion` address serves this app
over plain HTTP.

## Features

- **Auth**: sign up (username 3-20 `[a-z0-9_]`, display name, password min 8),
  log in/out. Passwords: PBKDF2-HMAC-SHA256 200k iterations + per-user salt.
  Sessions: random 32-byte token in `HttpOnly; SameSite=Lax` cookie
  (no `Secure` since it runs on http `.onion`), server-side session table,
  30-day expiry.
- **Threads**: 1-500 char text posts, delete your own.
- **Feed**: chronological global (20/page, `?page=N`), **Following** tab.
- **Replies**: reply to any thread; detail page shows replies + counts.
- **Likes**: toggle like + counts.
- **Reposts**: toggle repost; shown in feed with reposter attribution.
- **Follow**: follow/unfollow + follower/following counts.
- **Profile** `/@username`: name, bio (max 160, editable), join date, counts,
  **Threads / Replies / Likes** tabs. Pin one thread to the top of your profile.
- **Search** users.
- **Mentions**: `@username` in a thread links to their profile and notifies them.
- **Hashtags**: `#tag` in a thread links to its tag page; trending tags on Explore.
- **Notifications**: bell in nav with unread badge — likes, reposts, replies,
  mentions, follows. Marked read when opened.
- **Bookmarks**: save threads, read them later on the Bookmarks page.
- **Edit**: edit your own threads (marked edited).
- **Explore**: trending threads of the last 7 days, ranked by engagement.
- **Settings**: change display name, bio, and password.
- Relative timestamps in English ("just now", "5 min", "2 hr", "3 d").

## Security

- All user content `html.escape`d.
- All SQL parameterized.
- Per-session CSRF token on all POST forms.
- In-memory per-IP rate limits: sign up 5/hr, log in 20/hr, post 30/hr.
- Request body max 64KB (413 if larger).

## Data layout

| What | Path |
|---|---|
| App code | `app.py` |
| SQLite database (WAL) | `data/peka.db` |
| systemd unit | `peka-social.service` |

Tables: `users`, `sessions`, `posts` (`parent_id` for replies,
`edited_at`, `pinned`), `likes`, `reposts`, `follows`,
`notifications`, `bookmarks`.

## Known limitations

- Detail page shows one reply level (replies-to-replies are created fine
  and show on their direct parent's detail page).
- "Following" feed uses offset pagination; post+repost duplicates
  de-duped per page.
- Rate limits are in-memory (lost on restart) and per-process.
- No media uploads, DMs, notifications, or moderation.
