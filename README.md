# URL Shortener

A multi-user URL shortening service with trilingual support, built with Flask.

## Features

- **URL Shortening** — convert long URLs to short links (e.g. `http://host/xF3aB9`)
- **Custom Short Codes** — define your own memorable short codes
- **Link Expiry** — set expiration: 1 day / 7 days / 30 days / permanent
- **QR Code Generation** — auto-generate QR code for each shortened link
- **User System** — register, login, password reset (email via SMTP)
- **Dashboard** — manage your links, track click counts, view stats
- **Click Analytics** — record IP, User-Agent, Referer, and geolocation (country/region/city)
- **Admin Panel** — manage all users and links (admin account required)
- **Trilingual i18n** — English / 简体中文 / 粵語（繁體中文）

## Tech Stack

| Layer | Technology |
|-------|------------|
| Web Framework | Flask 3.0 |
| Database | SQLite (default) / PostgreSQL |
| Frontend | Bootstrap 5 (CDN) |
| QR Code | qrcode + Pillow |
| Geolocation | ip-api.com (free, no API key) |
| Email | SMTP (optional) |

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the app
python app.py
```

Open http://localhost:5000 in your browser.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECRET_KEY` | Yes (production) | `dev-secret-key-...` | Flask session secret key |
| `PORT` | No | `5000` | Server port |
| `DATABASE_URL` | No | — | PostgreSQL connection string (SQLite used if not set) |
| `SMTP_HOST` | No | — | SMTP server host for password reset emails |
| `SMTP_PORT` | No | `587` | SMTP server port |
| `SMTP_USER` | No | — | SMTP username |
| `SMTP_PASS` | No | — | SMTP password |
| `SMTP_FROM` | No | `SMTP_USER` | Sender email address |

If SMTP is not configured, password reset links are displayed on the page (demo mode).

## Database

The app auto-creates and migrates the database on startup:

```
users ──1:N──→ url_mappings ──1:N──→ clicks
```

### Tables

- **users** — user accounts with password hashes and reset tokens
- **url_mappings** — long URL, short code, click count, expiry, owner
- **clicks** — per-visit analytics with IP, UA, referer, geolocation

## Deployment

```bash
# With Gunicorn (production)
gunicorn -c gunicorn_config.py app:app
```

## Admin Account

Create a user with username `admin` to access the admin panel at `/admin`.

## Project Structure

```
├── app.py                  # Main application (all routes, logic)
├── app_simple.py           # Minimal test app
├── gunicorn_config.py      # Gunicorn config (4 workers)
├── i18n.py                 # Trilingual i18n engine
├── requirements.txt        # Python dependencies
├── runtime.txt             # Python runtime version
├── urls.db                 # SQLite database (auto-created)
├── templates/              # 11 Jinja2 templates
│   ├── index.html          # Home page (shorten form)
│   ├── login.html          # Login page
│   ├── register.html       # Registration page
│   ├── dashboard.html      # User link management
│   ├── success.html        # Shorten result + QR code
│   ├── error.html          # Error page
│   ├── link_stats.html     # Click analytics
│   ├── admin_dashboard.html # Admin panel
│   ├── forgot_password.html # Password reset
│   ├── reset_password.html  # Set new password
│   └── _lang_switcher.html  # Language switcher component
├── static/
│   └── qrcodes/            # Generated QR code PNGs
└── translations/           # i18n JSON files
    ├── en.json
    ├── zh-CN.json
    └── zh-HK.json
```

## License

This project is for educational purposes.
