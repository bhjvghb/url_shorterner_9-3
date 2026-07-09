from flask import Flask, render_template, request, redirect, url_for, session, abort, jsonify
import os
import re
import string
import random
import uuid
import logging
import base64
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode
import requests

# 数据库适配优先使用 PostgreSQL（通过环境变量 DATABASE_URL），否则回退到 SQLite
import sqlite3
import psycopg2
import psycopg2.extras

from i18n import init_i18n, _, flash_msg

# 日志配置
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# ===== 初始化三语国际化系统 =====
init_i18n(app)

# 获取环境变量中的端口（Render 会自动设置）
port = int(os.environ.get("PORT", 5000))

# 保留字列表
RESERVED_WORDS = [
    'admin', 'api', 'login', 'register', 'dashboard', 'analytics',
    'shorten', 'r', 'static', 'user', 'users', 'profile', 'settings',
    'help', 'about', 'contact', 'privacy', 'terms', 'faq'
]

# 有效期选项映射
EXPIRY_OPTIONS = {
    '1d': timedelta(days=1),
    '7d': timedelta(days=7),
    '30d': timedelta(days=30),
    'forever': None
}

# ------------------ 数据库连接工厂 ------------------
def get_db_connection():
    """根据环境变量返回 PostgreSQL 或 SQLite 连接"""
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        conn = psycopg2.connect(database_url, cursor_factory=psycopg2.extras.DictCursor)
        return conn
    else:
        conn = sqlite3.connect('urls.db')
        conn.row_factory = sqlite3.Row
        return conn

# ------------------ 数据库初始化（PostgreSQL 版） ------------------
def init_db():
    """创建表并检查/补充缺失列（支持 PostgreSQL 和 SQLite）"""
    conn = get_db_connection()
    cur = conn.cursor()
    is_postgres = os.environ.get('DATABASE_URL') is not None

    # ---------- 创建 users 表 ----------
    if is_postgres:
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) NOT NULL UNIQUE,
                email VARCHAR(255) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reset_token VARCHAR(36),
                reset_token_expiry TIMESTAMP
            )
        ''')
    else:
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reset_token TEXT,
                reset_token_expiry TIMESTAMP
            )
        ''')

    # ---------- 创建 url_mappings 表 ----------
    if is_postgres:
        cur.execute('''
            CREATE TABLE IF NOT EXISTS url_mappings (
                id SERIAL PRIMARY KEY,
                long_url TEXT NOT NULL,
                short_code VARCHAR(50) NOT NULL UNIQUE,
                is_custom BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                click_count INTEGER DEFAULT 0,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                expires_at TIMESTAMP,
                password_hash VARCHAR(255),
                tag VARCHAR(50),
                updated_at TIMESTAMP,
                reminder_sent INTEGER DEFAULT 0
            )
        ''')
    else:
        cur.execute('''
            CREATE TABLE IF NOT EXISTS url_mappings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                long_url TEXT NOT NULL,
                short_code TEXT NOT NULL UNIQUE,
                is_custom BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                click_count INTEGER DEFAULT 0,
                user_id INTEGER REFERENCES users(id),
                expires_at TIMESTAMP,
                password_hash TEXT,
                tag TEXT,
                updated_at TIMESTAMP,
                reminder_sent INTEGER DEFAULT 0
            )
        ''')
    # 迁移：为已有数据库添加 reminder_sent 列
    try:
        if is_postgres:
            cur.execute("ALTER TABLE url_mappings ADD COLUMN IF NOT EXISTS reminder_sent INTEGER DEFAULT 0")
        else:
            cur.execute("ALTER TABLE url_mappings ADD COLUMN reminder_sent INTEGER DEFAULT 0")
    except Exception:
        pass  # 列已存在则忽略

    # ---------- 创建 clicks 表 ----------
    if is_postgres:
        cur.execute('''
            CREATE TABLE IF NOT EXISTS clicks (
                id SERIAL PRIMARY KEY,
                short_code VARCHAR(50) NOT NULL,
                ip_address VARCHAR(45),
                user_agent TEXT,
                accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                referer TEXT,
                country VARCHAR(100),
                region VARCHAR(100),
                city VARCHAR(100),
                FOREIGN KEY (short_code) REFERENCES url_mappings(short_code) ON DELETE CASCADE
            )
        ''')
        cur.execute("CREATE INDEX IF NOT EXISTS idx_clicks_short_code ON clicks (short_code)")
    else:
        cur.execute('''
            CREATE TABLE IF NOT EXISTS clicks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                short_code TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                referer TEXT,
                country TEXT,
                region TEXT,
                city TEXT,
                FOREIGN KEY (short_code) REFERENCES url_mappings(short_code) ON DELETE CASCADE
            )
        ''')
        cur.execute("CREATE INDEX IF NOT EXISTS idx_clicks_short_code ON clicks (short_code)")

    # ---------- 检查并补充缺失的列 ----------
    def column_exists(table, column):
        if is_postgres:
            cur.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name=%s AND column_name=%s
            """, (table, column))
            return cur.fetchone() is not None
        else:
            cur.execute(f"PRAGMA table_info({table})")
            columns = [row[1] for row in cur.fetchall()]
            return column in columns

    # 为 url_mappings 添加可能缺失的列
    if not column_exists('url_mappings', 'is_custom'):
        if is_postgres:
            cur.execute("ALTER TABLE url_mappings ADD COLUMN is_custom BOOLEAN DEFAULT FALSE")
        else:
            cur.execute("ALTER TABLE url_mappings ADD COLUMN is_custom BOOLEAN DEFAULT 0")
        print("✅ Add an is_custom column to url_mappings")

    if not column_exists('url_mappings', 'click_count'):
        if is_postgres:
            cur.execute("ALTER TABLE url_mappings ADD COLUMN click_count INTEGER DEFAULT 0")
        else:
            cur.execute("ALTER TABLE url_mappings ADD COLUMN click_count INTEGER DEFAULT 0")
        print("✅ Add a click_count column to url_mappings")

    if not column_exists('url_mappings', 'user_id'):
        if is_postgres:
            cur.execute("ALTER TABLE url_mappings ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE SET NULL")
        else:
            cur.execute("ALTER TABLE url_mappings ADD COLUMN user_id INTEGER REFERENCES users(id)")
        print("✅ Add a user_id column to url_mappings")

    if not column_exists('url_mappings', 'expires_at'):
        if is_postgres:
            cur.execute("ALTER TABLE url_mappings ADD COLUMN expires_at TIMESTAMP")
        else:
            cur.execute("ALTER TABLE url_mappings ADD COLUMN expires_at TIMESTAMP")
        print("✅ Add an expires_at column to url_mappings")

    # 新增：密码保护 / 标签 / 编辑时间
    for col_name, col_type in [('password_hash', 'VARCHAR(255)' if is_postgres else 'TEXT'),
                                ('tag', 'VARCHAR(50)' if is_postgres else 'TEXT'),
                                ('updated_at', 'TIMESTAMP')]:
        if not column_exists('url_mappings', col_name):
            cur.execute(f"ALTER TABLE url_mappings ADD COLUMN {col_name} {col_type}")
            print(f"✅ Add a {col_name} column to url_mappings")

    # 为 users 表添加可能缺失的列
    if not column_exists('users', 'reset_token'):
        if is_postgres:
            cur.execute("ALTER TABLE users ADD COLUMN reset_token VARCHAR(36)")
        else:
            cur.execute("ALTER TABLE users ADD COLUMN reset_token TEXT")
        print("✅ Add a reset_token column to users")

    if not column_exists('users', 'reset_token_expiry'):
        if is_postgres:
            cur.execute("ALTER TABLE users ADD COLUMN reset_token_expiry TIMESTAMP")
        else:
            cur.execute("ALTER TABLE users ADD COLUMN reset_token_expiry TIMESTAMP")
        print("✅ Add a reset_token_expiry column to users")

    # 为 clicks 表添加地理位置列
    for col_name in ('country', 'region', 'city'):
        if not column_exists('clicks', col_name):
            col_type = "VARCHAR(100)" if is_postgres else "TEXT"
            cur.execute(f"ALTER TABLE clicks ADD COLUMN {col_name} {col_type}")
            print(f"✅ Add a {col_name} column to clicks")

    conn.commit()
    cur.close()
    conn.close()
    print("✅ Database initialization/upgrade completed")

# ------------------ 密码辅助函数 ------------------
def hash_password(password):
    return generate_password_hash(password)

def verify_password(password_hash, password):
    return check_password_hash(password_hash, password)

# ------------------ IP 地理定位 ------------------
def geolocate_ip(ip_address):
    """通过 ip-api.com 免费 API 查询 IP 地理位置（无 API Key，每分钟45次请求限制）"""
    # 跳过本地/私有 IP
    private_prefixes = ('127.', '10.', '192.168.', '172.16.', '172.17.', '172.18.',
                        '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
                        '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
                        '172.29.', '172.30.', '172.31.', '0.', '::1')
    if ip_address.startswith(private_prefixes) or ip_address == 'localhost':
        return {'country': 'Local', 'region': '', 'city': ''}

    try:
        resp = requests.get(f'http://ip-api.com/json/{ip_address}?fields=country,regionName,city',
                           timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            # ip-api.com 在某些情况下会返回 "CN"/"China"，统一规范为主大陆表述
            country_raw = data.get('country', '')
            if country_raw in ('CN', 'China', '中国', '中華人民共和國', "People's Republic of China"):
                country = 'Mainland China'
            else:
                country = country_raw
            return {
                'country': country,
                'region': data.get('regionName', ''),
                'city': data.get('city', '')
            }
    except Exception as e:
        logger.warning(f"IP geolocation failed for {ip_address}: {e}")

    return {'country': '', 'region': '', 'city': ''}

# ------------------ 发送密码重置邮件 ------------------
def send_reset_email(to_email, reset_link):
    """通过 SMTP 发送密码重置邮件，配置通过环境变量传入"""
    smtp_host = os.environ.get('SMTP_HOST')
    smtp_port = os.environ.get('SMTP_PORT', '587')
    smtp_user = os.environ.get('SMTP_USER')
    smtp_pass = os.environ.get('SMTP_PASS')
    smtp_from = os.environ.get('SMTP_FROM', smtp_user or 'noreply@urlshortener.com')

    if not all([smtp_host, smtp_user, smtp_pass]):
        logger.info(f"[DEMO MODE] SMTP not configured. Reset link: {reset_link}")
        return False, reset_link  # 返回链接供演示模式使用

    try:
        msg = MIMEMultipart()
        msg['From'] = smtp_from
        msg['To'] = to_email
        msg['Subject'] = 'Password Reset - URL Shortener'
        body = f"""Hi,

You requested a password reset for your URL Shortener account.

Click the link below to reset your password (valid for 1 hour):
{reset_link}

If you did not request this, please ignore this email.

--
URL Shortener
"""
        msg.attach(MIMEText(body, 'plain', 'utf-8'))

        with smtplib.SMTP(smtp_host, int(smtp_port), timeout=10) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)

        logger.info(f"Password reset email sent to {to_email}")
        return True, None
    except Exception as e:
        logger.error(f"Failed to send reset email to {to_email}: {e}")
        return False, str(reset_link)  # 失败时回退到演示模式

# ------------------ 登录保护装饰器 ------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ------------------ 短码生成与验证 ------------------
def generate_short_code(length=6):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def validate_custom_code(code):
    if len(code) < 3 or len(code) > 20:
        return False, 'code_length_invalid'
    if not re.match(r'^[a-zA-Z0-9_-]+$', code):
        return False, 'code_chars_invalid'
    if code.startswith('-') or code.endswith('-'):
        return False, 'code_hyphen_invalid'
    if '--' in code:
        return False, 'code_consecutive_hyphens'
    if code.lower() in RESERVED_WORDS:
        return False, 'code_reserved'
    return True, 'ok'

# ------------------ 首页 ------------------
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM url_mappings")
    total_urls = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM url_mappings WHERE is_custom = true")
    custom_urls = cur.fetchone()[0]
    cur.close()
    conn.close()
    return render_template('index.html',
                         total_urls=total_urls,
                         custom_urls=custom_urls,
                         host_url=request.host_url,
                         session=session)

# ------------------ 缩短URL ------------------
@app.route('/shorten', methods=['POST'])
@login_required
def shorten_url():
    long_url = request.form.get('long_url', '').strip()
    custom_code = request.form.get('custom_code', '').strip()
    expiry_choice = request.form.get('expiry', 'forever')
    password = request.form.get('password', '').strip()  # 可选密码保护

    if not long_url:
        return render_error_page(key='url_required')
    if not long_url.startswith(('http://', 'https://')):
        long_url = 'https://' + long_url

    conn = get_db_connection()
    cur = conn.cursor()
    is_postgres = os.environ.get('DATABASE_URL') is not None

    if custom_code:
        is_valid, error_key = validate_custom_code(custom_code)
        if not is_valid:
            cur.close()
            conn.close()
            return render_error_page(key=error_key, code=custom_code)
        cur.execute("SELECT * FROM url_mappings WHERE short_code = %s" if is_postgres else "SELECT * FROM url_mappings WHERE short_code = ?", (custom_code,))
        if cur.fetchone():
            cur.close()
            conn.close()
            return render_error_page(key='code_in_use', code=custom_code)
        short_code = custom_code
        is_custom = True
    else:
        attempts = 0
        while attempts < 10:
            short_code = generate_short_code(6)
            cur.execute("SELECT * FROM url_mappings WHERE short_code = %s" if is_postgres else "SELECT * FROM url_mappings WHERE short_code = ?", (short_code,))
            if not cur.fetchone() and short_code.lower() not in RESERVED_WORDS:
                break
            attempts += 1
        else:
            cur.close()
            conn.close()
            return render_error_page(key='gen_failed')
        is_custom = False

    user_id = session.get('user_id')

    # 密码编码（base64 可逆编码，便于用户在仪表盘查看）
    pwd_hash = base64.b64encode(password.encode()).decode() if password else None

    # 计算过期时间
    expires_at = None
    if expiry_choice in EXPIRY_OPTIONS:
        delta = EXPIRY_OPTIONS[expiry_choice]
        if delta:
            expires_at = datetime.now() + delta
    else:
        expires_at = None

    try:
        if is_postgres:
            cur.execute("""
                INSERT INTO url_mappings (long_url, short_code, is_custom, click_count, user_id, expires_at, password_hash)
                VALUES (%s, %s, %s, 0, %s, %s, %s)
            """, (long_url, short_code, is_custom, user_id, expires_at, pwd_hash))
        else:
            cur.execute("""
                INSERT INTO url_mappings (long_url, short_code, is_custom, click_count, user_id, expires_at, password_hash)
                VALUES (?, ?, ?, 0, ?, ?, ?)
            """, (long_url, short_code, 1 if is_custom else 0, user_id, expires_at, pwd_hash))
        conn.commit()
    except Exception as e:
        cur.close()
        conn.close()
        return render_error_page(key='db_error', error=str(e))

    cur.close()
    conn.close()
    short_url = f"{request.host_url}{short_code}"
    
    # ------------------ 生成二维码 ------------------
    try:
        # 确保目录存在
        qrcode_dir = os.path.join(app.static_folder, 'qrcodes')
        os.makedirs(qrcode_dir, exist_ok=True)
        
        # 生成二维码图片
        img = qrcode.make(short_url)
        img_path = os.path.join(qrcode_dir, f'{short_code}.png')
        img.save(img_path)
    except Exception as e:
        # 二维码生成失败不影响主要功能，仅打印错误
        print(f"⚠️ QR code generation failed: {e}")
    
    return render_success_page(long_url, short_url, short_code, is_custom, expires_at)

# ------------------ 批量缩短 ------------------
@app.route('/batch_shorten', methods=['POST'])
@login_required
def batch_shorten():
    data = request.get_json(silent=True)
    if not data or 'items' not in data:
        return jsonify({'error': _('url_required')}), 400

    items = data.get('items', [])
    expiry_choice = data.get('expiry', 'forever')
    user_id = session.get('user_id')

    if not items or not isinstance(items, list):
        return jsonify({'error': _('url_required')}), 400

    expires_at = None
    if expiry_choice in EXPIRY_OPTIONS:
        delta = EXPIRY_OPTIONS[expiry_choice]
        if delta:
            expires_at = datetime.now() + delta

    conn = get_db_connection()
    cur = conn.cursor()
    is_postgres = os.environ.get('DATABASE_URL') is not None

    results = []
    used_codes = set()  # 本次批量内已使用的短码

    for item in items:
        long_url = (item.get('url', '') or '').strip()
        custom_code = (item.get('custom_code', '') or '').strip()
        password = (item.get('password', '') or '').strip()

        if not long_url:
            results.append({'url': long_url, 'success': False, 'error': _('url_required')})
            continue

        if not long_url.startswith(('http://', 'https://')):
            long_url = 'https://' + long_url

        is_custom = False
        if custom_code:
            is_valid, error_key = validate_custom_code(custom_code)
            if not is_valid:
                results.append({'url': long_url, 'success': False, 'error': _(error_key)})
                continue
            cur.execute("SELECT * FROM url_mappings WHERE short_code = %s" if is_postgres else "SELECT * FROM url_mappings WHERE short_code = ?", (custom_code,))
            if cur.fetchone() or custom_code in used_codes:
                results.append({'url': long_url, 'success': False, 'error': _('code_in_use', code=custom_code)})
                continue
            short_code = custom_code
            is_custom = True
            used_codes.add(short_code)
        else:
            for _ in range(10):
                code = generate_short_code(6)
                cur.execute("SELECT * FROM url_mappings WHERE short_code = %s" if is_postgres else "SELECT * FROM url_mappings WHERE short_code = ?", (code,))
                if not cur.fetchone() and code.lower() not in RESERVED_WORDS and code not in used_codes:
                    short_code = code
                    used_codes.add(short_code)
                    break
            else:
                results.append({'url': long_url, 'success': False, 'error': _('gen_failed')})
                continue

        pwd_hash = base64.b64encode(password.encode()).decode() if password else None

        try:
            if is_postgres:
                cur.execute("""
                    INSERT INTO url_mappings (long_url, short_code, is_custom, click_count, user_id, expires_at, password_hash)
                    VALUES (%s, %s, %s, 0, %s, %s, %s)
                """, (long_url, short_code, is_custom, user_id, expires_at, pwd_hash))
            else:
                cur.execute("""
                    INSERT INTO url_mappings (long_url, short_code, is_custom, click_count, user_id, expires_at, password_hash)
                    VALUES (?, ?, ?, 0, ?, ?, ?)
                """, (long_url, short_code, 1 if is_custom else 0, user_id, expires_at, pwd_hash))
            conn.commit()

            short_url = f"{request.host_url}{short_code}"
            try:
                qrcode_dir = os.path.join(app.static_folder, 'qrcodes')
                os.makedirs(qrcode_dir, exist_ok=True)
                img = qrcode.make(short_url)
                img.save(os.path.join(qrcode_dir, f'{short_code}.png'))
            except Exception:
                pass

            results.append({
                'url': long_url,
                'success': True,
                'short_code': short_code,
                'short_url': short_url,
                'is_custom': is_custom,
                'is_protected': bool(pwd_hash)
            })
        except Exception as e:
            conn.rollback()
            results.append({'url': long_url, 'success': False, 'error': str(e)[:100]})

    cur.close()
    conn.close()
    return jsonify({'results': results, 'host_url': request.host_url})

# ------------------ 重定向 ------------------
@app.route('/<short_code>')
def redirect_to_long_url(short_code):
    conn = get_db_connection()
    cur = conn.cursor()
    is_postgres = os.environ.get('DATABASE_URL') is not None

    cur.execute("SELECT id, long_url, expires_at, password_hash FROM url_mappings WHERE short_code = %s" if is_postgres else "SELECT id, long_url, expires_at, password_hash FROM url_mappings WHERE short_code = ?", (short_code,))
    result = cur.fetchone()
    if not result:
        cur.close()
        conn.close()
        return render_error_page(key='url_not_found', status_code=404)

    url_id, long_url, expires_at, password_hash = result
    if expires_at and expires_at < datetime.now():
        cur.close()
        conn.close()
        return render_error_page(key='url_expired', status_code=410)

    # 密码保护检查
    if password_hash:
        cur.close()
        conn.close()
        session['redirect_target'] = short_code
        return redirect(url_for('verify_password_page', short_code=short_code))

    cur.execute("UPDATE url_mappings SET click_count = click_count + 1 WHERE id = %s" if is_postgres else "UPDATE url_mappings SET click_count = click_count + 1 WHERE id = ?", (url_id,))

# 获取真实客户端 IP
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip_address and ',' in ip_address:
        ip_address = ip_address.split(',')[0].strip()

    user_agent = request.headers.get('User-Agent', 'Unknown')
    referer = request.headers.get('Referer', '')

    # IP 地理定位
    geo = geolocate_ip(ip_address)

    if is_postgres:
        cur.execute("""
            INSERT INTO clicks (short_code, ip_address, user_agent, referer, country, region, city)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (short_code, ip_address, user_agent, referer, geo['country'], geo['region'], geo['city']))
    else:
        cur.execute("""
            INSERT INTO clicks (short_code, ip_address, user_agent, referer, country, region, city)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (short_code, ip_address, user_agent, referer, geo['country'], geo['region'], geo['city']))

    conn.commit()
    cur.close()
    conn.close()
    return redirect(long_url)

# ------------------ 密码保护验证 ------------------
@app.route('/p/<short_code>', methods=['GET', 'POST'])
def verify_password_page(short_code):
    if request.method == 'POST':
        password = request.form.get('password', '')
        conn = get_db_connection()
        cur = conn.cursor()
        is_postgres = os.environ.get('DATABASE_URL') is not None

        cur.execute("SELECT long_url, password_hash FROM url_mappings WHERE short_code = %s" if is_postgres else "SELECT long_url, password_hash FROM url_mappings WHERE short_code = ?", (short_code,))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            return render_error_page(key='url_not_found', status_code=404)

        long_url, pwd_hash = row
        # 解码 base64 验证密码
        try:
            stored_password = base64.b64decode(pwd_hash).decode() if pwd_hash else None
        except Exception:
            stored_password = None

        if stored_password and password == stored_password:
            # 密码正确：记录点击并重定向
            ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
            if ip_address and ',' in ip_address:
                ip_address = ip_address.split(',')[0].strip()
            user_agent = request.headers.get('User-Agent', '')
            referer = request.headers.get('Referer', '')
            geo = geolocate_ip(ip_address)
            if is_postgres:
                cur.execute("UPDATE url_mappings SET click_count = click_count + 1 WHERE short_code = %s", (short_code,))
                cur.execute("INSERT INTO clicks (short_code, ip_address, user_agent, referer, country, region, city) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                           (short_code, ip_address, user_agent, referer, geo['country'], geo['region'], geo['city']))
            else:
                cur.execute("UPDATE url_mappings SET click_count = click_count + 1 WHERE short_code = ?", (short_code,))
                cur.execute("INSERT INTO clicks (short_code, ip_address, user_agent, referer, country, region, city) VALUES (?,?,?,?,?,?,?)",
                           (short_code, ip_address, user_agent, referer, geo['country'], geo['region'], geo['city']))
            conn.commit()
            cur.close()
            conn.close()
            return redirect(long_url)
        else:
            cur.close()
            conn.close()
            return render_template('protected.html', short_code=short_code, error=_('password_incorrect'))

    return render_template('protected.html', short_code=short_code, error=None)

# ------------------ 注册 ------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = (request.form.get('username', '') or '').strip()
        email = (request.form.get('email', '') or '').strip()
        password = (request.form.get('password', '') or '')
        confirm = (request.form.get('confirm_password', '') or '')

        if not username or not email or not password:
            return render_error_page(key='all_fields_required')
        if password != confirm:
            return render_error_page(key='passwords_not_match')
        if len(password) < 6:
            return render_error_page(key='password_too_short')

        conn = get_db_connection()
        cur = conn.cursor()
        is_postgres = os.environ.get('DATABASE_URL') is not None

        try:
            if is_postgres:
                cur.execute("""
                    INSERT INTO users (username, email, password_hash)
                    VALUES (%s, %s, %s)
                """, (username, email, hash_password(password)))
            else:
                cur.execute("""
                    INSERT INTO users (username, email, password_hash)
                    VALUES (?, ?, ?)
                """, (username, email, hash_password(password)))
            conn.commit()
        except Exception as e:
            conn.rollback()
            if 'duplicate key' in str(e).lower() or 'unique constraint' in str(e).lower():
                if 'username' in str(e).lower():
                    return render_error_page(key='username_exists')
                elif 'email' in str(e).lower():
                    return render_error_page(key='email_exists')
            return render_error_page(key='registration_failed', error=str(e))
        finally:
            cur.close()
            conn.close()
        return redirect(url_for('login'))
    return render_template('register.html')

# ------------------ 登录 ------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = (request.form.get('username', '') or '').strip()
        password = (request.form.get('password', '') or '')

        conn = get_db_connection()
        cur = conn.cursor()
        is_postgres = os.environ.get('DATABASE_URL') is not None

        cur.execute("SELECT id, username, password_hash FROM users WHERE username = %s OR email = %s" if is_postgres else "SELECT id, username, password_hash FROM users WHERE username = ? OR email = ?", (username_or_email, username_or_email))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and verify_password(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('index'))
        else:
            return render_error_page(key='invalid_credentials')
    return render_template('login.html')

# ------------------ 登出 ------------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ------------------ 忘记密码 ------------------
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = (request.form.get('email', '') or '').strip()
        conn = get_db_connection()
        cur = conn.cursor()
        is_postgres = os.environ.get('DATABASE_URL') is not None

        cur.execute("SELECT id FROM users WHERE email = %s" if is_postgres else "SELECT id FROM users WHERE email = ?", (email,))
        user = cur.fetchone()
        if user:
            token = str(uuid.uuid4())
            expiry = datetime.now() + timedelta(hours=1)
            if is_postgres:
                cur.execute("UPDATE users SET reset_token = %s, reset_token_expiry = %s WHERE id = %s", (token, expiry, user[0]))
            else:
                cur.execute("UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?", (token, expiry, user[0]))
            conn.commit()
            reset_link = url_for('reset_password', token=token, _external=True)

            # 尝试通过 SMTP 发送邮件，失败则回退到页面显示链接
            success, fallback_link = send_reset_email(email, reset_link)
            cur.close()
            conn.close()

            if success:
                logger.info(f"Reset email sent to {email}")
            else:
                logger.warning(f"SMTP unavailable, showing reset link on page for {email}")

            return render_template('forgot_password.html',
                                 email_sent=True,
                                 reset_link=fallback_link if fallback_link else None)

        cur.close()
        conn.close()
        # 为安全起见，无论邮箱是否存在都显示相同的提示信息
        return render_template('forgot_password.html', email_sent=True, reset_link=None)
    return render_template('forgot_password.html')

# ------------------ 重置密码 ------------------
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_db_connection()
    cur = conn.cursor()
    is_postgres = os.environ.get('DATABASE_URL') is not None

    cur.execute("SELECT id FROM users WHERE reset_token = %s AND reset_token_expiry > %s" if is_postgres else "SELECT id FROM users WHERE reset_token = ? AND reset_token_expiry > ?", (token, datetime.now()))
    user = cur.fetchone()
    if not user:
        cur.close()
        conn.close()
        return render_error_page(key='token_invalid', status_code=400)

    if request.method == 'POST':
        new_password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        if new_password != confirm:
            cur.close()
            conn.close()
            return render_error_page(key='passwords_not_match')
        if len(new_password) < 6:
            cur.close()
            conn.close()
            return render_error_page(key='password_too_short')
        if is_postgres:
            cur.execute("UPDATE users SET password_hash = %s, reset_token = NULL, reset_token_expiry = NULL WHERE id = %s", (hash_password(new_password), user[0]))
        else:
            cur.execute("UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?", (hash_password(new_password), user[0]))
        conn.commit()
        cur.close()
        conn.close()
        return redirect(url_for('login'))
    cur.close()
    conn.close()
    return render_template('reset_password.html', token=token)

# ------------------ 定时任务（Cron） ------------------
CRON_SECRET = os.environ.get('CRON_SECRET', 'default-cron-secret-change-me')

def _check_cron_token():
    """简单的 token 验证，防止外部随意调用 cron 端点"""
    token = request.args.get('token', '')
    return token == CRON_SECRET

@app.route('/cron/expiry-reminder')
def cron_expiry_reminder():
    """检查 30 分钟内即将到期的链接，发送邮件提醒用户"""
    if not _check_cron_token():
        return 'Unauthorized', 401

    conn = get_db_connection()
    cur = conn.cursor()
    is_postgres = os.environ.get('DATABASE_URL') is not None

    now = datetime.now()
    window_end = now + timedelta(minutes=30)
    reminder_sent = 0

    # 查找 30 分钟内到期且未发送过提醒的链接
    cur.execute("""
        SELECT um.short_code, um.long_url, um.expires_at, um.reminder_sent,
               u.email, u.username
        FROM url_mappings um
        JOIN users u ON um.user_id = u.id
        WHERE um.expires_at IS NOT NULL
          AND um.expires_at <= %s
          AND um.expires_at > %s
          AND (um.reminder_sent = 0 OR um.reminder_sent IS NULL)
    """ if is_postgres else """
        SELECT um.short_code, um.long_url, um.expires_at, um.reminder_sent,
               u.email, u.username
        FROM url_mappings um
        JOIN users u ON um.user_id = u.id
        WHERE um.expires_at IS NOT NULL
          AND um.expires_at <= ?
          AND um.expires_at > ?
          AND (um.reminder_sent = 0 OR um.reminder_sent IS NULL)
    """, (window_end, now))

    rows = cur.fetchall()

    smtp_configured = all([os.environ.get('SMTP_HOST'), os.environ.get('SMTP_USER'), os.environ.get('SMTP_PASS')])

    for row in rows:
        short_code, long_url, expires_at, _, email, username = row
        short_url = f"{request.host_url}{short_code}"
        exp_str = expires_at.strftime('%Y-%m-%d %H:%M UTC') if isinstance(expires_at, datetime) else str(expires_at)

        if smtp_configured:
            try:
                send_expiry_email(email, username, short_code, short_url, long_url, exp_str)
            except Exception as e:
                logger.warning(f"Failed to send expiry reminder for {short_code}: {e}")
                continue

        # 标记已发送提醒
        cur.execute("UPDATE url_mappings SET reminder_sent = 1 WHERE short_code = %s" if is_postgres else "UPDATE url_mappings SET reminder_sent = 1 WHERE short_code = ?", (short_code,))
        reminder_sent += 1

    conn.commit()
    cur.close()
    conn.close()

    return jsonify({'reminders_sent': reminder_sent, 'smtp_configured': smtp_configured})

@app.route('/cron/cleanup-expired')
def cron_cleanup_expired():
    """清理已过期的链接（软删除，标记为已过期）"""
    if not _check_cron_token():
        return 'Unauthorized', 401

    conn = get_db_connection()
    cur = conn.cursor()
    is_postgres = os.environ.get('DATABASE_URL') is not None

    cur.execute("SELECT COUNT(*) FROM url_mappings WHERE expires_at IS NOT NULL AND expires_at < %s" if is_postgres else "SELECT COUNT(*) FROM url_mappings WHERE expires_at IS NOT NULL AND expires_at < ?", (datetime.now(),))
    expired_count = cur.fetchone()[0]
    cur.close()
    conn.close()

    return jsonify({'expired_links': expired_count, 'note': '这些链接已阻止访问但未被删除。'})

def send_expiry_email(to_email, username, short_code, short_url, long_url, exp_str):
    """发送链接到期提醒邮件"""
    smtp_host = os.environ.get('SMTP_HOST')
    smtp_port = os.environ.get('SMTP_PORT', '587')
    smtp_user = os.environ.get('SMTP_USER')
    smtp_pass = os.environ.get('SMTP_PASS')
    smtp_from = os.environ.get('SMTP_FROM', smtp_user or 'noreply@linksnap.com')

    if not all([smtp_host, smtp_user, smtp_pass]):
        logger.info(f"[DEMO] Expiry reminder: {short_code} expires {exp_str}")
        return

    msg = MIMEMultipart()
    msg['From'] = smtp_from
    msg['To'] = to_email
    msg['Subject'] = f'LinkSnap - Your short link {short_code} is expiring soon'
    body = f"""Hi {username},

Your short link is about to expire:

  Short Code: {short_code}
  Short URL:  {short_url}
  Long URL:   {long_url}
  Expires At: {exp_str}

You can extend the lifespan by visiting your dashboard:
  {request.host_url}dashboard

--
LinkSnap
"""
    msg.attach(MIMEText(body, 'plain', 'utf-8'))

    with smtplib.SMTP(smtp_host, int(smtp_port), timeout=10) as server:
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)

# ------------------ 仪表盘 ------------------
@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    search = request.args.get('search', '').strip()
    tag_filter = request.args.get('tag', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 10

    conn = get_db_connection()
    cur = conn.cursor()
    is_postgres = os.environ.get('DATABASE_URL') is not None

    # 构建查询
    base_where = "WHERE user_id = %s" if is_postgres else "WHERE user_id = ?"
    params = [user_id]

    if search:
        base_where += (" AND (long_url LIKE %s OR short_code LIKE %s)" if is_postgres
                       else " AND (long_url LIKE ? OR short_code LIKE ?)")
        params.extend([f'%{search}%', f'%{search}%'])

    if tag_filter:
        base_where += (" AND tag = %s" if is_postgres else " AND tag = ?")
        params.append(tag_filter)

    # 获取总数（分页用）
    count_sql = f"SELECT COUNT(*) FROM url_mappings {base_where}"
    cur.execute(count_sql, tuple(params))
    total_links = cur.fetchone()[0]
    total_pages = max(1, (total_links + per_page - 1) // per_page)
    page = min(page, total_pages)

    # 获取所有标签（用于筛选下拉）
    tag_sql = "SELECT DISTINCT tag FROM url_mappings WHERE user_id = %s AND tag IS NOT NULL AND tag != '' ORDER BY tag" if is_postgres else "SELECT DISTINCT tag FROM url_mappings WHERE user_id = ? AND tag IS NOT NULL AND tag != '' ORDER BY tag"
    cur.execute(tag_sql, (user_id,))
    tags = [r[0] for r in cur.fetchall()]

    # 分页查询
    offset = (page - 1) * per_page
    select_sql = f"""
        SELECT short_code, long_url, click_count, created_at, is_custom, expires_at, password_hash, tag
        FROM url_mappings {base_where}
        ORDER BY created_at DESC
        LIMIT {per_page} OFFSET {offset}
    """
    cur.execute(select_sql, tuple(params))
    rows = cur.fetchall()

    urls = []
    for row in rows:
        short_code, long_url, click_count, created_at, is_custom, expires_at, password_hash, tag = row
        is_expired = False
        if expires_at and expires_at < datetime.now():
            is_expired = True

        short_url = f"{request.host_url}{short_code}"
        qrcode_path = os.path.join(app.static_folder, 'qrcodes', f'{short_code}.png')
        qrcode_exists = os.path.exists(qrcode_path)

        urls.append({
            'short_code': short_code,
            'long_url': long_url,
            'short_url': short_url,
            'click_count': click_count,
            'created_at': created_at,
            'is_custom': is_custom,
            'expires_at': expires_at,
            'is_expired': is_expired,
            'qrcode_exists': qrcode_exists,
            'is_protected': bool(password_hash),
            'tag': tag or ''
        })
    cur.close()
    conn.close()
    return render_template('dashboard.html', urls=urls, username=session['username'],
                          search=search, tag_filter=tag_filter, tags=tags,
                          page=page, total_pages=total_pages, total_links=total_links)

# ------------------ 删除链接 ------------------
@app.route('/delete/<short_code>', methods=['POST'])
@login_required
def delete_link(short_code):
    user_id = session['user_id']
    conn = get_db_connection()
    cur = conn.cursor()
    is_postgres = os.environ.get('DATABASE_URL') is not None

    cur.execute("SELECT user_id FROM url_mappings WHERE short_code = %s" if is_postgres else "SELECT user_id FROM url_mappings WHERE short_code = ?", (short_code,))
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        return render_error_page(key='link_not_found', status_code=404)
    owner_id = row[0]
    if owner_id != user_id and session.get('username') != 'admin':
        cur.close()
        conn.close()
        return render_error_page(key='not_owner', status_code=403)

    # 删除链接
    cur.execute("DELETE FROM url_mappings WHERE short_code = %s" if is_postgres else "DELETE FROM url_mappings WHERE short_code = ?", (short_code,))
    # 删除相关点击记录（外键级联删除可能已自动处理，但 SQLite 默认不开启外键，手动删除确保兼容）
    cur.execute("DELETE FROM clicks WHERE short_code = %s" if is_postgres else "DELETE FROM clicks WHERE short_code = ?", (short_code,))
    conn.commit()
    cur.close()
    conn.close()
    
    # 删除对应的二维码文件
    try:
        qrcode_path = os.path.join(app.static_folder, 'qrcodes', f'{short_code}.png')
        if os.path.exists(qrcode_path):
            os.remove(qrcode_path)
    except:
        pass
    
    return redirect(url_for('dashboard'))

# ------------------ 延长有效期 ------------------
@app.route('/extend/<short_code>', methods=['POST'])
@login_required
def extend_link(short_code):
    user_id = session['user_id']
    conn = get_db_connection()
    cur = conn.cursor()
    is_postgres = os.environ.get('DATABASE_URL') is not None

    cur.execute("SELECT user_id FROM url_mappings WHERE short_code = %s" if is_postgres else "SELECT user_id FROM url_mappings WHERE short_code = ?", (short_code,))
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        return render_error_page(key='link_not_found', status_code=404)
    owner_id = row[0]
    if owner_id != user_id and session.get('username') != 'admin':
        cur.close()
        conn.close()
        return render_error_page(key='not_owner', status_code=403)

    # 延长30天
    if is_postgres:
        cur.execute("UPDATE url_mappings SET expires_at = COALESCE(expires_at, NOW()) + INTERVAL '30 days' WHERE short_code = %s", (short_code,))
    else:
        cur.execute("UPDATE url_mappings SET expires_at = datetime(COALESCE(expires_at, CURRENT_TIMESTAMP), '+30 days') WHERE short_code = ?", (short_code,))
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('dashboard'))

# ------------------ 编辑链接 ------------------
@app.route('/edit/<short_code>', methods=['POST'])
@login_required
def edit_link(short_code):
    user_id = session['user_id']
    new_long_url = request.form.get('new_long_url', '').strip()
    if not new_long_url:
        return render_error_page(key='url_required')
    if not new_long_url.startswith(('http://', 'https://')):
        new_long_url = 'https://' + new_long_url

    conn = get_db_connection()
    cur = conn.cursor()
    is_postgres = os.environ.get('DATABASE_URL') is not None

    cur.execute("SELECT user_id FROM url_mappings WHERE short_code = %s" if is_postgres else "SELECT user_id FROM url_mappings WHERE short_code = ?", (short_code,))
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        return render_error_page(key='link_not_found', status_code=404)
    if row[0] != user_id and session.get('username') != 'admin':
        cur.close(); conn.close()
        return render_error_page(key='not_owner', status_code=403)

    if is_postgres:
        cur.execute("UPDATE url_mappings SET long_url = %s, updated_at = NOW() WHERE short_code = %s", (new_long_url, short_code))
    else:
        cur.execute("UPDATE url_mappings SET long_url = ?, updated_at = CURRENT_TIMESTAMP WHERE short_code = ?", (new_long_url, short_code))
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('dashboard'))

# ------------------ 更新标签 ------------------
@app.route('/tag/<short_code>', methods=['POST'])
@login_required
def update_tag(short_code):
    user_id = session['user_id']
    tag = request.form.get('tag', '').strip()[:50]

    conn = get_db_connection()
    cur = conn.cursor()
    is_postgres = os.environ.get('DATABASE_URL') is not None

    cur.execute("SELECT user_id FROM url_mappings WHERE short_code = %s" if is_postgres else "SELECT user_id FROM url_mappings WHERE short_code = ?", (short_code,))
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        return render_error_page(key='link_not_found', status_code=404)
    if row[0] != user_id and session.get('username') != 'admin':
        cur.close(); conn.close()
        return render_error_page(key='not_owner', status_code=403)

    if is_postgres:
        cur.execute("UPDATE url_mappings SET tag = NULLIF(%s, '') WHERE short_code = %s", (tag, short_code))
    else:
        cur.execute("UPDATE url_mappings SET tag = NULLIF(?, '') WHERE short_code = ?", (tag, short_code))
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('dashboard'))

# ------------------ 查看密码（仪表盘用） ------------------
@app.route('/password/<short_code>')
@login_required
def view_password(short_code):
    user_id = session['user_id']
    conn = get_db_connection()
    cur = conn.cursor()
    is_postgres = os.environ.get('DATABASE_URL') is not None

    cur.execute("SELECT user_id, password_hash FROM url_mappings WHERE short_code = %s" if is_postgres else "SELECT user_id, password_hash FROM url_mappings WHERE short_code = ?", (short_code,))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row or row[0] != user_id:
        abort(403)

    pwd_hash = row[1]
    if not pwd_hash:
        return {'password': None}

    try:
        password = base64.b64decode(pwd_hash).decode()
        return {'password': password}
    except Exception:
        return {'password': None}

# ------------------ 管理面板 ------------------
@app.route('/admin')
@login_required
def admin_dashboard():
    if session.get('username') != 'admin':
        abort(403)
    conn = get_db_connection()
    cur = conn.cursor()
    is_postgres = os.environ.get('DATABASE_URL') is not None

    cur.execute("SELECT COUNT(*) FROM url_mappings")
    total_urls = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM url_mappings WHERE is_custom = true")
    custom_urls = cur.fetchone()[0]
    cur.execute("SELECT COALESCE(SUM(click_count), 0) FROM url_mappings")
    total_clicks = cur.fetchone()[0]

    cur.execute("""
        SELECT id, short_code, long_url, is_custom, created_at, click_count, expires_at
        FROM url_mappings
        ORDER BY created_at DESC
        LIMIT 20
    """)
    recent_urls = cur.fetchall()

    cur.execute("SELECT id, username, email, created_at FROM users ORDER BY id")
    users = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('admin_dashboard.html',
                         total_urls=total_urls,
                         custom_urls=custom_urls,
                         total_clicks=total_clicks,
                         recent_urls=recent_urls,
                         users=users,
                         username=session['username'])

# ------------------ 管理员删除用户 ------------------
@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if session.get('username') != 'admin':
        abort(403)
    if user_id == session['user_id']:
        return render_error_page(key='cannot_delete_self', status_code=400)
    conn = get_db_connection()
    cur = conn.cursor()
    is_postgres = os.environ.get('DATABASE_URL') is not None
    cur.execute("DELETE FROM users WHERE id = %s" if is_postgres else "DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('admin_dashboard'))

# ------------------ 管理员删除链接 ------------------
@app.route('/admin/link/<int:link_id>/delete', methods=['POST'])
@login_required
def admin_delete_link(link_id):
    if session.get('username') != 'admin':
        abort(403)
    conn = get_db_connection()
    cur = conn.cursor()
    is_postgres = os.environ.get('DATABASE_URL') is not None

    # 先获取 short_code 以便删除点击记录
    cur.execute("SELECT short_code FROM url_mappings WHERE id = %s" if is_postgres else "SELECT short_code FROM url_mappings WHERE id = ?", (link_id,))
    row = cur.fetchone()
    if row:
        short_code = row[0]
        cur.execute("DELETE FROM clicks WHERE short_code = %s" if is_postgres else "DELETE FROM clicks WHERE short_code = ?", (short_code,))

    cur.execute("DELETE FROM url_mappings WHERE id = %s" if is_postgres else "DELETE FROM url_mappings WHERE id = ?", (link_id,))
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('admin_dashboard'))

# ------------------ 点击分析公共函数 ------------------
def get_click_analytics(short_code, user_id, username=None):
    """获取短链接的完整点击分析数据，供 stats 和 report 路由共用"""
    conn = get_db_connection()
    cur = conn.cursor()
    is_postgres = os.environ.get('DATABASE_URL') is not None

    # 查询短链接信息，验证权限
    cur.execute("SELECT long_url, user_id FROM url_mappings WHERE short_code = %s" if is_postgres else "SELECT long_url, user_id FROM url_mappings WHERE short_code = ?", (short_code,))
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        return None

    long_url, owner_id = row
    if owner_id != user_id and username != 'admin':
        cur.close()
        conn.close()
        return {'forbidden': True}

    # 查询点击记录（含地理位置）
    cur.execute("SELECT ip_address, user_agent, accessed_at, referer, country, region, city FROM clicks WHERE short_code = %s ORDER BY accessed_at DESC" if is_postgres else "SELECT ip_address, user_agent, accessed_at, referer, country, region, city FROM clicks WHERE short_code = ? ORDER BY accessed_at DESC", (short_code,))
    clicks = cur.fetchall()
    cur.close()
    conn.close()

    # 转换为字典列表
    clicks_list = []
    unique_ips_set = set()
    for c in clicks:
        accessed = c[2]
        if isinstance(accessed, str):
            try:
                accessed = datetime.strptime(accessed, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                try:
                    accessed = datetime.fromisoformat(accessed)
                except ValueError:
                    accessed = None
        ip = c[0]
        if ip:
            unique_ips_set.add(ip)
        clicks_list.append({
            'ip': ip,
            'user_agent': c[1],
            'accessed_at': accessed,
            'referer': c[3],
            'country': c[4] if len(c) > 4 else '',
            'region': c[5] if len(c) > 5 else '',
            'city': c[6] if len(c) > 6 else ''
        })

    total_clicks = len(clicks_list)
    unique_ips = len(unique_ips_set)
    now = datetime.now()

    # 首次/最近点击时间
    valid_times = [c['accessed_at'] for c in clicks_list if c['accessed_at']]
    first_click_at = min(valid_times) if valid_times else None
    last_click_at = max(valid_times) if valid_times else None

    # 今日点击数
    today_cutoff = now - timedelta(hours=24)
    today_clicks = sum(1 for c in clicks_list if c['accessed_at'] and c['accessed_at'] >= today_cutoff)

    # 日点击趋势
    daily_trend = {}
    for c in clicks_list:
        if c['accessed_at']:
            date_key = c['accessed_at'].strftime('%Y-%m-%d')
            daily_trend[date_key] = daily_trend.get(date_key, 0) + 1
    trend_data = []
    for i in range(29, -1, -1):
        d = (now - timedelta(days=i)).strftime('%Y-%m-%d')
        trend_data.append({'date': d, 'count': daily_trend.get(d, 0)})

    # 来源域名分布
    referer_domains = {}
    for c in clicks_list:
        ref = c['referer']
        if not ref:
            domain = 'direct'
        else:
            try:
                domain = ref.split('/')[2] if '://' in ref else ref.split('/')[0]
            except Exception:
                domain = 'other'
        referer_domains[domain] = referer_domains.get(domain, 0) + 1
    referer_stats = sorted(
        [{'domain': k, 'count': v} for k, v in referer_domains.items()],
        key=lambda x: x['count'], reverse=True
    )[:10]

    # 浏览器 / OS
    browser_raw, os_raw = {}, {}
    for c in clicks_list:
        browser, os_name = parse_user_agent(c['user_agent'])
        browser_raw[browser] = browser_raw.get(browser, 0) + 1
        os_raw[os_name] = os_raw.get(os_name, 0) + 1
    browser_stats = sorted([{'name': k, 'count': v} for k, v in browser_raw.items()], key=lambda x: x['count'], reverse=True)
    os_stats = sorted([{'name': k, 'count': v} for k, v in os_raw.items()], key=lambda x: x['count'], reverse=True)

    # 国家分布
    country_raw = {}
    for c in clicks_list:
        cn = c['country'] if c['country'] else 'Unknown'
        country_raw[cn] = country_raw.get(cn, 0) + 1
    country_stats = sorted([{'name': k, 'count': v} for k, v in country_raw.items()], key=lambda x: x['count'], reverse=True)[:10]

    return {
        'long_url': long_url,
        'clicks_list': clicks_list,
        'total_clicks': total_clicks,
        'unique_ips': unique_ips,
        'first_click_at': first_click_at,
        'last_click_at': last_click_at,
        'today_clicks': today_clicks,
        'trend_data': trend_data,
        'referer_stats': referer_stats,
        'browser_stats': browser_stats,
        'os_stats': os_stats,
        'country_stats': country_stats
    }

# ------------------ User-Agent 解析 ------------------
def parse_user_agent(ua_string):
    """从 User-Agent 字符串中解析浏览器和操作系统名称"""
    ua = (ua_string or '').lower()
    browser = 'Other'
    os_name = 'Other'

    # 浏览器检测（注意顺序很重要）
    if 'edg/' in ua:
        browser = 'Edge'
    elif 'opr/' in ua or 'opera' in ua:
        browser = 'Opera'
    elif 'chrome/' in ua and 'chromium' not in ua:
        browser = 'Chrome'
    elif 'firefox/' in ua:
        browser = 'Firefox'
    elif 'safari/' in ua and 'chrome/' not in ua:
        browser = 'Safari'
    elif 'msie ' in ua or 'trident/' in ua:
        browser = 'IE'

    # 操作系统检测
    if 'windows nt 10' in ua or 'windows nt 11' in ua:
        os_name = 'Windows 10/11'
    elif 'windows nt 6.3' in ua:
        os_name = 'Windows 8.1'
    elif 'windows nt 6.1' in ua:
        os_name = 'Windows 7'
    elif 'windows' in ua:
        os_name = 'Windows'
    elif 'mac os x' in ua or 'macintosh' in ua:
        os_name = 'macOS'
    elif 'android' in ua:
        os_name = 'Android'
    elif 'iphone' in ua or 'ipad' in ua or 'ipod' in ua:
        os_name = 'iOS'
    elif 'linux' in ua:
        os_name = 'Linux'

    return browser, os_name

# ------------------ 链接统计 ------------------
@app.route('/stats/<short_code>')
@login_required
def link_stats(short_code):
    user_id = session['user_id']
    analytics = get_click_analytics(short_code, user_id, session.get('username'))
    if not analytics:
        return render_error_page(key='link_not_found', status_code=404)
    if analytics.get('forbidden'):
        return render_error_page(key='not_owner', status_code=403)

    return render_template('link_stats.html',
                         short_code=short_code,
                         long_url=analytics['long_url'],
                         clicks=analytics['clicks_list'],
                         total_clicks=analytics['total_clicks'],
                         today_clicks=analytics['today_clicks'],
                         trend_data=analytics['trend_data'],
                         referer_stats=analytics['referer_stats'],
                         browser_stats=analytics['browser_stats'],
                         os_stats=analytics['os_stats'],
                         country_stats=analytics['country_stats'])

# ------------------ 点击分析报告 ------------------
@app.route('/report/<short_code>')
@login_required
def click_report(short_code):
    user_id = session['user_id']
    analytics = get_click_analytics(short_code, user_id, session.get('username'))
    if not analytics:
        return render_error_page(key='link_not_found', status_code=404)
    if analytics.get('forbidden'):
        return render_error_page(key='not_owner', status_code=403)

    return render_template('report.html',
                         short_code=short_code,
                         long_url=analytics['long_url'],
                         clicks=analytics['clicks_list'],
                         total_clicks=analytics['total_clicks'],
                         today_clicks=analytics['today_clicks'],
                         unique_ips=analytics['unique_ips'],
                         first_click_at=analytics['first_click_at'],
                         last_click_at=analytics['last_click_at'],
                         trend_data=analytics['trend_data'],
                         referer_stats=analytics['referer_stats'],
                         browser_stats=analytics['browser_stats'],
                         os_stats=analytics['os_stats'],
                         country_stats=analytics['country_stats'])

# ------------------ 错误页面 (三语) ------------------
def render_error_page(message=None, key=None, status_code=400, **kwargs):
    """
    渲染三语错误页面。
    - key: 翻译键，如 'url_required'
    - message: 原始英文消息（当 key 未提供时使用）
    优先使用 key 进行翻译。
    """
    if key:
        msg = _(key, **kwargs)
    elif message:
        msg = message
    else:
        msg = _('url_not_found')
    return render_template('error.html', message=msg, status_code=status_code), status_code

# ------------------ 成功页面 (三语) ------------------
def render_success_page(long_url, short_url, short_code, is_custom, expires_at):
    qrcode_url = url_for('static', filename=f'qrcodes/{short_code}.png')
    qrcode_exists = os.path.exists(os.path.join(app.static_folder, 'qrcodes', f'{short_code}.png'))

    if expires_at:
        expiry_text = expires_at.strftime("%Y-%m-%d %H:%M:%S")
    else:
        expiry_text = _('permanent')

    return render_template('success.html',
                         long_url=long_url,
                         short_url=short_url,
                         short_code=short_code,
                         is_custom=is_custom,
                         expiry_text=expiry_text,
                         qrcode_url=qrcode_url,
                         qrcode_exists=qrcode_exists)

print("🚀 Initializing the database...")
init_db()
print("✅ Database initialization completed.")

# 创建二维码存储目录（如果不存在）
qrcode_dir = os.path.join(app.static_folder, 'qrcodes')
os.makedirs(qrcode_dir, exist_ok=True)

# ------------------ 启动 ------------------
if __name__ == '__main__':
    # 生产环境安全检查
    if app.secret_key == 'dev-secret-key-change-in-production':
        logger.warning("=" * 60)
        logger.warning("⚠️  SECURITY WARNING: Using default SECRET_KEY!")
        logger.warning("   Set the SECRET_KEY environment variable in production.")
        logger.warning("   Example: export SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')")
        logger.warning("=" * 60)

    if not os.environ.get('SMTP_HOST'):
        logger.info("ℹ️  SMTP not configured. Password reset will use demo mode (show link on page).")
        logger.info("   Set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS env vars to enable email sending.")

    init_db()
    print("=" * 60)
    print("🚀 URL Shortener started successfully!")
    print("=" * 60)
    print(f"📍 Home URL: http://localhost:{port}")
    print(f"🔧 Admin Panel: http://localhost:{port}/admin (Username: admin)")
    print("=" * 60)
    app.run(host='0.0.0.0', port=port, debug=False)

    #pip install -r requirements.txt
    #python app.py