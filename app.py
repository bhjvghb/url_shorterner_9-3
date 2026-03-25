from flask import Flask, render_template, request, redirect, url_for, session, abort
# from flask_babel import Babel, gettext as _  # 已删除，未使用
import os
import re
import string
import random
import uuid
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode
from PIL import Image

# 数据库适配优先使用 PostgreSQL（通过环境变量 DATABASE_URL），否则回退到 SQLite
import sqlite3
import psycopg2
import psycopg2.extras

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

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
                expires_at TIMESTAMP
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
                expires_at TIMESTAMP
            )
        ''')

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
        print("✅ 为 url_mappings 添加 is_custom 列")

    if not column_exists('url_mappings', 'click_count'):
        if is_postgres:
            cur.execute("ALTER TABLE url_mappings ADD COLUMN click_count INTEGER DEFAULT 0")
        else:
            cur.execute("ALTER TABLE url_mappings ADD COLUMN click_count INTEGER DEFAULT 0")
        print("✅ 为 url_mappings 添加 click_count 列")

    if not column_exists('url_mappings', 'user_id'):
        if is_postgres:
            cur.execute("ALTER TABLE url_mappings ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE SET NULL")
        else:
            cur.execute("ALTER TABLE url_mappings ADD COLUMN user_id INTEGER REFERENCES users(id)")
        print("✅ 为 url_mappings 添加 user_id 列")

    if not column_exists('url_mappings', 'expires_at'):
        if is_postgres:
            cur.execute("ALTER TABLE url_mappings ADD COLUMN expires_at TIMESTAMP")
        else:
            cur.execute("ALTER TABLE url_mappings ADD COLUMN expires_at TIMESTAMP")
        print("✅ 为 url_mappings 添加 expires_at 列")

    # 为 users 表添加可能缺失的列
    if not column_exists('users', 'reset_token'):
        if is_postgres:
            cur.execute("ALTER TABLE users ADD COLUMN reset_token VARCHAR(36)")
        else:
            cur.execute("ALTER TABLE users ADD COLUMN reset_token TEXT")
        print("✅ 为 users 添加 reset_token 列")

    if not column_exists('users', 'reset_token_expiry'):
        if is_postgres:
            cur.execute("ALTER TABLE users ADD COLUMN reset_token_expiry TIMESTAMP")
        else:
            cur.execute("ALTER TABLE users ADD COLUMN reset_token_expiry TIMESTAMP")
        print("✅ 为 users 添加 reset_token_expiry 列")

    conn.commit()
    cur.close()
    conn.close()
    print("✅ 数据库初始化/升级完成")

# ------------------ 密码辅助函数 ------------------
def hash_password(password):
    return generate_password_hash(password)

def verify_password(password_hash, password):
    return check_password_hash(password_hash, password)

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
        return False, "长度必须在3-20个字符之间"
    if not re.match(r'^[a-zA-Z0-9_-]+$', code):
        return False, "只能包含字母、数字、下划线(_)和连字符(-)"
    if code.startswith('-') or code.endswith('-'):
        return False, "不能以连字符开头或结尾"
    if '--' in code:
        return False, "不能包含连续连字符"
    if code.lower() in RESERVED_WORDS:
        return False, f"'{code}' 是系统保留字"
    return True, "验证通过"

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

    if not long_url:
        return render_error_page("请输入要缩短的URL网址")
    if not long_url.startswith(('http://', 'https://')):
        long_url = 'https://' + long_url

    conn = get_db_connection()
    cur = conn.cursor()
    is_postgres = os.environ.get('DATABASE_URL') is not None

    if custom_code:
        is_valid, error_msg = validate_custom_code(custom_code)
        if not is_valid:
            cur.close()
            conn.close()
            return render_error_page(f"自定义短码错误: {error_msg}")
        cur.execute("SELECT * FROM url_mappings WHERE short_code = %s" if is_postgres else "SELECT * FROM url_mappings WHERE short_code = ?", (custom_code,))
        if cur.fetchone():
            cur.close()
            conn.close()
            return render_error_page(f"短码 '{custom_code}' 已被使用，请换一个")
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
            return render_error_page("生成短码失败，请重试")
        is_custom = False

    user_id = session.get('user_id')

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
                INSERT INTO url_mappings (long_url, short_code, is_custom, click_count, user_id, expires_at)
                VALUES (%s, %s, %s, 0, %s, %s)
            """, (long_url, short_code, is_custom, user_id, expires_at))
        else:
            cur.execute("""
                INSERT INTO url_mappings (long_url, short_code, is_custom, click_count, user_id, expires_at)
                VALUES (?, ?, ?, 0, ?, ?)
            """, (long_url, short_code, 1 if is_custom else 0, user_id, expires_at))
        conn.commit()
    except Exception as e:
        cur.close()
        conn.close()
        return render_error_page(f"数据库错误: {str(e)}")

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
        print(f"⚠️ 二维码生成失败: {e}")
    
    return render_success_page(long_url, short_url, short_code, is_custom, expires_at)

# ------------------ 重定向 ------------------
@app.route('/<short_code>')
def redirect_to_long_url(short_code):
    conn = get_db_connection()
    cur = conn.cursor()
    is_postgres = os.environ.get('DATABASE_URL') is not None

    cur.execute("SELECT id, long_url, expires_at FROM url_mappings WHERE short_code = %s" if is_postgres else "SELECT id, long_url, expires_at FROM url_mappings WHERE short_code = ?", (short_code,))
    result = cur.fetchone()
    if not result:
        cur.close()
        conn.close()
        return render_error_page("短网址不存在或已过期", 404)

    url_id, long_url, expires_at = result
    if expires_at and expires_at < datetime.now():
        cur.close()
        conn.close()
        return render_error_page("该短网址已过期", 410)

    cur.execute("UPDATE url_mappings SET click_count = click_count + 1 WHERE id = %s" if is_postgres else "UPDATE url_mappings SET click_count = click_count + 1 WHERE id = ?", (url_id,))
    conn.commit()

    # 简单日志（可扩展为点击记录表）
    try:
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', 'Unknown')
        print(f"📊 访问记录: {short_code} | IP: {ip_address} | UA: {user_agent[:50]}...")
    except:
        pass

    cur.close()
    conn.close()
    return redirect(long_url)

# ------------------ 注册 ------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        confirm = request.form['confirm_password']

        if not username or not email or not password:
            return render_error_page("所有字段均为必填")
        if password != confirm:
            return render_error_page("两次输入的密码不一致")
        if len(password) < 6:
            return render_error_page("密码至少6位")

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
                    return render_error_page("用户名已存在")
                elif 'email' in str(e).lower():
                    return render_error_page("邮箱已被注册")
            return render_error_page(f"注册失败: {str(e)}")
        finally:
            cur.close()
            conn.close()
        return redirect(url_for('login'))
    return render_template('register.html')

# ------------------ 登录 ------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form['username'].strip()
        password = request.form['password']

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
            return render_error_page("用户名/邮箱或密码错误")
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
        email = request.form['email'].strip()
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
            print(f"密码重置链接: {reset_link}")
            cur.close()
            conn.close()
            return f"重置链接已生成：<a href='{reset_link}'>{reset_link}</a>"
        cur.close()
        conn.close()
        return "如果邮箱存在，重置链接已发送，请查收。"
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
        return render_error_page("链接无效或已过期", 400)

    if request.method == 'POST':
        new_password = request.form['password']
        confirm = request.form['confirm_password']
        if new_password != confirm:
            return render_error_page("两次密码不一致")
        if len(new_password) < 6:
            return render_error_page("密码至少6位")
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

# ------------------ 仪表盘 ------------------
@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    conn = get_db_connection()
    cur = conn.cursor()
    is_postgres = os.environ.get('DATABASE_URL') is not None

    cur.execute("""
        SELECT short_code, long_url, click_count, created_at, is_custom, expires_at
        FROM url_mappings
        WHERE user_id = %s
        ORDER BY created_at DESC
    """ if is_postgres else """
        SELECT short_code, long_url, click_count, created_at, is_custom, expires_at
        FROM url_mappings
        WHERE user_id = ?
        ORDER BY created_at DESC
    """, (user_id,))
    rows = cur.fetchall()
    urls = []
    for row in rows:
        short_code, long_url, click_count, created_at, is_custom, expires_at = row
        is_expired = False
        if expires_at and expires_at < datetime.now():
            is_expired = True
        urls.append({
            'short_code': short_code,
            'long_url': long_url,
            'click_count': click_count,
            'created_at': created_at,
            'is_custom': is_custom,
            'expires_at': expires_at,
            'is_expired': is_expired
        })
    cur.close()
    conn.close()
    return render_template('dashboard.html', urls=urls, username=session['username'])

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
        return render_error_page("链接不存在", 404)
    owner_id = row[0]
    if owner_id != user_id and session.get('username') != 'admin':
        cur.close()
        conn.close()
        return render_error_page("无权删除此链接", 403)

    cur.execute("DELETE FROM url_mappings WHERE short_code = %s" if is_postgres else "DELETE FROM url_mappings WHERE short_code = ?", (short_code,))
    conn.commit()
    cur.close()
    conn.close()
    
    # 可选：删除对应的二维码文件
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
        return render_error_page("链接不存在", 404)
    owner_id = row[0]
    if owner_id != user_id and session.get('username') != 'admin':
        cur.close()
        conn.close()
        return render_error_page("无权操作此链接", 403)

    # 延长30天
    if is_postgres:
        cur.execute("UPDATE url_mappings SET expires_at = COALESCE(expires_at, NOW()) + INTERVAL '30 days' WHERE short_code = %s", (short_code,))
    else:
        cur.execute("UPDATE url_mappings SET expires_at = datetime(COALESCE(expires_at, CURRENT_TIMESTAMP), '+30 days') WHERE short_code = ?", (short_code,))
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('dashboard'))

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
        return render_error_page("不能删除自己", 400)
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
    cur.execute("DELETE FROM url_mappings WHERE id = %s" if is_postgres else "DELETE FROM url_mappings WHERE id = ?", (link_id,))
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('admin_dashboard'))

# ------------------ 错误页面 ------------------
def render_error_page(message, status_code=400):
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>发生错误</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>body {{ background: linear-gradient(135deg, #ff6b6b 0%, #c44569 100%); min-height: 100vh; display: flex; align-items: center; }} .error-container {{ background: white; border-radius: 15px; padding: 40px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); max-width: 600px; margin: 0 auto; }}</style>
    </head>
    <body>
        <div class="container">
            <div class="error-container">
                <div class="text-center mb-4"><h1 style="font-size:80px;color:#ff6b6b;">❌</h1><h2 class="text-danger">发生错误</h2></div>
                <div class="alert alert-danger"><h4 class="alert-heading">错误信息：</h4><p class="mb-0">{message}</p></div>
                <div class="text-center mt-4"><a href="/" class="btn btn-primary btn-lg">🏠 返回首页</a><button class="btn btn-secondary btn-lg" onclick="history.back()">↩️ 返回上页</button></div>
                <div class="mt-4 text-center text-muted small"><p>如果问题持续存在，请联系系统管理员</p><p>错误代码: {status_code}</p></div>
            </div>
        </div>
    </body>
    </html>
    ''', status_code

# ------------------ 成功页面 ------------------
def render_success_page(long_url, short_url, short_code, is_custom, expires_at):
    # 生成二维码图片 URL（如果存在）
    qrcode_url = url_for('static', filename=f'qrcodes/{short_code}.png')
    # 检查二维码文件是否存在（避免显示坏图）
    qrcode_exists = os.path.exists(os.path.join(app.static_folder, 'qrcodes', f'{short_code}.png'))
    
    expiry_text = "永久有效"
    if expires_at:
        expiry_text = expires_at.strftime("%Y-%m-%d %H:%M:%S")
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>缩短成功</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; }}
            .success-container {{ background: white; border-radius: 15px; padding: 40px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); max-width: 700px; margin: 0 auto; }}
            .url-box {{ background: #f8f9fa; border: 2px dashed #dee2e6; border-radius: 10px; padding: 15px; margin: 15px 0; word-break: break-all; }}
            .custom-badge {{ background: linear-gradient(135deg, #ff6b6b, #ee5a24); color: white; padding: 5px 15px; border-radius: 20px; font-size: 0.9em; font-weight: bold; }}
            .qrcode {{ max-width: 200px; margin: 20px auto; border: 1px solid #ddd; border-radius: 10px; padding: 10px; background: white; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="success-container">
                <div class="text-center mb-4">
                    <h1 style="font-size:80px;color:#28a745;">✅</h1>
                    <h2 class="text-success">缩短成功！{f'<span class="custom-badge ms-2">自定义短码</span>' if is_custom else ''}</h2>
                </div>
                <div class="mb-4">
                    <h5>📎 原始网址：</h5>
                    <div class="url-box"><a href="{long_url}" target="_blank">{long_url}</a></div>
                    <h5>🔗 短网址：</h5>
                    <div class="url-box"><a href="{short_url}" id="short-url" target="_blank" style="font-size:1.2em;font-weight:bold;">{short_url}</a></div>
                    {f'<div class="alert alert-info mt-3"><strong>🎉 好消息！</strong> 你使用了自定义短码 <code>{short_code}</code>，这个链接更容易记忆和分享！</div>' if is_custom else ''}
                </div>
                
                <!-- 二维码区域 -->
                <div class="text-center mb-4">
                    <h5>📱 扫描二维码访问</h5>
                    {'<img class="qrcode" src="' + qrcode_url + '" alt="QR Code">' if qrcode_exists else '<p class="text-muted">二维码生成失败</p>'}
                    <div class="mt-2">
                        <button class="btn btn-sm btn-outline-secondary" onclick="downloadQRCode()">💾 下载二维码</button>
                    </div>
                </div>
                
                <div class="text-center mt-4">
                    <button class="btn btn-success btn-lg px-5" onclick="copyToClipboard()">📋 复制短网址</button>
                    <a href="{short_url}" target="_blank" class="btn btn-primary btn-lg px-5">🔗 测试访问</a>
                    <a href="/" class="btn btn-outline-primary btn-lg px-5">🏠 返回首页</a>
                </div>
                <div class="mt-4 text-center">
                    <div class="btn-group" role="group">
                        <button class="btn btn-outline-secondary btn-sm" onclick="shareOnTwitter()">🐦 Twitter</button>
                        <button class="btn btn-outline-secondary btn-sm" onclick="shareOnWhatsApp()">💬 WhatsApp</button>
                        <button class="btn btn-outline-secondary btn-sm" onclick="shareOnEmail()">📧 Email</button>
                    </div>
                </div>
                <div class="mt-4 alert alert-light">
                    <h6>📊 统计信息：</h6>
                    <p class="mb-1">• 短码：<code>{short_code}</code></p>
                    <p class="mb-1">• 类型：{'自定义' if is_custom else '系统生成'}</p>
                    <p class="mb-0">• 有效期：{expiry_text}</p>
                </div>
            </div>
        </div>
        <script>
            function copyToClipboard() {{ navigator.clipboard.writeText("{short_url}"); alert('✅ 已复制到剪贴板！'); }}
            function shareOnTwitter() {{ const text = `我用自制的URL缩短器创建了一个短链接：{short_url}`; window.open(`https://twitter.com/intent/tweet?text=${{encodeURIComponent(text)}}`, '_blank'); }}
            function shareOnWhatsApp() {{ const text = `分享一个短链接：{short_url}`; window.open(`https://wa.me/?text=${{encodeURIComponent(text)}}`, '_blank'); }}
            function shareOnEmail() {{ const subject = "分享短链接"; const body = `这是我创建的短链接：{short_url}`; window.location.href = `mailto:?subject=${{encodeURIComponent(subject)}}&body=${{encodeURIComponent(body)}}`; }}
            function downloadQRCode() {{
                var img = document.querySelector('.qrcode');
                if (img) {{
                    var link = document.createElement('a');
                    link.href = img.src;
                    link.download = 'qrcode_{short_code}.png';
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                }}
            }}
        </script>
    </body>
    </html>
    '''

print("🚀 正在初始化数据库...")
init_db()
print("✅ 数据库初始化调用完成。")

# 创建二维码存储目录（如果不存在）
qrcode_dir = os.path.join(app.static_folder, 'qrcodes')
os.makedirs(qrcode_dir, exist_ok=True)

# ------------------ 启动 ------------------
if __name__ == '__main__':
    init_db()
    print("=" * 60)
    print("🚀 URL缩短器启动成功！")
    print("=" * 60)
    print(f"📍 首页地址: http://localhost:{port}")
    print(f"🔧 管理面板: http://localhost:{port}/admin (需要用户名admin)")
    print("=" * 60)
    app.run(host='0.0.0.0', port=port, debug=False)