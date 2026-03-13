from flask import Flask, render_template, request, redirect, url_for, session, abort
import sqlite3
import string
import random
import os
import re
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from functools import wraps

app = Flask(__name__)
# 设置一个安全的 secret key（生产环境应从环境变量读取）
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# 获取环境变量中的端口，Render会提供这个
port = int(os.environ.get("PORT", 5000))

# 保留字列表，防止与系统路由冲突
RESERVED_WORDS = [
    'admin', 'api', 'login', 'register', 'dashboard', 'analytics',
    'shorten', 'r', 'static', 'user', 'users', 'profile', 'settings',
    'help', 'about', 'contact', 'privacy', 'terms', 'faq'
]

# ------------------ 数据库初始化（增加用户表）------------------
def init_db():
    conn = sqlite3.connect('urls.db')
    c = conn.cursor()
    # 原有的短链接表
    c.execute('''
        CREATE TABLE IF NOT EXISTS url_mappings
        (id INTEGER PRIMARY KEY AUTOINCREMENT,
         long_url TEXT NOT NULL,
         short_code TEXT NOT NULL UNIQUE,
         is_custom BOOLEAN DEFAULT 0,
         created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
         click_count INTEGER DEFAULT 0)
    ''')
    # 新增用户表
    c.execute('''
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
    # 为短链接表添加 user_id 列（可选，用于关联用户）
    c.execute("PRAGMA table_info(url_mappings)")
    columns = [col[1] for col in c.fetchall()]
    if 'user_id' not in columns:
        c.execute("ALTER TABLE url_mappings ADD COLUMN user_id INTEGER REFERENCES users(id)")
    conn.commit()
    conn.close()
    print("✅ 数据库初始化完成（包含用户表）")
init_db()
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

# ------------------ 原有的短码生成与验证函数（保持不变）------------------
def generate_short_code(length=6):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def validate_custom_code(code):
    # 长度检查
    if len(code) < 3 or len(code) > 20:
        return False, "长度必须在3-20个字符之间"
    # 格式检查：只允许字母、数字、下划线、连字符
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
    # 如果希望强制登录，可取消下面两行的注释
    if 'user_id' not in session:
         return redirect(url_for('login'))

    conn = sqlite3.connect('urls.db')
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM url_mappings")
    total_urls = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM url_mappings WHERE is_custom = 1")
    custom_urls = c.fetchone()[0]
    conn.close()
    return render_template('index.html',
                         total_urls=total_urls,
                         custom_urls=custom_urls,
                         host_url=request.host_url,
                         session=session)  # 将 session 传给模板，用于显示登录状态

# ------------------ 缩短URL（修改：关联当前用户）------------------
@app.route('/shorten', methods=['POST'])
@login_required
def shorten_url():
    long_url = request.form.get('long_url', '').strip()
    custom_code = request.form.get('custom_code', '').strip()
    if not long_url:
        return render_error_page("请输入要缩短的网址")
    if not long_url.startswith(('http://', 'https://')):
        long_url = 'https://' + long_url

    conn = sqlite3.connect('urls.db')
    c = conn.cursor()

    if custom_code:
        is_valid, error_msg = validate_custom_code(custom_code)
        if not is_valid:
            conn.close()
            return render_error_page(f"自定义短码错误: {error_msg}")
        c.execute("SELECT * FROM url_mappings WHERE short_code = ?", (custom_code,))
        if c.fetchone():
            conn.close()
            return render_error_page(f"短码 '{custom_code}' 已被使用，请换一个")
        short_code = custom_code
        is_custom = 1
    else:
        attempts = 0
        while attempts < 10:
            short_code = generate_short_code(6)
            c.execute("SELECT * FROM url_mappings WHERE short_code = ?", (short_code,))
            if not c.fetchone() and short_code.lower() not in RESERVED_WORDS:
                break
            attempts += 1
        else:
            conn.close()
            return render_error_page("生成短码失败，请重试")
        is_custom = 0

    # 获取当前登录用户ID（如果有）
    user_id = session.get('user_id', None)

    try:
        c.execute("""
            INSERT INTO url_mappings (long_url, short_code, is_custom, click_count, user_id)
            VALUES (?, ?, ?, 0, ?)
        """, (long_url, short_code, is_custom, user_id))
        conn.commit()
        url_id = c.lastrowid
    except sqlite3.IntegrityError as e:
        conn.close()
        return render_error_page(f"数据库错误: {str(e)}")

    conn.close()
    short_url = f"{request.host_url}{short_code}"
    return render_success_page(long_url, short_url, short_code, is_custom)

# ------------------ 重定向到原网址（保持不变）------------------
@app.route('/<short_code>')
def redirect_to_long_url(short_code):
    conn = sqlite3.connect('urls.db')
    c = conn.cursor()
    c.execute("SELECT id, long_url FROM url_mappings WHERE short_code = ?", (short_code,))
    result = c.fetchone()
    if not result:
        conn.close()
        return render_error_page("短网址不存在或已过期", 404)
    url_id, long_url = result
    c.execute("UPDATE url_mappings SET click_count = click_count + 1 WHERE id = ?", (url_id,))
    conn.commit()
    # 简单日志
    try:
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', 'Unknown')
        print(f"📊 访问记录: {short_code} | IP: {ip_address} | UA: {user_agent[:50]}...")
    except:
        pass
    conn.close()
    return redirect(long_url)

# ------------------ 新增：用户注册 ------------------
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

        conn = sqlite3.connect('urls.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                      (username, email, hash_password(password)))
            conn.commit()
        except sqlite3.IntegrityError as e:
            conn.close()
            if "username" in str(e):
                return render_error_page("用户名已存在")
            elif "email" in str(e):
                return render_error_page("邮箱已被注册")
            else:
                return render_error_page("注册失败，请稍后重试")
        conn.close()
        return redirect(url_for('login'))
    return render_template('register.html')

# ------------------ 新增：用户登录 ------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form['username'].strip()
        password = request.form['password']

        conn = sqlite3.connect('urls.db')
        c = conn.cursor()
        c.execute("SELECT id, username, password_hash FROM users WHERE username=? OR email=?",
                  (username_or_email, username_or_email))
        user = c.fetchone()
        conn.close()

        if user and verify_password(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            # 登录成功后重定向到首页（或仪表盘）
            return redirect(url_for('index'))
        else:
            return render_error_page("用户名/邮箱或密码错误")
    return render_template('login.html')

# ------------------ 新增：用户登出 ------------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ------------------ 新增：忘记密码 ------------------
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip()
        conn = sqlite3.connect('urls.db')
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE email=?", (email,))
        user = c.fetchone()
        if user:
            token = str(uuid.uuid4())
            expiry = datetime.now() + timedelta(hours=1)
            c.execute("UPDATE users SET reset_token=?, reset_token_expiry=? WHERE id=?",
                      (token, expiry, user[0]))
            conn.commit()
            reset_link = url_for('reset_password', token=token, _external=True)
            # 模拟发送邮件：打印到控制台
            print(f"密码重置链接: {reset_link}")
            # 为了方便测试，我们直接在页面上显示链接（生产环境应改为发送邮件）
            conn.close()
            return f"重置链接已生成：<a href='{reset_link}'>{reset_link}</a>"
        conn.close()
        # 无论邮箱是否存在都返回相同提示，防止用户枚举
        return "如果邮箱存在，重置链接已发送，请查收。"
    return render_template('forgot_password.html')

# ------------------ 新增：重置密码 ------------------
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = sqlite3.connect('urls.db')
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE reset_token=? AND reset_token_expiry > ?",
              (token, datetime.now()))
    user = c.fetchone()
    if not user:
        conn.close()
        return render_error_page("链接无效或已过期", 400)

    if request.method == 'POST':
        new_password = request.form['password']
        confirm = request.form['confirm_password']
        if new_password != confirm:
            return render_error_page("两次密码不一致")
        if len(new_password) < 6:
            return render_error_page("密码至少6位")
        c.execute("UPDATE users SET password_hash=?, reset_token=NULL, reset_token_expiry=NULL WHERE id=?",
                  (hash_password(new_password), user[0]))
        conn.commit()
        conn.close()
        return redirect(url_for('login'))
    conn.close()
    return render_template('reset_password.html', token=token)

# ------------------ 新增：用户仪表盘 ------------------
@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    conn = sqlite3.connect('urls.db')
    c = conn.cursor()
    # 获取当前用户的所有短链接
    c.execute("""
        SELECT short_code, long_url, click_count, created_at, is_custom
        FROM url_mappings
        WHERE user_id=?
        ORDER BY created_at DESC
    """, (user_id,))
    urls = c.fetchall()
    conn.close()
    return render_template('dashboard.html', urls=urls, username=session['username'])

# ------------------ 原有的管理面板（修改：需要登录且为管理员）------------------
@app.route('/admin')
@login_required
def admin_dashboard():
    # 简单判断：只有用户名为 admin 才可访问
    if session.get('username') != 'admin':
        abort(403)  # 返回禁止访问
    conn = sqlite3.connect('urls.db')
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM url_mappings")
    total_urls = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM url_mappings WHERE is_custom = 1")
    custom_urls = c.fetchone()[0]
    c.execute("SELECT SUM(click_count) FROM url_mappings")
    total_clicks = c.fetchone()[0] or 0
    c.execute("""
        SELECT id, short_code, long_url, is_custom, created_at, click_count
        FROM url_mappings
        ORDER BY created_at DESC
        LIMIT 20
    """)
    recent_urls = c.fetchall()
    conn.close()

    # 渲染管理面板模板（此处为简化，仍用字符串拼接，建议改为独立模板）
    table_rows = ""
    for url in recent_urls:
        url_id, short_code, long_url, is_custom, created_at, clicks = url
        table_rows += f"""
        <tr>
            <td>{url_id}</td>
            <td><code>{short_code}</code></td>
            <td>{'✅' if is_custom else '❌'}</td>
            <td><a href="{long_url}" target="_blank">{long_url[:50]}...</a></td>
            <td>{created_at}</td>
            <td>{clicks}</td>
        </tr>
        """
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>管理面板</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {{ background: #f8f9fa; padding: 20px; }}
            .stat-card {{ background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }}
            .table-container {{ background: white; padding: 20px; border-radius: 10px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1 class="mb-4">🔧 管理面板</h1>
            <p>欢迎，{session['username']}！ <a href="/logout">登出</a></p>
            <div class="row mb-4">
                <div class="col-md-3">
                    <div class="stat-card text-center">
                        <h3>{total_urls}</h3>
                        <p class="text-muted">总链接数</p>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card text-center">
                        <h3>{custom_urls}</h3>
                        <p class="text-muted">自定义链接</p>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card text-center">
                        <h3>{total_clicks}</h3>
                        <p class="text-muted">总点击量</p>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card text-center">
                        <h3><a href="/" target="_blank">🔗</a></h3>
                        <p class="text-muted">访问前台</p>
                    </div>
                </div>
            </div>
            <div class="table-container">
                <h4>最近创建的链接</h4>
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>短码</th>
                            <th>自定义</th>
                            <th>原网址</th>
                            <th>创建时间</th>
                            <th>点击量</th>
                        </tr>
                    </thead>
                    <tbody>
                        {table_rows}
                    </tbody>
                </table>
            </div>
            <div class="mt-3">
                <a href="/" class="btn btn-primary">返回首页</a>
                <a href="/admin" class="btn btn-secondary">刷新</a>
            </div>
        </div>
    </body>
    </html>
    '''

# ------------------ 原有的错误页面渲染函数（完整）------------------
def render_error_page(message, status_code=400):
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>发生错误</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {{
                background: linear-gradient(135deg, #ff6b6b 0%, #c44569 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
            }}
            .error-container {{
                background: white;
                border-radius: 15px;
                padding: 40px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                max-width: 600px;
                margin: 0 auto;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="error-container">
                <div class="text-center mb-4">
                    <h1 style="font-size: 80px; color: #ff6b6b;">❌</h1>
                    <h2 class="text-danger">发生错误</h2>
                </div>
                <div class="alert alert-danger">
                    <h4 class="alert-heading">错误信息：</h4>
                    <p class="mb-0">{message}</p>
                </div>
                <div class="text-center mt-4">
                    <a href="/" class="btn btn-primary btn-lg">🏠 返回首页</a>
                    <button class="btn btn-secondary btn-lg" onclick="history.back()">↩️ 返回上页</button>
                </div>
                <div class="mt-4 text-center text-muted small">
                    <p>如果问题持续存在，请联系系统管理员</p>
                    <p>错误代码: {status_code}</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    ''', status_code

# ------------------ 原有的成功页面渲染函数（完整）------------------
def render_success_page(long_url, short_url, short_code, is_custom):
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>缩短成功</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
            }}
            .success-container {{
                background: white;
                border-radius: 15px;
                padding: 40px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                max-width: 700px;
                margin: 0 auto;
            }}
            .url-box {{
                background: #f8f9fa;
                border: 2px dashed #dee2e6;
                border-radius: 10px;
                padding: 15px;
                margin: 15px 0;
                word-break: break-all;
            }}
            .custom-badge {{
                background: linear-gradient(135deg, #ff6b6b, #ee5a24);
                color: white;
                padding: 5px 15px;
                border-radius: 20px;
                font-size: 0.9em;
                font-weight: bold;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="success-container">
                <div class="text-center mb-4">
                    <h1 style="font-size: 80px; color: #28a745;">✅</h1>
                    <h2 class="text-success">
                        缩短成功！
                        {f'<span class="custom-badge ms-2">自定义短码</span>' if is_custom else ''}
                    </h2>
                </div>
                
                <div class="mb-4">
                    <h5>📎 原始网址：</h5>
                    <div class="url-box">
                        <a href="{long_url}" target="_blank">{long_url}</a>
                    </div>
                    
                    <h5>🔗 短网址：</h5>
                    <div class="url-box">
                        <a href="{short_url}" id="short-url" target="_blank" style="font-size: 1.2em; font-weight: bold;">
                            {short_url}
                        </a>
                    </div>
                    
                    {f'<div class="alert alert-info mt-3"><strong>🎉 好消息！</strong> 你使用了自定义短码 <code>{short_code}</code>，这个链接更容易记忆和分享！</div>' if is_custom else ''}
                </div>
                
                <div class="text-center mt-4">
                    <button class="btn btn-success btn-lg px-5" onclick="copyToClipboard()">
                        📋 复制短网址
                    </button>
                    <a href="{short_url}" target="_blank" class="btn btn-primary btn-lg px-5">
                        🔗 测试访问
                    </a>
                    <a href="/" class="btn btn-outline-primary btn-lg px-5">
                        🏠 返回首页
                    </a>
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
                    <p class="mb-0">• 创建时间：{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                </div>
            </div>
        </div>
        
        <script>
            function copyToClipboard() {{
                navigator.clipboard.writeText("{short_url}");
                alert('✅ 已复制到剪贴板！');
            }}
            
            function shareOnTwitter() {{
                const text = `我用自制的URL缩短器创建了一个短链接：{short_url}`;
                window.open(`https://twitter.com/intent/tweet?text=${{encodeURIComponent(text)}}`, '_blank');
            }}
            
            function shareOnWhatsApp() {{
                const text = `分享一个短链接：{short_url}`;
                window.open(`https://wa.me/?text=${{encodeURIComponent(text)}}`, '_blank');
            }}
            
            function shareOnEmail() {{
                const subject = "分享短链接";
                const body = `这是我创建的短链接：{short_url}`;
                window.location.href = `mailto:?subject=${{encodeURIComponent(subject)}}&body=${{encodeURIComponent(body)}}`;
            }}
        </script>
    </body>
    </html>
    '''

# ------------------ 应用启动 ------------------
if __name__ == '__main__':
    init_db()
    print("=" * 60)
    print("🚀 URL缩短器启动成功！")
    print("=" * 60)
    print(f"📍 首页地址: http://localhost:{port}")
    print(f"🔧 管理面板: http://localhost:{port}/admin (需要用户名admin)")
    print("=" * 60)

    app.run(host='0.0.0.0', port=port, debug=False)
