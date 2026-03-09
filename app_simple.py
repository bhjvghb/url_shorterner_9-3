from flask import Flask
import os

app = Flask(__name__)

@app.route('/')
def hello():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>简单测试</title>
        <style>
            body { 
                font-family: Arial, sans-serif; 
                padding: 40px; 
                background: #f0f0f0;
            }
            .container {
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1 style="color: green;">✅ 测试成功！</h1>
            <p>如果能看到这个页面，说明Flask工作正常。</p>
            <p>问题可能出在模板文件上。</p>
            <p><strong>当前时间：</strong> <span id="time"></span></p>
        </div>
        <script>
            document.getElementById('time').textContent = new Date().toLocaleString();
        </script>
    </body>
    </html>
    """

if __name__ == '__main__':
    print("🚀 启动简单测试服务器...")
    print("📍 请访问: http://127.0.0.1:5000")
    app.run(debug=True, port=5000)