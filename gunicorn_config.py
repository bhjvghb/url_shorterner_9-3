# Gunicorn配置文件
workers = 4
worker_class = 'sync'
bind = '0.0.0.0:$PORT'
timeout = 120