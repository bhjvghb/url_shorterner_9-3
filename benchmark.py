#!/usr/bin/env python3
"""
LinkSnap 核心接口性能压测脚本
使用 Flask test client，消除网络延迟，仅测试服务端处理时间。
"""

import sys
import os
import time
import statistics
import json

sys.path.insert(0, '.')

from app import app, init_db

init_db()

app.config['TESTING'] = True
client = app.test_client()

N = 100

# ====== 1. 准备测试数据 ======
print('=== 准备测试环境 ===')

# 先清理旧测试数据（防止上次残留）
from app import get_db_connection
conn = get_db_connection()
conn.execute("DELETE FROM clicks WHERE short_code IN (SELECT short_code FROM url_mappings WHERE user_id IN (SELECT id FROM users WHERE username='bench_user'))")
conn.execute("DELETE FROM url_mappings WHERE user_id IN (SELECT id FROM users WHERE username='bench_user')")
conn.execute("DELETE FROM users WHERE username='bench_user'")
conn.commit()
conn.close()

# 注册
resp = client.post('/register', data={
    'username': 'bench_user',
    'email': 'bench@test.com',
    'password': '123456',
    'confirm_password': '123456'
}, follow_redirects=False)
print(f'  注册: {resp.status_code}')

# 登录
resp = client.post('/login', data={
    'username': 'bench_user',
    'password': '123456'
}, follow_redirects=False)
print(f'  登录: {resp.status_code}')

# 缩短一条链接
resp = client.post('/shorten', data={
    'long_url': 'https://www.example.com/benchmark-test-url',
    'expiry': 'forever'
}, follow_redirects=True)
print(f'  缩短: {resp.status_code}')
if resp.status_code != 200:
    print(f'  ERROR: {resp.data[:500]}')
    sys.exit(1)

# 从数据库取 short_code
conn = get_db_connection()
row = conn.execute(
    "SELECT short_code FROM url_mappings WHERE long_url LIKE '%benchmark-test%' LIMIT 1"
).fetchone()
conn.close()
if row is None:
    print('  ERROR: 未找到测试短链接')
    sys.exit(1)
short_code = row['short_code']
print(f'  short_code: {short_code}\n')


# ====== 2. 压测 ======
def bench(label, method, path, data=None, content_type=None):
    times = []
    for i in range(N):
        start = time.perf_counter()
        if method == 'GET':
            resp = client.get(path)
        else:
            kwargs = dict(data=data)
            if content_type:
                kwargs['content_type'] = content_type
            resp = client.post(path, **kwargs)
        times.append((time.perf_counter() - start) * 1000)
    times.sort()
    avg = statistics.mean(times)
    p50 = times[N // 2]
    p99 = times[int(N * 0.99)]
    print(f'  {label:42s} avg={avg:6.1f}ms  p50={p50:6.1f}ms  '
          f'p99={p99:7.1f}ms  min={times[0]:5.1f}ms  max={times[-1]:7.1f}ms')
    return avg, p50, p99


# ====== 3. 运行 ======
print(f'=== 每个端点 {N} 次请求（Flask test client，本地 SQLite）===\n')

r1 = bench('GET / (首页)', 'GET', '/')
r2 = bench('POST /shorten', 'POST', '/shorten', data={
    'long_url': f'https://perf-{int(time.time()*1000)}.example.com/xyz',
    'expiry': 'forever'
})
r3 = bench('GET /<short_code> (重定向)', 'GET', f'/{short_code}')
r4 = bench('GET /dashboard', 'GET', '/dashboard')
r5 = bench('GET /stats/<code> (统计)', 'GET', f'/stats/{short_code}')

# 批量缩短（每批 5 条，JSON 格式）
def bench_batch():
    times = []
    for i in range(N):
        items = [{'url': f'https://example.com/bt-{i}-{j}-{int(time.time()*1000)}', 'custom_code': '', 'password': ''}
                 for j in range(5)]
        start = time.perf_counter()
        resp = client.post('/batch_shorten',
                           data=json.dumps({'items': items, 'expiry': 'forever'}),
                           content_type='application/json')
        times.append((time.perf_counter() - start) * 1000)
    times.sort()
    avg = statistics.mean(times)
    p50 = times[N // 2]
    p99 = times[int(N * 0.99)]
    print(f'  {"POST /batch_shorten (5条)":42s} avg={avg:6.1f}ms  p50={p50:6.1f}ms  '
          f'p99={p99:7.1f}ms  min={times[0]:5.1f}ms  max={times[-1]:7.1f}ms')
    return avg, p50, p99

r6 = bench_batch()

print(f'\n{"="*80}')
print(f'{"端点":42s}  {"平均(ms)":>8s}  {"P50(ms)":>8s}  {"P99(ms)":>8s}')
print(f'{"-"*80}')
data = [
    ('GET / (首页)', r1),
    ('POST /shorten (URL缩短+QR)', r2),
    ('GET /<short_code> (重定向+记录)', r3),
    ('GET /dashboard (分页查询)', r4),
    ('GET /stats/<code> (分析+图表)', r5),
    ('POST /batch_shorten (5条)', r6),
]
for label, (avg, p50, p99) in data:
    print(f'  {label:42s}  {avg:6.1f}     {p50:6.1f}     {p99:6.1f}')
