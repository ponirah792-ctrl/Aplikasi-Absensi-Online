# app.py
# Aplikasi Absensi Online (single-file Flask)
# Fitur: register/login (JWT), generate QR (admin), scan attendance (upload photo), list & export xlsx
# Dependencies: flask flask_cors pyjwt qrcode pillow openpyxl werkzeug

import os
import sqlite3
import io
import time
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, send_file, g
from flask_cors import CORS
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import qrcode
from openpyxl import Workbook

# ---------------------------
# Configuration
# ---------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'attendance.db')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

JWT_SECRET = os.environ.get('ATT_JWT_SECRET', 'ganti_dengan_rahasia')  # ganti di env saat deploy
JWT_ALGO = 'HS256'
TOKEN_EXPIRE_HOURS = 8

ALLOWED_EXT = {'png', 'jpg', 'jpeg'}

# ---------------------------
# Flask init
# ---------------------------
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
CORS(app)

# ---------------------------
# Database helpers
# ---------------------------
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def exec_db(query, args=()):
    cur = get_db().execute(query, args)
    get_db().commit()
    cur.close()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Create tables if not exist"""
    db = sqlite3.connect(DB_PATH)
    c = db.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS attendance (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            status TEXT,
            timestamp INTEGER,
            lat REAL,
            lng REAL,
            photo TEXT,
            source TEXT
        )
    ''')
    db.commit()
    db.close()

# call once on start
init_db()

# ---------------------------
# Auth helpers
# ---------------------------
def create_token(payload, hours=TOKEN_EXPIRE_HOURS):
    exp = datetime.utcnow() + timedelta(hours=hours)
    payload2 = payload.copy()
    payload2.update({'exp': exp})
    token = jwt.encode(payload2, JWT_SECRET, algorithm=JWT_ALGO)
    # PyJWT >=2 returns str; ensure str
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token

def decode_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except Exception:
        return None

def auth_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization', None)
        if not auth:
            return jsonify({'error':'Missing Authorization header'}), 401
        parts = auth.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return jsonify({'error':'Invalid Authorization header'}), 401
        token = parts[1]
        payload = decode_token(token)
        if not payload:
            return jsonify({'error':'Invalid or expired token'}), 401
        # attach user to request context
        request.user = payload
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not getattr(request, 'user', None):
            return jsonify({'error':'Missing user'}), 401
        if request.user.get('role') != 'admin':
            return jsonify({'error':'Admin only'}), 403
        return f(*args, **kwargs)
    return wrapper

# ---------------------------
# Utilities
# ---------------------------
import uuid
def gen_id():
    return str(uuid.uuid4())

def allowed_file(filename):
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    return ext in ALLOWED_EXT

# ---------------------------
# Routes: Auth
# ---------------------------
@app.route('/api/register', methods=['POST'])
def register():
    """
    JSON: {name, email, password, role (optional: admin/pegawai)}
    """
    data = request.json or {}
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'pegawai')
    if not name or not email or not password:
        return jsonify({'error':'Missing fields'}), 400
    # check existing
    existing = query_db('SELECT * FROM users WHERE email=?', (email,), one=True)
    if existing:
        return jsonify({'error':'Email already used'}), 400
    uid = gen_id()
    hashed = generate_password_hash(password)
    exec_db('INSERT INTO users (id,name,email,password,role) VALUES (?,?,?,?,?)',
            (uid, name, email, hashed, role))
    return jsonify({'ok':True, 'id': uid, 'name': name, 'email': email, 'role': role})

@app.route('/api/login', methods=['POST'])
def login():
    """
    JSON: {email, password}
    Returns JWT token and user info
    """
    data = request.json or {}
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'error':'Missing fields'}), 400
    user = query_db('SELECT * FROM users WHERE email=?', (email,), one=True)
    if not user:
        return jsonify({'error':'Invalid credentials'}), 401
    if not check_password_hash(user['password'], password):
        return jsonify({'error':'Invalid credentials'}), 401
    payload = {'id': user['id'], 'name': user['name'], 'email': user['email'], 'role': user['role']}
    token = create_token(payload)
    return jsonify({'token': token, 'user': payload})

# ---------------------------
# Routes: Admin helpers (generate QR)
# ---------------------------
@app.route('/api/admin/generate_qr/<user_id>', methods=['GET'])
@auth_required
@admin_required
def generate_qr(user_id):
    """
    Generate QR for a user.
    The QR encodes a simple string like "user:<user_id>"
    Admin can download the PNG.
    """
    user = query_db('SELECT id,name,email FROM users WHERE id=?', (user_id,), one=True)
    if not user:
        return jsonify({'error':'User not found'}), 404
    payload = f"user:{user['id']}"
    img = qrcode.make(payload)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    filename = f"qr_{user['id']}.png"
    return send_file(buf, mimetype='image/png', as_attachment=True, download_name=filename)

# ---------------------------
# Routes: Attendance scan & list
# ---------------------------
@app.route('/api/attendance/scan', methods=['POST'])
@auth_required
def attendance_scan():
    """
    Multipart form:
    - status: present/izin/sakit
    - lat (optional)
    - lng (optional)
    - photo (optional file)
    For QR workflow, client should scan QR, obtain user id from QR content, and POST here with that user_id.
    But for security we use the token user as the actor (so token must represent the employee).
    To allow admin scanning on behalf, pass user_id form field (admin only).
    """
    # Determine acting user
    actor = request.user  # from token
    form_user_id = request.form.get('user_id')
    # If actor is admin and form_user_id provided, admin can mark attendance for a user
    if actor.get('role') == 'admin' and form_user_id:
        user_id = form_user_id
    else:
        user_id = actor.get('id')

    status = request.form.get('status', 'present')
    lat = request.form.get('lat')
    lng = request.form.get('lng')
    ts = int(time.time()*1000)
    photo_path = None

    # handle photo upload
    f = request.files.get('photo')
    if f and f.filename != '':
        if not allowed_file(f.filename):
            return jsonify({'error':'File type not allowed'}), 400
        fn = secure_filename(f.filename)
        # prefix with id+timestamp
        final_name = f"{user_id}_{int(time.time())}_{fn}"
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], final_name)
        f.save(save_path)
        photo_path = save_path

    # store record
    aid = gen_id()
    exec_db('INSERT INTO attendance (id,user_id,status,timestamp,lat,lng,photo,source) VALUES (?,?,?,?,?,?,?,?)',
            (aid, user_id, status, ts, float(lat) if lat else None, float(lng) if lng else None, photo_path, 'qr'))
    return jsonify({'ok': True, 'attendance_id': aid})

@app.route('/api/attendance', methods=['GET'])
@auth_required
def attendance_list():
    """
    Admin or user listing.
    Query params:
      - start: timestamp ms
      - end: timestamp ms
      - user_id: optional (admin can filter, normal user only sees own)
    """
    actor = request.user
    start = request.args.get('start')
    end = request.args.get('end')
    q_user_id = request.args.get('user_id')

    sql = 'SELECT a.*, u.name FROM attendance a LEFT JOIN users u ON u.id=a.user_id WHERE 1=1'
    params = []
    if actor.get('role') != 'admin':
        # restrict to self
        sql += ' AND a.user_id=?'
        params.append(actor.get('id'))
    else:
        if q_user_id:
            sql += ' AND a.user_id=?'
            params.append(q_user_id)
    if start:
        sql += ' AND a.timestamp>=?'
        params.append(int(start))
    if end:
        sql += ' AND a.timestamp<=?'
        params.append(int(end))
    sql += ' ORDER BY a.timestamp DESC'
    rows = query_db(sql, tuple(params))
    out = []
    for r in rows:
        out.append({
            'id': r['id'],
            'user_id': r['user_id'],
            'name': r['name'],
            'status': r['status'],
            'timestamp': r['timestamp'],
            'datetime': datetime.utcfromtimestamp(r['timestamp']/1000).isoformat(),
            'lat': r['lat'],
            'lng': r['lng'],
            'photo': os.path.basename(r['photo']) if r['photo'] else None,
            'source': r['source']
        })
    return jsonify(out)

# ---------------------------
# Routes: Export XLSX
# ---------------------------
@app.route('/api/attendance/export', methods=['GET'])
@auth_required
def attendance_export():
    """
    Export attendance (admin only).
    Uses same query params as /attendance
    """
    if request.user.get('role') != 'admin':
        return jsonify({'error':'Admin only'}), 403

    start = request.args.get('start')
    end = request.args.get('end')
    q_user_id = request.args.get('user_id')

    sql = 'SELECT a.*, u.name FROM attendance a LEFT JOIN users u ON u.id=a.user_id WHERE 1=1'
    params = []
    if q_user_id:
        sql += ' AND a.user_id=?'
        params.append(q_user_id)
    if start:
        sql += ' AND a.timestamp>=?'
        params.append(int(start))
    if end:
        sql += ' AND a.timestamp<=?'
        params.append(int(end))
    sql += ' ORDER BY a.timestamp DESC'
    rows = query_db(sql, tuple(params))

    wb = Workbook()
    ws = wb.active
    ws.title = "Attendance"
    headers = ['ID', 'User ID', 'Name', 'Status', 'Datetime (UTC)', 'Lat', 'Lng', 'Photo', 'Source']
    ws.append(headers)
    for r in rows:
        dt = datetime.utcfromtimestamp(r['timestamp']/1000).isoformat() if r['timestamp'] else ''
        ws.append([r['id'], r['user_id'], r['name'], r['status'], dt, r['lat'], r['lng'], os.path.basename(r['photo']) if r['photo'] else '', r['source']])
    # save to bytes
    bio = io.BytesIO()
    wb.save(bio)
    bio.seek(0)
    filename = f"attendance_export_{int(time.time())}.xlsx"
    return send_file(bio, as_attachment=True, download_name=filename, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

# ---------------------------
# Route: Simple user list (admin)
# ---------------------------
@app.route('/api/users', methods=['GET'])
@auth_required
@admin_required
def users_list():
    rows = query_db('SELECT id,name,email,role FROM users ORDER BY name')
    out = [dict(r) for r in rows]
    return jsonify(out)

# ---------------------------
# Route: Upload static file access (photos)
# ---------------------------
@app.route('/uploads/<path:filename>', methods=['GET'])
def uploaded_file(filename):
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(path):
        return jsonify({'error':'Not found'}), 404
    return send_file(path)

# ---------------------------
# CLI helper: create an admin user quickly
# ---------------------------
@app.route('/api/__create_admin', methods=['POST'])
def create_admin_quick():
    """
    For setup only. Create admin:
    JSON: {name, email, password}
    NOTE: remove or protect this endpoint after initial setup.
    """
    data = request.json or {}
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    if not name or not email or not password:
        return jsonify({'error':'Missing fields'}), 400
    existing = query_db('SELECT * FROM users WHERE email=?', (email,), one=True)
    if existing:
        return jsonify({'error':'Email exists'}), 400
    uid = gen_id()
    hashed = generate_password_hash(password)
    exec_db('INSERT INTO users (id,name,email,password,role) VALUES (?,?,?,?,?)', (uid, name, email, hashed, 'admin'))
    return jsonify({'ok':True, 'id': uid})

# ---------------------------
# Main
# ---------------------------
if __name__ == '__main__':
    print("Starting Attendance app on http://127.0.0.1:5000")
    app.run(debug=True)
