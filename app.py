from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send, join_room, emit
from functools import wraps
import sqlite3
import uuid
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # 실제 운영 환경에서는 환경 변수로 관리
DATABASE = 'market.db'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', logger=True, engineio_logger=True)

# 데이터베이스 연결 관리
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 사용자별 방 목록을 저장할 딕셔너리
user_rooms = {}

@socketio.on('identify')
def handle_identity(data):
    user_id = data.get('user_id')
    if user_id:
        user_rooms[user_id] = []
        print(f"[identify] 사용자 {user_id} 식별 완료")

@socketio.on('join')
def handle_join(data):
    user_id = data.get('user_id')
    other_id = data.get('other_id')
    if not user_id or not other_id:
        print("[join] user_id 또는 other_id 누락")
        return

    room = '_'.join(sorted([user_id, other_id]))
    join_room(room)
    print(f"[join] {user_id}가 방 {room}에 참여")

@socketio.on('send_message')
def handle_send_message(data):
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')
    message = data.get('message')

    if not sender_id or not receiver_id or not message:
        print("[send_message] 필수 필드 누락")
        return

    room = '_'.join(sorted([sender_id, receiver_id]))
    db = get_db()
    cursor = db.cursor()
    message_id = str(uuid.uuid4())

    try:
        cursor.execute(
            "INSERT INTO chat (id, sender_id, receiver_id, message) VALUES (?, ?, ?, ?)",
            (message_id, sender_id, receiver_id, message)
        )
        db.commit()
        print(f"[DB 저장] 메시지 저장 성공 - {message_id}")
    except Exception as e:
        print(f"[DB 저장 오류] {e}")
        return

    data['message_id'] = message_id
    data['created_at'] = datetime.now().strftime('%H:%M')
    emit('message', data, room=room)

# 비회원 접근 가능 라우트
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        db = get_db()
        cursor = db.cursor()
        
        # 중복 체크
        cursor.execute("SELECT * FROM user WHERE username = ? OR email = ?", (username, email))
        if cursor.fetchone():
            flash('이미 존재하는 사용자명 또는 이메일입니다.')
            return redirect(url_for('register'))
        
        # 비밀번호 해싱
        hashed_password = generate_password_hash(password)
        
        # 사용자 생성
        user_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO user (id, username, password, email) VALUES (?, ?, ?, ?)",
            (user_id, username, hashed_password, email)
        )
        db.commit()
        
        flash('회원가입이 완료되었습니다. 로그인해주세요.')
        return redirect(url_for('login'))
    
    return render_template('auth/register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    
    return render_template('auth/login.html')

# 로그인 필요 데코레이터
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# 관리자 권한 체크 데코레이터
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        
        if not user or not user['is_admin']:
            flash('관리자 권한이 필요합니다.')
            return redirect(url_for('dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function

# 회원 전용 라우트
@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT p.*, u.username as seller_name 
        FROM product p 
        JOIN user u ON p.seller_id = u.id 
        WHERE p.status = 'active'
        ORDER BY p.created_at DESC
    """)
    products = cursor.fetchall()
    return render_template('dashboard.html', products=products)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    db = get_db()
    cursor = db.cursor()
    
    if request.method == 'POST':
        bio = request.form.get('bio', '')
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))
    
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    return render_template('profile.html', user=user)

@app.route('/product/new', methods=['GET', 'POST'])
@login_required
def new_product():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = int(request.form['price'])
        
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()
        
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    
    return render_template('product/new.html')

@app.route('/product/<product_id>')
@login_required
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT p.*, u.username as seller_name, u.id as seller_id
        FROM product p
        JOIN user u ON p.seller_id = u.id
        WHERE p.id = ?
    """, (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    return render_template('product/view.html', product=product)

@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    if request.method == 'POST':
        target_id = request.form['target_id']
        target_type = request.form['target_type']
        reason = request.form['reason']
        
        db = get_db()
        cursor = db.cursor()
        report_id = str(uuid.uuid4())
        
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, target_type, reason) VALUES (?, ?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, target_type, reason)
        )
        db.commit()
        
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    
    return render_template('report.html')

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '')
    min_price = request.args.get('min_price', '')
    max_price = request.args.get('max_price', '')
    
    db = get_db()
    cursor = db.cursor()
    
    # 기본 쿼리
    sql = """
        SELECT p.*, u.username as seller_name 
        FROM product p 
        JOIN user u ON p.seller_id = u.id 
        WHERE p.status = 'active'
    """
    params = []
    
    # 검색어 조건
    if query:
        sql += " AND (p.title LIKE ? OR p.description LIKE ?)"
        params.extend([f'%{query}%', f'%{query}%'])
    
    # 가격 범위 조건
    if min_price:
        sql += " AND p.price >= ?"
        params.append(int(min_price))
    if max_price:
        sql += " AND p.price <= ?"
        params.append(int(max_price))
    
    sql += " ORDER BY p.created_at DESC"
    
    cursor.execute(sql, params)
    products = cursor.fetchall()
    
    return render_template('search.html', products=products, query=query, min_price=min_price, max_price=max_price)

@app.route('/chat')
@login_required
def chat_list():
    db = get_db()
    cursor = db.cursor()
    
    # 현재 사용자와 대화한 사용자 목록 조회
    cursor.execute("""
        SELECT DISTINCT u.id, u.username, 
            (SELECT message FROM chat 
             WHERE (sender_id = ? AND receiver_id = u.id) 
                OR (sender_id = u.id AND receiver_id = ?)
             ORDER BY created_at DESC LIMIT 1) as last_message,
            (SELECT created_at FROM chat 
             WHERE (sender_id = ? AND receiver_id = u.id) 
                OR (sender_id = u.id AND receiver_id = ?)
             ORDER BY created_at DESC LIMIT 1) as last_message_time
        FROM user u
        JOIN chat c ON (c.sender_id = u.id AND c.receiver_id = ?) 
            OR (c.sender_id = ? AND c.receiver_id = u.id)
        WHERE u.id != ?
        ORDER BY last_message_time DESC
    """, (session['user_id'], session['user_id'], session['user_id'], session['user_id'], 
          session['user_id'], session['user_id'], session['user_id']))
    
    chat_users = cursor.fetchall()
    print(f"채팅 목록 조회: {len(chat_users)}개의 대화 내역이 있습니다.")
    return render_template('chat/list.html', chat_users=chat_users)

@app.route('/chat/<user_id>')
@login_required
def chat_room(user_id):
    db = get_db()
    cursor = db.cursor()
    
    # 상대방 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    other_user = cursor.fetchone()
    
    if not other_user:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('chat_list'))
    
    # 채팅 내역 조회
    cursor.execute("""
        SELECT c.*, 
            CASE 
                WHEN c.sender_id = ? THEN 'sent'
                ELSE 'received'
            END as message_type
        FROM chat c
        WHERE (c.sender_id = ? AND c.receiver_id = ?)
            OR (c.sender_id = ? AND c.receiver_id = ?)
        ORDER BY c.created_at ASC
    """, (session['user_id'], session['user_id'], user_id, user_id, session['user_id']))
    
    messages = cursor.fetchall()
    print(f"채팅방 메시지 조회: {len(messages)}개의 메시지가 있습니다.")
    return render_template('chat/room.html', other_user=other_user, messages=messages)

# 세션 사용자 ID 가져오기
def get_user_id_from_session():
    if 'user_id' in session:
        return session['user_id']
    return None

# WebSocket 이벤트
@socketio.on('connect')
def handle_connect():
    user_id = get_user_id_from_session()
    if user_id:
        print(f"사용자 {user_id}가 WebSocket에 연결되었습니다.")
    else:
        print("인증되지 않은 사용자가 WebSocket에 연결을 시도했습니다.")

@socketio.on('identify')
def handle_identify_event(data):
    user_id = data.get('user_id')
    if not user_id:
        print("사용자 ID가 없습니다.")
        return
    
    print(f"사용자 {user_id}가 식별되었습니다.")
    join_room(user_id)
    print(f"사용자 {user_id}가 방 {user_id}에 참여했습니다.")

@socketio.on('join')
def handle_join_event(data):
    user_id = get_user_id_from_session()
    if not user_id:
        print("세션에 user_id가 없습니다.")
        return
    
    room = data.get('room')
    if not room:
        print("방 정보가 없습니다.")
        return
        
    join_room(room)
    print(f"사용자 {user_id}가 방 {room}에 참여했습니다.")

@socketio.on('send_message')
def handle_send_message_event(data):
    user_id = get_user_id_from_session()
    if not user_id:
        print("세션에 user_id가 없습니다.")
        return
    
    receiver_id = data.get('receiver_id')
    message = data.get('message')
    
    if not receiver_id or not message:
        print("수신자 ID 또는 메시지가 없습니다.")
        return
    
    print(f"메시지 전송: {user_id} -> {receiver_id}: {message}")
    
    db = get_db()
    cursor = db.cursor()
    message_id = str(uuid.uuid4())
    
    try:
        cursor.execute(
            "INSERT INTO chat (id, sender_id, receiver_id, message) VALUES (?, ?, ?, ?)",
            (message_id, user_id, receiver_id, message)
        )
        db.commit()
        print(f"메시지 저장 성공: {message_id}")
    except Exception as e:
        print(f"메시지 저장 실패: {e}")
        return
    
    # 메시지 데이터에 sender_id 추가
    data['message_id'] = message_id
    data['sender_id'] = user_id
    data['created_at'] = datetime.now().strftime('%H:%M')
    
    # 특정 사용자에게만 메시지 전송
    emit('message', data, room=receiver_id)
    # 발신자에게도 메시지 전송
    emit('message', data, room=user_id)
    print(f"메시지 전송 완료: {receiver_id}, {user_id}")

# 관리자 대시보드
@app.route('/admin')
@admin_required
def admin_dashboard():
    db = get_db()
    cursor = db.cursor()
    
    # 통계 정보
    cursor.execute("SELECT COUNT(*) as count FROM user")
    total_users = cursor.fetchone()['count']
    
    cursor.execute("SELECT COUNT(*) as count FROM product")
    total_products = cursor.fetchone()['count']
    
    cursor.execute("SELECT COUNT(*) as count FROM report WHERE status = 'pending'")
    pending_reports = cursor.fetchone()['count']
    
    # 최근 신고 목록
    cursor.execute("""
        SELECT r.*, u.username as reporter_name
        FROM report r
        JOIN user u ON r.reporter_id = u.id
        ORDER BY r.created_at DESC
        LIMIT 5
    """)
    recent_reports = cursor.fetchall()
    
    return render_template('admin/dashboard.html',
                         total_users=total_users,
                         total_products=total_products,
                         pending_reports=pending_reports,
                         recent_reports=recent_reports)

# 사용자 관리
@app.route('/admin/users')
@admin_required
def admin_users():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user ORDER BY created_at DESC")
    users = cursor.fetchall()
    return render_template('admin/users.html', users=users)

# 상품 관리
@app.route('/admin/products')
@admin_required
def admin_products():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT p.*, u.username as seller_name
        FROM product p
        JOIN user u ON p.seller_id = u.id
        ORDER BY p.created_at DESC
    """)
    products = cursor.fetchall()
    return render_template('admin/products.html', products=products)

# 신고 관리
@app.route('/admin/reports')
@admin_required
def admin_reports():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT r.*, u.username as reporter_name
        FROM report r
        JOIN user u ON r.reporter_id = u.id
        ORDER BY r.created_at DESC
    """)
    reports = cursor.fetchall()
    return render_template('admin/reports.html', reports=reports)

# 신고 처리
@app.route('/admin/report/<report_id>/process', methods=['POST'])
@admin_required
def process_report(report_id):
    action = request.form.get('action')
    db = get_db()
    cursor = db.cursor()
    
    if action == 'resolve':
        cursor.execute("UPDATE report SET status = 'resolved' WHERE id = ?", (report_id,))
    elif action == 'block':
        cursor.execute("""
            UPDATE report SET status = 'resolved' WHERE id = ?;
            UPDATE user SET is_blocked = 1 WHERE id = (SELECT target_id FROM report WHERE id = ?);
        """, (report_id, report_id))
    
    db.commit()
    flash('신고가 처리되었습니다.')
    return redirect(url_for('admin_reports'))

# 상품 상태 변경
@app.route('/admin/product/<product_id>/status', methods=['POST'])
@admin_required
def update_product_status(product_id):
    status = request.form.get('status')
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE product SET status = ? WHERE id = ?", (status, product_id))
    db.commit()
    flash('상품 상태가 변경되었습니다.')
    return redirect(url_for('admin_products'))

# 데이터베이스 초기화
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # 사용자 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                bio TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_admin BOOLEAN DEFAULT 0,
                is_blocked BOOLEAN DEFAULT 0
            )
        """)
        
        # 상품 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price INTEGER NOT NULL,
                seller_id TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (seller_id) REFERENCES user (id)
            )
        """)
        
        # 신고 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                target_type TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (reporter_id) REFERENCES user (id)
            )
        """)
        
        # 채팅 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES user (id),
                FOREIGN KEY (receiver_id) REFERENCES user (id)
            )
        """)
        
        # 관리자 계정 생성
        cursor.execute("SELECT * FROM user WHERE username = 'admin'")
        if not cursor.fetchone():
            admin_id = str(uuid.uuid4())
            hashed_password = generate_password_hash('admin123')
            cursor.execute(
                "INSERT INTO user (id, username, password, email, is_admin) VALUES (?, ?, ?, ?, ?)",
                (admin_id, 'admin', hashed_password, 'admin@example.com', 1)
            )
        
        db.commit()
        print("데이터베이스 초기화 완료")

if __name__ == '__main__':
    socketio.run(app, debug=True)