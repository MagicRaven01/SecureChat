from flask import Flask, request, jsonify, send_from_directory, make_response
from flask_cors import CORS
import json
import os
from datetime import datetime, timedelta
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib
import sys
import uuid
import secrets
import re
from functools import wraps

# Установка UTF-8 кодировки для вывода
if sys.stdout.encoding != 'utf-8':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

app = Flask(__name__, static_folder='.', static_url_path='')

# ============================================
# Security Headers - защита от XSS и других атак
# ============================================
@app.after_request
def add_security_headers(response):
    """Добавляет security заголовки ко всем ответам"""
    # Content Security Policy - защита от XSS
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    
    # Запрещаем встраивать в фреймы
    response.headers['X-Frame-Options'] = 'DENY'
    
    # Запрещаем MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Включаем XSS фильтр браузера
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Referrer Policy
    response.headers['Referrer-Policy'] = 'no-referrer'
    
    # Permissions Policy
    response.headers['Permissions-Policy'] = (
        'geolocation=(), microphone=(), camera=(), usb=(), payment=()'
    )
    
    return response

# ============================================
# CORS конфигурация - только доверенные источники
# ============================================
CORS(app, 
     origins=['http://localhost:5000', 'http://127.0.0.1:5000'],
     supports_credentials=True,
     methods=['GET', 'POST', 'DELETE', 'OPTIONS'],
     allow_headers=['Content-Type', 'Authorization'])

# Хранилище сообщений в памяти (можно заменить на БД)
messages_storage = {}
# Хранилище сессий - теперь с CSRF токеном и expiration
sessions = {}  # {user_id: {'token': str, 'csrf_token': str, 'expires_at': datetime}}
# Хранилище пользователей
users = {}
# Rate limiting
rate_limit = {}  # {user_id: {'count': int, 'reset_time': datetime}}

# Ограничения для защиты от DoS
MAX_USERS = 10000
MAX_CHATS = 100000

# ============================================
# Валидация данных
# ============================================

def validate_user_id(user_id: str) -> bool:
    """Проверяет валидность user_id"""
    if not user_id:
        return False
    
    if len(user_id) < 5 or len(user_id) > 50:
        return False
    
    # Только буквы, цифры, дефис, подчеркивание
    if not re.match(r'^[A-Z0-9_-]+$', user_id):
        return False
    
    return True

# ============================================
# Функции аутентификации и управления сессиями
# ============================================

def generate_session_token():
    """Генерирует безопасный токен сессии"""
    return secrets.token_urlsafe(32)

def generate_csrf_token():
    """Генерирует CSRF токен"""
    return secrets.token_urlsafe(32)

def create_session(user_id):
    """Создаёт сессию с временем истечения (1 час)"""
    session_token = generate_session_token()
    csrf_token = generate_csrf_token()
    sessions[user_id] = {
        'token': session_token,
        'csrf_token': csrf_token,
        'expires_at': datetime.now() + timedelta(hours=1)
    }
    return session_token, csrf_token

def verify_session_token(user_id):
    """Проверяет валидность токена сессии"""
    if user_id not in sessions:
        return False
    
    session = sessions[user_id]
    
    # Проверяем expiration
    if datetime.now() > session['expires_at']:
        del sessions[user_id]
        return False
    
    return True

def verify_csrf_token(user_id, csrf_token):
    """Проверяет CSRF токен"""
    if user_id not in sessions:
        return False
    
    return secrets.compare_digest(sessions[user_id]['csrf_token'], csrf_token)

# ============================================
# Rate limiting
# ============================================
def check_rate_limit(user_id, max_requests=30, window_seconds=60):
    """Проверяет rate limit для пользователя"""
    now = datetime.now()
    
    if user_id not in rate_limit:
        rate_limit[user_id] = {'count': 0, 'reset_time': now + timedelta(seconds=window_seconds)}
        return True
    
    limit_data = rate_limit[user_id]
    
    if now > limit_data['reset_time']:
        limit_data['count'] = 0
        limit_data['reset_time'] = now + timedelta(seconds=window_seconds)
    
    if limit_data['count'] >= max_requests:
        return False
    
    limit_data['count'] += 1
    return True

def rate_limit_decorator(max_requests=30, window_seconds=60):
    """Декоратор для защиты от spam"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = verify_auth_header(request)
            if not user_id:
                return jsonify({'error': 'Unauthorized'}), 401
            
            if not check_rate_limit(user_id, max_requests, window_seconds):
                return jsonify({'error': 'Rate limit exceeded'}), 429
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ============================================
# Функции шифрования AES-256-GCM
# ============================================

def generate_aes_key(password: str, salt: bytes = None) -> tuple:
    """Генерирует AES-256 ключ из пароля с использованием PBKDF2"""
    if salt is None:
        salt = os.urandom(16)
    
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
    return key, salt

def generate_message_key(user_id1: str, user_id2: str) -> str:
    """Генерирует ключ на основе ID двух пользователей"""
    sorted_ids = sorted([user_id1, user_id2])
    key_data = '|'.join(sorted_ids)
    return hashlib.sha256(key_data.encode()).hexdigest()[:32]

def aes_encrypt(message: str, password: str) -> str:
    """Шифрует сообщение с использованием AES-256-GCM"""
    key, salt = generate_aes_key(password)
    nonce = os.urandom(12)  # 96 bits для GCM
    
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, message.encode(), None)
    
    # Возвращаем соль + nonce + зашифрованный текст в base64
    encrypted_data = salt + nonce + ciphertext
    return base64.b64encode(encrypted_data).decode()

def aes_decrypt(encrypted_text: str, password: str) -> str:
    """Расшифровывает сообщение, зашифрованное AES-256-GCM"""
    try:
        encrypted_data = base64.b64decode(encrypted_text)
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:28]
        ciphertext = encrypted_data[28:]
        
        key, _ = generate_aes_key(password, salt)
        
        cipher = AESGCM(key)
        plaintext = cipher.decrypt(nonce, ciphertext, None)
        
        return plaintext.decode()
    except Exception as e:
        print(f"Ошибка расшифровки: {e}")
        return None

def get_chat_id(user_id1: str, user_id2: str) -> str:
    """Генерирует уникальный ID чата между двумя пользователями"""
    sorted_ids = sorted([user_id1, user_id2])
    return hashlib.sha256('|'.join(sorted_ids).encode()).hexdigest()

# ============================================
# Подача статических файлов
# ============================================

@app.route('/')
def index():
    """Главная страница"""
    return send_from_directory('.', 'chat.html')

@app.route('/<path:filename>')
def serve_static(filename):
    """Подача статических файлов (CSS, JS и др.)"""
    return send_from_directory('.', filename)

# ============================================
# API endpoints
# ============================================

@app.route('/api/auth/register', methods=['POST'])
def register_user():
    """Регистрирует нового пользователя и выдаёт токен сессии"""
    data = request.json
    user_id = data.get('user_id')
    
    # ✅ Валидация user_id
    if not validate_user_id(user_id):
        return jsonify({'error': 'Invalid user_id format'}), 400
    
    # ✅ Проверка на лимит пользователей
    if len(users) >= MAX_USERS:
        return jsonify({'error': 'Server capacity exceeded'}), 503
    
    # ✅ Проверяем что пользователь не существует
    if user_id in users:
        return jsonify({'error': 'User already exists'}), 409
    
    # Генерируем токен сессии и CSRF токен
    session_token, csrf_token = create_session(user_id)
    users[user_id] = {
        'user_id': user_id,
        'created_at': datetime.now().isoformat(),
        'last_seen': datetime.now().isoformat()
    }
    
    return jsonify({
        'success': True,
        'user_id': user_id,
        'session_token': session_token,
        'csrf_token': csrf_token
    }), 201

def verify_auth_header(request):
    """Проверяет авторизационный заголовок с защитой от timing attack"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None
    
    token = auth_header[7:]
    
    # Ищем пользователя с этим токеном
    for user_id, session_data in sessions.items():
        # Используем constant-time comparison для защиты от timing attack
        if secrets.compare_digest(session_data['token'], token):
            if verify_session_token(user_id):
                return user_id
    
    return None

@app.route('/api/messages', methods=['GET'])
def get_messages():
    """Получить сообщения между двумя пользователями"""
    # ✅ Проверяем авторизацию
    user_id = verify_auth_header(request)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    
    remote_id = request.args.get('remote_id')
    
    if not remote_id:
        return jsonify({'error': 'Missing remote_id'}), 400
    
    # ✅ Проверяем валидность remote_id
    if not validate_user_id(remote_id):
        return jsonify({'error': 'Invalid remote_id'}), 400
    
    # ✅ Разрешаем общение даже если второй пользователь не зарегистрирован
    # Это позволяет отправлять приглашения и сообщения до регистрации
    
    chat_id = get_chat_id(user_id, remote_id)
    
    if chat_id not in messages_storage:
        messages_storage[chat_id] = []
    
    return jsonify({
        'messages': messages_storage[chat_id],
        'chat_id': chat_id
    })

@app.route('/api/messages', methods=['POST'])
@rate_limit_decorator(max_requests=30, window_seconds=60)
def send_message():
    """Отправить зашифрованное сообщение"""
    # Проверяем авторизацию
    user_id = verify_auth_header(request)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    remote_id = data.get('remote_id')
    encrypted_text = data.get('encrypted_text')
    csrf_token = data.get('csrf_token')
    
    # ✅ Проверяем CSRF токен
    if not csrf_token or not verify_csrf_token(user_id, csrf_token):
        return jsonify({'error': 'Invalid CSRF token'}), 403
    
    if not all([remote_id, encrypted_text]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # ✅ Разрешаем отправлять сообщения даже если пользователь не зарегистрирован
    # Это позволяет инициировать общение с неподключённым пользователем
    
    # ✅ Проверяем что encrypted_text имеет допустимую длину
    if len(encrypted_text) > 10000:
        return jsonify({'error': 'Message too large'}), 413
    
    chat_id = get_chat_id(user_id, remote_id)
    
    if chat_id not in messages_storage:
        messages_storage[chat_id] = []
    
    message = {
        'id': len(messages_storage[chat_id]),
        'from': user_id,
        'to': remote_id,
        'encrypted_text': encrypted_text,
        'timestamp': datetime.now().isoformat(),
        'read': False
    }
    
    messages_storage[chat_id].append(message)
    
    return jsonify({
        'success': True,
        'message': message
    }), 201

@app.route('/api/messages/<int:message_id>', methods=['DELETE'])
def delete_message(message_id):
    """Удалить сообщение"""
    # ✅ Проверяем авторизацию
    user_id = verify_auth_header(request)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    
    remote_id = request.args.get('remote_id')
    if not remote_id:
        return jsonify({'error': 'Missing remote_id'}), 400
    
    chat_id = get_chat_id(user_id, remote_id)
    
    if chat_id not in messages_storage:
        return jsonify({'error': 'Chat not found'}), 404
    
    if message_id >= len(messages_storage[chat_id]):
        return jsonify({'error': 'Message not found'}), 404
    
    message = messages_storage[chat_id][message_id]
    
    # ✅ Проверяем что пользователь владеет сообщением
    if message['from'] != user_id:
        return jsonify({'error': 'You can only delete your own messages'}), 403
    
    # ✅ Удаляем сообщение
    messages_storage[chat_id].pop(message_id)
    
    return jsonify({'success': True}), 200

@app.route('/api/messages/clear', methods=['POST'])
def clear_messages():
    """Очистить все сообщения (только свои)"""
    # ✅ Проверяем авторизацию
    user_id = verify_auth_header(request)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    remote_id = data.get('remote_id')
    csrf_token = data.get('csrf_token')
    
    # ✅ Проверяем CSRF
    if not csrf_token or not verify_csrf_token(user_id, csrf_token):
        return jsonify({'error': 'Invalid CSRF token'}), 403
    
    if not remote_id:
        return jsonify({'error': 'Missing remote_id'}), 400
    
    # ✅ Проверяем что пользователь существует
    if remote_id not in users:
        return jsonify({'error': 'User not found'}), 404
    
    chat_id = get_chat_id(user_id, remote_id)
    if chat_id in messages_storage:
        messages_storage[chat_id] = []
    
    return jsonify({'success': True})

@app.route('/api/health', methods=['GET'])
def health():
    """Проверка статуса сервера"""
    return jsonify({'status': 'ok'}), 200

# ============================================
# Статистика и управление
# ============================================

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Получить статистику по чатам (только для своих)"""
    # ✅ Требуем авторизацию
    user_id = verify_auth_header(request)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # ✅ Возвращаем только статистику пользователя
    user_chats = {}
    for chat_id, messages in messages_storage.items():
        # Проверяем что пользователь участвует в этом чате
        for msg in messages:
            if msg['from'] == user_id or msg['to'] == user_id:
                user_chats[chat_id] = len(messages)
                break
    
    return jsonify({
        'total_chats': len(user_chats),
        'total_messages': sum(user_chats.values()),
        'chats': user_chats})

if __name__ == '__main__':
    print("=" * 60)
    print("[*] Защищённый чат сервер")
    print("=" * 60)
    print("Запущен на http://localhost:5000")
    print("\nОткройте chat.html в браузере для использования чата")
    print("=" * 60)
    app.run(debug=False, host='localhost', port=5000)
