// ===== Генерация и управление ID =====
let currentUserId = null;
let currentSessionToken = null;
let currentCsrfToken = null;

// ===== Функция для уведомлений =====
function showNotification(message, type = 'success', duration = 3000) {
    const container = document.getElementById('notificationContainer');
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    
    container.appendChild(notification);
    
    // Автоматически удаляем уведомление
    setTimeout(() => {
        notification.classList.add('removing');
        setTimeout(() => {
            notification.remove();
        }, 300);
    }, duration);
}

function generateUserId() {
    const timestamp = Date.now().toString(36);
    const randomStr = Math.random().toString(36).substring(2, 15);
    return (timestamp + randomStr).substring(0, 20).toUpperCase();
}

async function initializeUser() {
    currentUserId = generateUserId();
    // Регистрируем пользователя на сервере
    try {
        const response = await fetch('/api/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: currentUserId })
        });
        const data = await response.json();
        if (data.success) {
            currentSessionToken = data.session_token;
            currentCsrfToken = data.csrf_token;
            document.getElementById('userId').textContent = currentUserId;
            console.log('✅ Пользователь зарегистрирован:', currentUserId);
            return true;
        } else {
            console.error('Ошибка регистрации:', data.error);
            return false;
        }
    } catch (e) {
        console.error('Ошибка регистрации:', e);
        return false;
    }
}

initializeUser();

function generateNewId() {
    currentUserId = generateUserId();
    document.getElementById('userId').textContent = currentUserId;
    document.getElementById('remoteId').value = '';
    disconnectUser();
    
    // Регистрируем новый ID на сервере
    initializeUser().then(() => {
        showNotification('✅ Новый ID сгенерирован', 'success');
    });
}

function copyToClipboard() {
    navigator.clipboard.writeText(currentUserId).then(() => {
        showNotification('✅ ID скопирован в буфер обмена!', 'success');
    });
}

// ===== Управление чатом =====
let remoteUserId = null;
let messages = [];
let lastMessageCheck = 0;

async function connectToUser() {
    const remoteId = document.getElementById('remoteId').value.trim().toUpperCase();
    
    if (!remoteId) {
        showNotification('⚠️ Пожалуйста, введите ID собеседника', 'info');
        return;
    }

    if (remoteId === currentUserId) {
        showNotification('⚠️ Вы не можете подключиться к себе!', 'info');
        return;
    }

    remoteUserId = remoteId;
    messages = [];

    // Загружаем историю сообщений с сервера
    try {
        const response = await fetch(`/api/messages?remote_id=${remoteId}`, {
            headers: { 'Authorization': `Bearer ${currentSessionToken}` }
        });
        
        if (!response.ok) {
            showNotification('❌ Ошибка подключения: ' + response.statusText, 'error');
            return;
        }
        
        const data = await response.json();
        
        if (data.messages && Array.isArray(data.messages)) {
            for (const msg of data.messages) {
                try {
                    const decrypted = await decryptMessage(msg.encrypted_text);
                    messages.push({
                        id: msg.id,
                        from: msg.from,
                        to: msg.to,
                        text: decrypted,
                        timestamp: msg.timestamp
                    });
                } catch (decryptError) {
                    console.error('Ошибка расшифровки сообщения:', decryptError);
                    messages.push({
                        id: msg.id,
                        from: msg.from,
                        to: msg.to,
                        text: '[Ошибка расшифровки]',
                        timestamp: msg.timestamp
                    });
                }
            }
        }
    } catch (e) {
        console.error('Ошибка загрузки истории:', e);
        showNotification('❌ Ошибка загрузки истории', 'error');
    }

    // Обновляем UI
    document.getElementById('statusIndicator').classList.add('connected');
    document.getElementById('statusText').textContent = `Подключено к ${remoteId}`;
    document.getElementById('headerInfo').textContent = `ID собеседника: ${remoteId}`;
    document.getElementById('messageInput').disabled = false;
    document.getElementById('sendBtn').disabled = false;
    
    const noConnectionMsg = document.getElementById('noConnectionMsg');
    if (noConnectionMsg) noConnectionMsg.remove();

    displayMessages();

    // Проверяем новые сообщения каждые 2 секунды
    window.chatCheckInterval = setInterval(checkNewMessages, 2000);
}

function disconnectUser() {
    remoteUserId = null;
    messageKey = null;
    if (window.chatCheckInterval) {
        clearInterval(window.chatCheckInterval);
    }

    document.getElementById('statusIndicator').classList.remove('connected');
    document.getElementById('statusText').textContent = 'Не подключено';
    document.getElementById('headerInfo').textContent = 'Введите ID собеседника для начала';
    document.getElementById('messageInput').disabled = true;
    document.getElementById('sendBtn').disabled = true;
    document.getElementById('messagesContainer').innerHTML = '<div class="no-connection" id="noConnectionMsg">Выберите собеседника для начала переписки</div>';
}

// ===== Функции шифрования AES-256-GCM =====

// Генерация ключа на основе ID двух пользователей с PBKDF2
async function generateMessageKey(userId1, userId2, salt) {
    const sorted = [userId1, userId2].sort();
    const combined = sorted.join('|');
    
    if (!salt) {
        salt = crypto.getRandomValues(new Uint8Array(16));
    }
    
    const encoder = new TextEncoder();
    const passwordKey = await crypto.subtle.importKey(
        'raw',
        encoder.encode(combined),
        { name: 'PBKDF2' },
        false,
        ['deriveBits']
    );

    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        passwordKey,
        256
    );

    return {
        key: await crypto.subtle.importKey(
            'raw',
            derivedBits,
            { name: 'AES-GCM' },
            false,
            ['encrypt', 'decrypt']
        ),
        salt: salt
    };
}

// Функция шифрования
async function encryptMessage(text) {
    try {
        const nonce = crypto.getRandomValues(new Uint8Array(12));
        
        const { key, salt } = await generateMessageKey(currentUserId, remoteUserId);
        
        const encoder = new TextEncoder();
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce },
            key,
            encoder.encode(text)
        );

        // Объединяем соль + nonce + зашифрованные данные
        const combined = new Uint8Array(salt.length + nonce.length + encrypted.byteLength);
        combined.set(salt, 0);
        combined.set(nonce, salt.length);
        combined.set(new Uint8Array(encrypted), salt.length + nonce.length);

        // Кодируем в base64
        return btoa(String.fromCharCode.apply(null, combined));
    } catch (e) {
        console.error('Ошибка шифрования:', e);
        return text;
    }
}

// Функция расшифровки
async function decryptMessage(encrypted) {
    try {
        // Декодируем из base64
        const binaryString = atob(encrypted);
        const combined = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            combined[i] = binaryString.charCodeAt(i);
        }

        const salt = combined.slice(0, 16);
        const nonce = combined.slice(16, 28);
        const ciphertext = combined.slice(28);

        const { key } = await generateMessageKey(currentUserId, remoteUserId, salt);

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce },
            key,
            ciphertext
        );

        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    } catch (e) {
        console.error('Ошибка расшифровки:', e);
        return '[Ошибка расшифровки сообщения]';
    }
}

// ===== Отправка и получение сообщений =====
async function sendMessage() {
    const text = document.getElementById('messageInput').value.trim();
    
    if (!text) return;
    if (!remoteUserId) {
        showNotification('⚠️ Сначала подключитесь к собеседнику', 'info');
        return;
    }

    const encrypted = await encryptMessage(text);

    // Отправляем зашифрованное сообщение на сервер
    try {
        const response = await fetch('/api/messages', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${currentSessionToken}`
            },
            body: JSON.stringify({
                remote_id: remoteUserId,
                encrypted_text: encrypted,
                csrf_token: currentCsrfToken
            })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            console.error('Ошибка сервера:', response.status, data);
            showNotification('❌ Ошибка отправки: ' + (data.error || response.statusText), 'error');
            return;
        }
        
        if (data.success && data.message) {
            // Добавляем сообщение ТОЛЬКО после успешной отправки на сервер
            const message = {
                id: data.message.id,
                from: currentUserId,
                to: remoteUserId,
                text: text,
                timestamp: data.message.timestamp
            };
            messages.push(message);
            lastMessageCheck = Date.now();
            displayMessages();
            showNotification('✅ Сообщение отправлено', 'success');
        } else {
            console.error('Неполный ответ от сервера:', data);
            showNotification('❌ Ошибка отправки: ' + (data.error || 'Неполный ответ'), 'error');
        }
    } catch (e) {
        console.error('Ошибка отправки сообщения:', e);
        showNotification('❌ Ошибка отправки сообщения', 'error');
    }

    document.getElementById('messageInput').value = '';
}

async function checkNewMessages() {
    if (!remoteUserId) return;

    try {
        const response = await fetch(
            `/api/messages?remote_id=${remoteUserId}`,
            { headers: { 'Authorization': `Bearer ${currentSessionToken}` } }
        );
        
        if (!response.ok) return;
        
        const data = await response.json();
        
        if (!data.messages || !Array.isArray(data.messages)) {
            return;
        }
        
        // Проверяем есть ли новые сообщения
        const hasNewMessages = data.messages.length > messages.length;
        
        if (hasNewMessages) {
            for (const msg of data.messages) {
                // Проверяем что его ещё нет в сообщениях
                const msgExists = messages.some(m => m.id === msg.id);
                
                if (!msgExists) {
                    try {
                        const decrypted = await decryptMessage(msg.encrypted_text);
                        
                        messages.push({
                            id: msg.id,
                            from: msg.from,
                            to: msg.to,
                            text: decrypted,
                            timestamp: msg.timestamp
                        });
                    } catch (decryptError) {
                        console.error('Ошибка расшифровки нового сообщения:', decryptError);
                        messages.push({
                            id: msg.id,
                            from: msg.from,
                            to: msg.to,
                            text: '[Ошибка расшифровки]',
                            timestamp: msg.timestamp
                        });
                    }
                }
            }
            displayMessages();
        }
    } catch (e) {
        console.error('Ошибка при проверке сообщений:', e);
    }
}

function displayMessages() {
    const container = document.getElementById('messagesContainer');
    
    if (messages.length === 0) {
        container.innerHTML = '<div class="no-connection">Нет сообщений. Начните разговор!</div>';
        return;
    }

    container.innerHTML = messages.map(msg => `
        <div class="message ${msg.from === currentUserId ? 'own' : ''}">
            <div class="message-content">
                ${escapeHtml(msg.text)}
                <div class="message-time">${msg.timestamp}</div>
            </div>
        </div>
    `).join('');

    // Скролл в конец
    container.scrollTop = container.scrollHeight;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ===== Отправка сообщения по Enter =====
document.getElementById('messageInput').addEventListener('keypress', function(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
});

// ===== Обработчики кнопок =====
document.addEventListener('DOMContentLoaded', function() {
    // Кнопка копирования ID
    const copyBtn = document.getElementById('copyBtn');
    if (copyBtn) {
        copyBtn.addEventListener('click', copyToClipboard);
    }
    
    // Кнопка генерации нового ID
    const generateBtn = document.getElementById('generateBtn');
    if (generateBtn) {
        generateBtn.addEventListener('click', generateNewId);
    }
    
    // Кнопка подключения
    const connectBtn = document.getElementById('connectBtn');
    if (connectBtn) {
        connectBtn.addEventListener('click', connectToUser);
    }
    
    // Кнопка отправки сообщения
    const sendBtn = document.getElementById('sendBtn');
    if (sendBtn) {
        sendBtn.addEventListener('click', sendMessage);
    }
});
