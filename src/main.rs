// Cargo.toml:
// [package]
// name = "totp-server"
// version = "0.1.0"
// edition = "2021"
//
// [dependencies]
// hmac = "0.12"
// sha1 = "0.10"
// base32 = "0.4"
// rand = "0.8"
// tiny_http = "0.12"
// qrcode = "0.14"
// urlencoding = "2.1"

use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};
use qrcode::QrCode;
use qrcode::render::svg;

type HmacSha1 = Hmac<Sha1>;

/// Реализация HOTP (HMAC-based One-Time Password) - RFC 4226
/// 
/// МАТЕМАТИЧЕСКИЙ ПРИНЦИП:
/// 1. Берем секретный ключ K и счетчик C
/// 2. Вычисляем HMAC-SHA1(K, C) - получаем 20 байт
/// 3. Применяем "Dynamic Truncation":
///    - Берем последний байт HMAC и используем его младшие 4 бита как offset
///    - Извлекаем 4 байта начиная с offset
///    - Преобразуем эти 4 байта в 31-битное число (старший бит обнуляем)
/// 4. Применяем модуль 10^digits для получения кода нужной длины
fn hotp(secret: &[u8], counter: u64, digits: u32) -> u32 {
    // Шаг 1: Преобразуем счетчик в массив байтов (big-endian)
    let counter_bytes = counter.to_be_bytes();
    
    // Шаг 2: Вычисляем HMAC-SHA1
    let mut mac = HmacSha1::new_from_slice(secret)
        .expect("HMAC может принять ключ любого размера");
    mac.update(&counter_bytes);
    let hmac_result = mac.finalize().into_bytes();
    
    // Шаг 3: Dynamic Truncation (это ключевая часть алгоритма!)
    // Берем последний байт и извлекаем из него младшие 4 бита
    let offset = (hmac_result[19] & 0x0f) as usize;
    
    // Извлекаем 4 байта начиная с offset и собираем их в u32
    let truncated_hash = u32::from_be_bytes([
        hmac_result[offset],
        hmac_result[offset + 1],
        hmac_result[offset + 2],
        hmac_result[offset + 3],
    ]);
    
    // Обнуляем старший бит (делаем число 31-битным)
    let code = truncated_hash & 0x7fffffff;
    
    // Шаг 4: Применяем модуль 10^digits
    code % 10_u32.pow(digits)
}

/// Реализация TOTP (Time-based One-Time Password) - RFC 6238
/// 
/// МАТЕМАТИЧЕСКИЙ ПРИНЦИП:
/// TOTP - это просто HOTP, где счетчик вычисляется из текущего времени:
/// counter = floor(unix_time / time_step)
/// 
/// Обычно time_step = 30 секунд
/// Это означает, что каждые 30 секунд генерируется новый код
fn totp(secret: &[u8], time_step: u64, digits: u32) -> u32 {
    // Получаем текущее Unix время (секунды с 1 января 1970)
    let unix_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Время не может быть до эпохи Unix")
        .as_secs();
    
    // Вычисляем счетчик: текущее время делим на временной интервал
    let counter = unix_time / time_step;
    
    // Используем HOTP с вычисленным счетчиком
    hotp(secret, counter, digits)
}

/// Проверка TOTP кода с учетом временного окна
/// window - количество интервалов назад/вперед для проверки (для учета задержек)
fn verify_totp(secret: &[u8], code: u32, time_step: u64, digits: u32, window: i32) -> bool {
    let unix_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Время не может быть до эпохи Unix")
        .as_secs();
    
    let counter = (unix_time / time_step) as i64;
    
    // Проверяем код в окне [-window, +window]
    for i in -window..=window {
        let test_counter = (counter + i as i64) as u64;
        if hotp(secret, test_counter, digits) == code {
            return true;
        }
    }
    
    false
}

/// Генерация случайного секретного ключа
fn generate_secret() -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..20).map(|_| rng.r#gen::<u8>()).collect()
}

/// Кодирование секрета в Base32 для отображения пользователю
fn encode_secret_base32(secret: &[u8]) -> String {
    base32::encode(base32::Alphabet::RFC4648 { padding: false }, secret)
}

/// Декодирование Base32 секрета (используется для импорта ключей)
#[allow(dead_code)]
fn decode_secret_base32(encoded: &str) -> Result<Vec<u8>, String> {
    base32::decode(base32::Alphabet::RFC4648 { padding: false }, encoded)
        .ok_or_else(|| "Неверный формат Base32".to_string())
}

/// Генерация TOTP URI для QR кода
/// Формат: otpauth://totp/Label?secret=BASE32SECRET&issuer=Issuer
fn generate_totp_uri(secret_base32: &str, label: &str, issuer: &str) -> String {
    format!(
        "otpauth://totp/{}?secret={}&issuer={}",
        urlencoding::encode(label),
        secret_base32,
        urlencoding::encode(issuer)
    )
}

/// Генерация QR кода в формате SVG
fn generate_qr_code_svg(data: &str) -> Result<String, String> {
    let code = QrCode::new(data.as_bytes())
        .map_err(|e| format!("Ошибка создания QR кода: {}", e))?;
    
    let svg = code.render::<svg::Color>()
        .min_dimensions(200, 200)
        .build();
    
    Ok(svg)
}

// ============= ВЕБ-СЕРВЕР =============

fn main() {
    // Генерируем секретный ключ (в реальном приложении он должен быть уникальным для каждого пользователя)
    let secret = generate_secret();
    let secret_base32 = encode_secret_base32(&secret);
    
    // Генерируем TOTP URI и QR код
    let totp_uri = generate_totp_uri(&secret_base32, "MyApp:user@example.com", "MyApp");
    let qr_code_svg = generate_qr_code_svg(&totp_uri).expect("Не удалось создать QR код");
    
    println!("🔐 TOTP 2FA Сервер запущен!");
    println!("📱 Ваш секретный ключ: {}", secret_base32);
    println!("🌐 Откройте браузер: http://localhost:8080");
    println!("\n💡 Как протестировать:");
    println!("   1. Откройте страницу в браузере");
    println!("   2. Отсканируйте QR код в Google Authenticator");
    println!("   3. Введите код из приложения для авторизации\n");
    
    let server = tiny_http::Server::http("127.0.0.1:8080").unwrap();
    
    for mut request in server.incoming_requests() {
        let url = request.url().to_string();
        
        if url == "/current_code" {
            // API endpoint для получения текущего кода и времени до обновления
            let unix_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Время не может быть до эпохи Unix")
                .as_secs();
            let current_code = totp(&secret, 30, 6);
            let remaining = 30 - (unix_time % 30);
            let json = format!(
                r#"{{"code": "{:06}", "remaining": {}, "server_time": {}}}"#, 
                current_code, remaining, unix_time
            );
            
            let response = tiny_http::Response::from_string(json)
                .with_header(tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap());
            request.respond(response).ok();
            
        } else if url == "/" {
            // Главная страница с формой авторизации
            let current_code = totp(&secret, 30, 6);
            let html = format!(r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>TOTP 2FA Авторизация</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 700px;
            margin: 50px auto;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        .container {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }}
        h1 {{ color: #333; text-align: center; }}
        .info-box {{
            background: #f0f7ff;
            border-left: 4px solid #4CAF50;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }}
        .qr-section {{
            text-align: center;
            background: #fff;
            padding: 20px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            margin: 20px 0;
        }}
        .qr-code {{
            display: inline-block;
            padding: 10px;
            background: white;
            border-radius: 8px;
        }}
        .secret {{
            font-family: 'Courier New', monospace;
            background: #f5f5f5;
            padding: 10px;
            border-radius: 4px;
            word-break: break-all;
            font-weight: bold;
        }}
        .code-display {{
            text-align: center;
            font-size: 48px;
            font-weight: bold;
            color: #4CAF50;
            margin: 20px 0;
            font-family: monospace;
            letter-spacing: 10px;
        }}
        input[type="text"] {{
            width: 100%;
            padding: 12px;
            font-size: 24px;
            text-align: center;
            border: 2px solid #ddd;
            border-radius: 5px;
            box-sizing: border-box;
            letter-spacing: 5px;
            font-family: monospace;
        }}
        button {{
            width: 100%;
            padding: 15px;
            background: #4CAF50;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 18px;
            cursor: pointer;
            margin-top: 15px;
        }}
        button:hover {{ background: #45a049; }}
        .timer {{
            text-align: center;
            font-size: 14px;
            color: #666;
            margin-top: 10px;
        }}
        .debug-info {{
            background: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 4px;
            padding: 10px;
            margin-top: 10px;
            font-size: 12px;
            font-family: monospace;
        }}
        .warning {{
            background: #f8d7da;
            border-left: 4px solid #dc3545;
            padding: 10px;
            margin-top: 10px;
            border-radius: 4px;
            font-size: 13px;
        }}
        .progress-bar {{
            width: 100%;
            height: 4px;
            background: #e0e0e0;
            border-radius: 2px;
            margin-top: 10px;
            overflow: hidden;
        }}
        .progress-fill {{
            height: 100%;
            background: #4CAF50;
            transition: width 1s linear;
        }}
    </style>
    <script>
        let lastRemaining = 30;
        
        function formatTime(timestamp) {{
            const date = new Date(timestamp * 1000);
            return date.toLocaleTimeString('ru-RU', {{ 
                hour: '2-digit', 
                minute: '2-digit', 
                second: '2-digit',
                hour12: false 
            }});
        }}
        
        async function updateFromServer() {{
            try {{
                const response = await fetch('/current_code');
                const data = await response.json();
                
                // Обновляем код
                document.getElementById('code-display').textContent = data.code;
                
                // Обновляем таймер и прогресс-бар
                const remaining = data.remaining;
                lastRemaining = remaining;
                
                const progress = (remaining / 30) * 100;
                document.getElementById('timer').textContent = `Код обновится через: ${{remaining}} сек`;
                document.getElementById('progress').style.width = progress + '%';
                
                // Меняем цвет когда остается мало времени
                if (remaining <= 5) {{
                    document.getElementById('progress').style.background = '#f44336';
                }} else {{
                    document.getElementById('progress').style.background = '#4CAF50';
                }}
                
                // Отладочная информация
                const serverTime = data.server_time;
                const clientTime = Math.floor(Date.now() / 1000);
                const timeDiff = serverTime - clientTime;
                
                document.getElementById('server-time').textContent = formatTime(serverTime);
                document.getElementById('client-time').textContent = formatTime(clientTime);
                document.getElementById('time-diff').textContent = timeDiff;
                
                // Показываем предупреждение если разница больше 1 секунды
                const warningDiv = document.getElementById('time-warning');
                if (Math.abs(timeDiff) > 1) {{
                    warningDiv.style.display = 'block';
                    warningDiv.innerHTML = `
                        <strong>⚠️ Обнаружена рассинхронизация времени!</strong><br>
                        Разница: ${{timeDiff}} сек. 
                        ${{timeDiff > 0 ? 'Часы компьютера отстают.' : 'Часы компьютера спешат.'}}
                        <br><small>Для точной работы синхронизируйте системное время.</small>
                    `;
                }} else {{
                    warningDiv.style.display = 'none';
                }}
            }} catch (e) {{
                console.error('Ошибка обновления:', e);
            }}
        }}
        
        // Обновляем данные с сервера каждую секунду
        setInterval(updateFromServer, 1000);
        
        // Первое обновление при загрузке
        window.onload = updateFromServer;
    </script>
</head>
<body>
    <div class="container">
        <h1>🔐 TOTP 2FA Авторизация</h1>
        
        <div class="qr-section">
            <h3>📱 Отсканируйте QR код</h3>
            <p style="color: #666; font-size: 14px;">Откройте Google Authenticator → Добавить → Сканировать QR код</p>
            <div class="qr-code">
                {qr_code}
            </div>
        </div>
        
        <div class="info-box">
            <strong>🔑 Или введите ключ вручную:</strong>
            <div class="secret">{secret}</div>
        </div>
        
        <div class="info-box">
            <strong>🔢 Текущий TOTP код:</strong>
            <div id="code-display" class="code-display">{code:06}</div>
            <div class="progress-bar">
                <div id="progress" class="progress-fill"></div>
            </div>
            <div class="timer" id="timer"></div>
            
            <div id="time-warning" class="warning" style="display: none;"></div>
            
            <div class="debug-info">
                <strong>🕐 Диагностика времени:</strong><br>
                Время сервера: <span id="server-time">--:--:--</span><br>
                Время браузера: <span id="client-time">--:--:--</span><br>
                Разница: <span id="time-diff">0</span> сек
            </div>
        </div>
        
        <form method="POST" action="/verify">
            <input type="text" name="code" placeholder="Введите 6-значный код" 
                   maxlength="6" pattern="[0-9]{{6}}" required autofocus>
            <button type="submit">Войти</button>
        </form>
        
        <div class="info-box" style="margin-top: 20px; font-size: 14px;">
            <strong>💡 Как работает TOTP:</strong>
            <ul>
                <li>Код генерируется каждые 30 секунд</li>
                <li>Используется HMAC-SHA1 от времени и секретного ключа</li>
                <li>Применяется dynamic truncation для получения 6-значного кода</li>
            </ul>
        </div>
    </div>
</body>
</html>
            "#, secret = secret_base32, code = current_code, qr_code = qr_code_svg);
            
            let response = tiny_http::Response::from_string(html)
                .with_header(tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap());
            request.respond(response).ok();
            
        } else if url.starts_with("/verify") {
            // Обработка проверки кода
            let mut content = String::new();
            request.as_reader().read_to_string(&mut content).ok();
            
            let code_str = content
                .split('&')
                .find(|p| p.starts_with("code="))
                .and_then(|p| p.strip_prefix("code="))
                .unwrap_or("");
            
            let code = code_str.parse::<u32>().unwrap_or(0);
            
            // Проверяем код с окном в 1 интервал (учитываем задержки сети/пользователя)
            let is_valid = verify_totp(&secret, code, 30, 6, 1);
            
            let html = if is_valid {
                r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Успешная авторизация</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
            min-height: 100vh;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            text-align: center;
        }
        .success-icon { font-size: 80px; margin-bottom: 20px; }
        h1 { color: #4CAF50; }
        a {
            display: inline-block;
            margin-top: 20px;
            padding: 15px 30px;
            background: #4CAF50;
            color: white;
            text-decoration: none;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="success-icon">✅</div>
        <h1>Авторизация успешна!</h1>
        <p>Код подтвержден. Двухфакторная аутентификация пройдена.</p>
        <a href="/">← Вернуться на главную</a>
    </div>
</body>
</html>
                "#.to_string()
            } else {
                format!(r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Ошибка авторизации</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            background: linear-gradient(135deg, #eb3349 0%, #f45c43 100%);
            min-height: 100vh;
        }}
        .container {{
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            text-align: center;
        }}
        .error-icon {{ font-size: 80px; margin-bottom: 20px; }}
        h1 {{ color: #f44336; }}
        a {{
            display: inline-block;
            margin-top: 20px;
            padding: 15px 30px;
            background: #f44336;
            color: white;
            text-decoration: none;
            border-radius: 5px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon">❌</div>
        <h1>Неверный код!</h1>
        <p>Введенный код: {code}</p>
        <p>Код не прошел проверку. Попробуйте еще раз.</p>
        <a href="/">← Попробовать снова</a>
    </div>
</body>
</html>
                "#, code = code_str)
            };
            
            let response = tiny_http::Response::from_string(html)
                .with_header(tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap());
            request.respond(response).ok();
        }
    }
}