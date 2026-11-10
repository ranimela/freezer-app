import { next } from '@vercel/functions';

export const config = {
  matcher: ['/((?!favicon.ico|_next|.*\\.(?:png|jpg|jpeg|gif|svg|webp|ico|css|js)).*)'],
};

// Web Crypto helper functions
async function getKey(secret) {
  const enc = new TextEncoder();
  return crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// Generate signed 30-day session token
async function createToken(secret) {
  const ts = Date.now().toString();
  const key = await getKey(secret);
  const enc = new TextEncoder();
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(ts));
  return `${ts}.${bytesToHex(new Uint8Array(sig))}`;
}

// Verify token cryptographically in constant time
async function verifyToken(token, secret) {
  if (!token || !secret) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [tsStr, hexSig] = parts;
  const ts = parseInt(tsStr, 10);
  if (isNaN(ts)) return false;

  // 30 days expiration window
  const maxAgeMs = 30 * 24 * 60 * 60 * 1000;
  if (Date.now() - ts > maxAgeMs || ts > Date.now() + 60000) {
    return false;
  }

  try {
    const key = await getKey(secret);
    const enc = new TextEncoder();
    const sigBytes = hexToBytes(hexSig);
    return await crypto.subtle.verify('HMAC', key, sigBytes, enc.encode(tsStr));
  } catch {
    return false;
  }
}

// Constant-time comparison for password against timing attacks
async function comparePassword(input, expected) {
  if (!input || !expected) return false;
  const enc = new TextEncoder();
  const hashA = await crypto.subtle.digest('SHA-256', enc.encode(input));
  const hashB = await crypto.subtle.digest('SHA-256', enc.encode(expected));
  const bufA = new Uint8Array(hashA);
  const bufB = new Uint8Array(hashB);
  let diff = 0;
  for (let i = 0; i < bufA.length; i++) {
    diff |= bufA[i] ^ bufB[i];
  }
  return diff === 0;
}

function getCookie(header, name) {
  if (!header) return null;
  const match = header.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]*)'));
  return match ? decodeURIComponent(match[1]) : null;
}

function renderLoginHtml({ error = false, unconfigured = false, returnTo = '/' }) {
  return `<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>כניסה | בררר</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;800&family=Heebo:wght@400;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-deep: #0f172a;
      --glass-bg: rgba(255, 255, 255, 0.04);
      --glass-border: rgba(255, 255, 255, 0.1);
      --text-main: #f1f5f9;
      --text-dim: #94a3b8;
      --accent-blue: #38bdf8;
      --accent-glow: rgba(56, 189, 248, 0.35);
      --error-red: #ef4444;
    }
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }
    body {
      font-family: 'Outfit', 'Heebo', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg-deep);
      background-image:
        radial-gradient(at 0% 0%, rgba(56, 189, 248, 0.12) 0px, transparent 50%),
        radial-gradient(at 100% 100%, rgba(56, 189, 248, 0.08) 0px, transparent 50%);
      color: var(--text-main);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .card {
      width: 100%;
      max-width: 380px;
      background: var(--glass-bg);
      border: 1px solid var(--glass-border);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border-radius: 24px;
      padding: 36px 28px;
      box-shadow: 0 20px 50px -10px rgba(0, 0, 0, 0.6);
      text-align: center;
      position: relative;
      overflow: hidden;
    }
    .card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 2px;
      background: linear-gradient(90deg, transparent, var(--accent-blue), transparent);
    }
    .icon-box {
      width: 64px;
      height: 64px;
      margin: 0 auto 20px;
      background: rgba(56, 189, 248, 0.1);
      border: 1px solid rgba(56, 189, 248, 0.25);
      border-radius: 18px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--accent-blue);
      box-shadow: 0 0 25px var(--accent-glow);
    }
    h1 {
      font-size: 2rem;
      font-weight: 800;
      background: linear-gradient(to bottom right, #fff 40%, var(--accent-blue));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: 6px;
    }
    p.subtitle {
      color: var(--text-dim);
      font-size: 0.95rem;
      margin-bottom: 24px;
    }
    .alert {
      background: rgba(239, 68, 68, 0.12);
      border: 1px solid rgba(239, 68, 68, 0.3);
      color: #fca5a5;
      padding: 10px 14px;
      border-radius: 12px;
      font-size: 0.9rem;
      margin-bottom: 20px;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      animation: shake 0.4s ease-in-out;
    }
    .info-alert {
      background: rgba(56, 189, 248, 0.1);
      border: 1px solid rgba(56, 189, 248, 0.25);
      color: var(--accent-blue);
      padding: 12px 14px;
      border-radius: 12px;
      font-size: 0.88rem;
      line-height: 1.5;
      margin-bottom: 20px;
    }
    @keyframes shake {
      0%, 100% { transform: translateX(0); }
      20%, 60% { transform: translateX(-6px); }
      40%, 80% { transform: translateX(6px); }
    }
    .input-wrap {
      position: relative;
      margin-bottom: 20px;
    }
    input[type="password"], input[type="text"] {
      width: 100%;
      background: rgba(15, 23, 42, 0.6);
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 14px;
      padding: 14px 44px 14px 16px;
      font-size: 1.05rem;
      color: var(--text-main);
      direction: ltr;
      text-align: right;
      outline: none;
      transition: all 0.2s ease;
      font-family: inherit;
    }
    input:focus {
      border-color: var(--accent-blue);
      box-shadow: 0 0 15px var(--accent-glow);
    }
    .toggle-pass {
      position: absolute;
      left: 12px;
      top: 50%;
      transform: translateY(-50%);
      background: none;
      border: none;
      color: var(--text-dim);
      cursor: pointer;
      padding: 4px;
      display: flex;
      align-items: center;
    }
    .toggle-pass:hover {
      color: var(--text-main);
    }
    .submit-btn {
      width: 100%;
      background: linear-gradient(135deg, #38bdf8 0%, #0284c7 100%);
      color: #0f172a;
      border: none;
      border-radius: 14px;
      padding: 14px;
      font-size: 1.05rem;
      font-weight: 700;
      cursor: pointer;
      transition: all 0.2s ease;
      font-family: inherit;
      box-shadow: 0 4px 15px rgba(56, 189, 248, 0.3);
    }
    .submit-btn:hover {
      transform: translateY(-1px);
      box-shadow: 0 6px 20px rgba(56, 189, 248, 0.45);
    }
    .submit-btn:active {
      transform: translateY(0);
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon-box">
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
        <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
      </svg>
    </div>
    <h1>בררר</h1>
    <p class="subtitle">המקפיא נעול. יש להזין סיסמה להמשך</p>

    ${
      unconfigured
        ? `<div class="info-alert">
            <strong>נדרשת הגדרה ראשונית:</strong><br>
            יש להגדיר את משתנה הסביבה <code>FREEZER_PASSWORD</code> בלוח הבקרה של Vercel.
          </div>`
        : ''
    }

    ${
      error
        ? `<div class="alert">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"/>
              <line x1="12" y1="8" x2="12" y2="12"/>
              <line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
            סיסמה שגויה. נסה שוב.
          </div>`
        : ''
    }

    ${
      !unconfigured
        ? `<form method="POST" action="/login">
            <input type="hidden" name="returnTo" value="${encodeURIComponent(returnTo)}">
            <div class="input-wrap">
              <input type="password" id="passInput" name="password" placeholder="סיסמה..." required autofocus autocomplete="current-password">
              <button type="button" class="toggle-pass" onclick="togglePassword()" title="הצג/הסתר סיסמה">
                <svg id="eyeIcon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                  <circle cx="12" cy="12" r="3"/>
                </svg>
              </button>
            </div>
            <button type="submit" class="submit-btn">כניסה</button>
          </form>`
        : ''
    }
  </div>

  <script>
    function togglePassword() {
      const inp = document.getElementById('passInput');
      const eye = document.getElementById('eyeIcon');
      if (inp.type === 'password') {
        inp.type = 'text';
        eye.innerHTML = '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>';
      } else {
        inp.type = 'password';
        eye.innerHTML = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>';
      }
    }
  </script>
</body>
</html>`;
}

export default async function proxy(request) {
  const url = new URL(request.url);
  const secret = process.env.FREEZER_PASSWORD || 'brrr';

  // Handle logout
  if (url.pathname === '/logout') {
    return new Response(null, {
      status: 302,
      headers: {
        Location: '/',
        'Set-Cookie': 'freezer_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict',
      },
    });
  }

  // Handle Login submission (POST /login)
  if (request.method === 'POST' && url.pathname === '/login') {
    if (!secret) {
      return new Response(renderLoginHtml({ unconfigured: true }), {
        status: 500,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }

    try {
      const bodyText = await request.text();
      const params = new URLSearchParams(bodyText);
      const password = params.get('password') || '';
      const returnTo = decodeURIComponent(params.get('returnTo') || '/');

      const isMatch = await comparePassword(password, secret);

      if (isMatch) {
        const token = await createToken(secret);
        const destination = returnTo.startsWith('/') ? returnTo : '/';
        return new Response(null, {
          status: 302,
          headers: {
            Location: destination,
            'Set-Cookie': `freezer_session=${token}; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Strict`,
          },
        });
      }

      // Add a 500ms delay to deter brute-force guessing
      await new Promise((r) => setTimeout(r, 500));

      return new Response(renderLoginHtml({ error: true, returnTo }), {
        status: 401,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    } catch {
      return new Response(renderLoginHtml({ error: true }), {
        status: 400,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }
  }

  // Check existing session cookie
  const cookieHeader = request.headers.get('cookie') || '';
  const sessionToken = getCookie(cookieHeader, 'freezer_session');

  if (secret) {
    const isValid = await verifyToken(sessionToken, secret);
    if (isValid) {
      // Valid cryptographic session - proceed to app
      return next();
    }
  } else {
    // If password not yet configured in Vercel env, show helpful setup prompt
    return new Response(renderLoginHtml({ unconfigured: true }), {
      status: 503,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  }

  // Not authenticated - serve login screen
  return new Response(renderLoginHtml({ error: false, returnTo: url.pathname }), {
    status: 401,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}
