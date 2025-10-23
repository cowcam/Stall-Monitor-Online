export interface Env {
  DB: D1Database;
}

// --- Configuration ---
const allowedOrigin = 'https://www.stallmonitor.com';

// --- CORS Headers ---
const corsHeaders = {
  'Access-Control-Allow-Origin': allowedOrigin,
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

// --- Crypto Helper Functions ---

/**
 * Converts an ArrayBuffer (like a hash) into a hex string.
 */
function bufferToHex(buffer: ArrayBuffer): string {
  return [...new Uint8Array(buffer)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * **NEW:** Converts a hex string (from the DB) back into an ArrayBuffer.
 */
function hexToBuffer(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Hashes a password with a salt using SHA-256.
 */
async function hashPassword(password: string, salt: Uint8Array): Promise<string> {
  const passwordBuffer = new TextEncoder().encode(password);
  const combinedBuffer = new Uint8Array(salt.length + passwordBuffer.length);
  combinedBuffer.set(salt);
  combinedBuffer.set(passwordBuffer, salt.length);
  const hashBuffer = await crypto.subtle.digest('SHA-256', combinedBuffer);
  return bufferToHex(hashBuffer);
}

// --- Main Worker Logic ---
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const { pathname } = new URL(request.url);

    // Handle all OPTIONS preflight requests
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // --- Handle GET for /api/messages ---
    if (request.method === 'GET' && pathname === '/api/messages') {
      // (This route is unchanged)
      try {
        const { results } = await env.DB.prepare('SELECT * FROM messages ORDER BY id DESC').all();
        return new Response(JSON.stringify(results), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      } catch (e) {
        console.error("--- ERROR IN /api/messages ---", e instanceof Error ? e.message : String(e));
        return new Response(e instanceof Error ? e.message : String(e), { status: 500, headers: corsHeaders });
      }
    }

    // --- Handle POST for /api/messages ---
    if (request.method === 'POST' && pathname === '/api/messages') {
      // (This route is unchanged)
      try {
        const message = await request.json<{ name: string; body: string }>();
        await env.DB.prepare('INSERT INTO messages (name, body) VALUES (?, ?)')
          .bind(message.name, message.body)
          .run();
        return new Response('Message added!', { status: 201, headers: corsHeaders });
      } catch (e) {
        console.error("--- ERROR IN POST /api/messages ---", e instanceof Error ? e.message : String(e));
        return new Response(e instanceof Error ? e.message : String(e), { status: 500, headers: corsHeaders });
      }
    }

    // --- Handle POST for /register ---
    if (request.method === 'POST' && pathname === '/register') {
      // (This route is unchanged)
      try {
        const { email, password } = await request.json<{ email: string; password: string }>();
        if (!email || !password) {
          return new Response('Email and password are required', { status: 400, headers: corsHeaders });
        }
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const passwordHash = await hashPassword(password, salt);
        const saltHex = bufferToHex(salt);
        await env.DB.prepare('INSERT INTO users (email, password_hash, salt) VALUES (?, ?, ?)')
          .bind(email, passwordHash, saltHex).run();
        return new Response('User account created!', { status: 201, headers: corsHeaders });
      } catch (e) {
        let errorMessage = e instanceof Error ? e.message : String(e);
        console.error("--- ERROR IN /register ---", errorMessage, e instanceof Error ? e.stack : '');
        if (errorMessage.includes('UNIQUE constraint failed: users.email')) {
          return new Response('This email is already in use.', { status: 409, headers: corsHeaders });
        }
        return new Response('Error creating account: ' + errorMessage, { status: 500, headers: corsHeaders });
      }
    }

    // --- **NEW:** Handle POST for /login ---
    if (request.method === 'POST' && pathname === '/login') {
      try {
        const { email, password } = await request.json<{ email: string; password: string }>();

        // 1. Find the user
        const user = await env.DB.prepare('SELECT password_hash, salt FROM users WHERE email = ?')
          .bind(email)
          .first<{ password_hash: string; salt: string }>();

        if (!user) {
          return new Response('Invalid email or password', { status: 401, headers: corsHeaders }); // 401 Unauthorized
        }

        // 2. Get the stored salt and hash
        const saltBuffer = hexToBuffer(user.salt);
        const storedHash = user.password_hash;

        // 3. Re-hash the provided password with the stored salt
        const providedHash = await hashPassword(password, saltBuffer);

        // 4. Compare!
        if (providedHash === storedHash) {
          // SUCCESS!
          // (In a real app, you'd create and return a JSON Web Token (JWT) here)
          return new Response('Login successful!', { status: 200, headers: corsHeaders });
        } else {
          // FAIL!
          return new Response('Invalid email or password', { status: 401, headers: corsHeaders });
        }
      } catch (e) {
        let errorMessage = e instanceof Error ? e.message : String(e);
        console.error("--- ERROR IN /login ---", errorMessage, e instanceof Error ? e.stack : '');
        return new Response('Error logging in: ' + errorMessage, { status: 500, headers: corsHeaders });
      }
    }

    // --- 404 Not Found ---
    return new Response('Not found', { status: 404, headers: corsHeaders });
  },
};