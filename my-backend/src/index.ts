export interface Env {
  DB: D1Database;
}

// --- Configuration ---
// Your frontend's live domain
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
 * Hashes a password with a salt using SHA-256.
 */
async function hashPassword(password: string, salt: Uint8Array): Promise<string> {
  const passwordBuffer = new TextEncoder().encode(password);
  
  // Create a buffer that is salt + password
  const combinedBuffer = new Uint8Array(salt.length + passwordBuffer.length);
  combinedBuffer.set(salt);
  combinedBuffer.set(passwordBuffer, salt.length);

  // Hash the combined buffer
  const hashBuffer = await crypto.subtle.digest('SHA-256', combinedBuffer);
  return bufferToHex(hashBuffer);
}

// --- Main Worker Logic ---

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const { pathname } = new URL(request.url);

    // --- Handle all OPTIONS preflight requests ---
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // --- Handle GET for /api/messages ---
    if (request.method === 'GET' && pathname === '/api/messages') {
      try {
        const { results } = await env.DB.prepare('SELECT * FROM messages ORDER BY id DESC').all();
        return new Response(JSON.stringify(results), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      } catch (e) {
        // This is the catch block for GET /api/messages
        console.error("--- ERROR IN /api/messages ---");
        if (e instanceof Error) {
          console.error("Error Message: " + e.message);
        } else {
          console.error("Caught a non-Error value: " + String(e));
        }
        return new Response(e instanceof Error ? e.message : String(e), { status: 500, headers: corsHeaders });
      }
    }

    // --- Handle POST for /api/messages ---
    if (request.method === 'POST' && pathname === '/api/messages') {
      try {
        const message = await request.json<{ name: string; body: string }>();
        await env.DB.prepare('INSERT INTO messages (name, body) VALUES (?, ?)')
          .bind(message.name, message.body)
          .run();
        return new Response('Message added!', { status: 201, headers: corsHeaders });
      } catch (e) {
        // This is the catch block for POST /api/messages
        console.error("--- ERROR IN POST /api/messages ---");
        if (e instanceof Error) {
          console.error("Error Message: " + e.message);
        } else {
          console.error("Caught a non-Error value: " + String(e));
        }
        return new Response(e instanceof Error ? e.message : String(e), { status: 500, headers: corsHeaders });
      }
    }

    // --- Handle POST for /register ---
    if (request.method === 'POST' && pathname === '/register') {
      try {
        const { email, password } = await request.json<{ email: string; password: string }>();

        if (!email || !password) {
          return new Response('Email and password are required', { status: 400, headers: corsHeaders });
        }
        
        // 1. Generate a new random salt
        const salt = crypto.getRandomValues(new Uint8Array(16));
        
        // 2. Hash the password with the salt
        const passwordHash = await hashPassword(password, salt);
        
        // 3. Convert salt to hex to store in the DB
        const saltHex = bufferToHex(salt);

        // 4. Store the user with the HASH and SALT
        await env.DB.prepare(
          'INSERT INTO users (email, password_hash, salt) VALUES (?, ?, ?)'
        ).bind(email, passwordHash, saltHex).run();
          
        return new Response('User account created!', { status: 201, headers: corsHeaders });
        
      } catch (e) {
        // --- THIS IS THE CORRECT CATCH BLOCK FOR /register ---
        console.error("--- ERROR IN /register ---");
        
        // Safely log the error details
        let errorMessage = "An unknown error occurred";
        if (e instanceof Error) {
          console.error("Error Message: " + e.message);
          console.error("Error Stack: " + e.stack);
          errorMessage = e.message;
        } else {
          console.error("Caught a non-Error value: " + String(e));
          errorMessage = String(e);
        }
        
        // Check for the "UNIQUE constraint failed" error
        if (errorMessage.includes('UNIQUE constraint failed: users.email')) {
          return new Response('This email is already in use.', { status: 409, headers: corsHeaders });
        }
        
        // General error
        return new Response('Error creating account: ' + errorMessage, { status: 500, headers: corsHeaders });
      }
    }

    // --- 404 Not Found ---
    return new Response('Not found', { status: 404, headers: corsHeaders });
  },
};