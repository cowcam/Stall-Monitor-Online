// --- This is the complete src/index.ts file ---

import { Hono } from 'hono';
import { cors } from 'hono/cors';

export interface Env {
  DB: D1Database;
  STRIPE_API_KEY: string;
}

// --- Crypto Helper Functions (Unchanged) ---
function bufferToHex(buffer: ArrayBuffer): string {
  return [...new Uint8Array(buffer)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
function hexToBuffer(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}
async function hashPassword(password: string, salt: Uint8Array): Promise<string> {
  const passwordBuffer = new TextEncoder().encode(password);
  const combinedBuffer = new Uint8Array(salt.length + passwordBuffer.length);
  combinedBuffer.set(salt);
  combinedBuffer.set(passwordBuffer, salt.length);
  const hashBuffer = await crypto.subtle.digest('SHA-256', combinedBuffer);
  return bufferToHex(hashBuffer);
}

// --- Initialize Hono (a lightweight router) ---
const app = new Hono<{ Bindings: Env }>();

// --- Add CORS Middleware ---
app.use(
  '/*',
  cors({
    origin: 'https://www.stallmonitor.com',
    allowMethods: ['POST', 'GET', 'OPTIONS'],
    allowHeaders: ['Content-Type'],
  })
);

// --- Handle POST for /register (Updated) ---
// We now return the user's email so the frontend knows who they are
app.post('/register', async (c) => {
  try {
    const { email, password } = await c.req.json<{ email: string; password: string }>();
    if (!email || !password) {
      return c.json({ error: 'Email and password are required' }, 400);
    }
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const passwordHash = await hashPassword(password, salt);
    const saltHex = bufferToHex(salt);

    await c.env.DB.prepare(
      'INSERT INTO users (email, password_hash, salt) VALUES (?, ?, ?)'
    ).bind(email, passwordHash, saltHex).run();
    
    // Return the user's email on success
    return c.json({ email: email, message: 'User account created!' }, 201);
  } catch (e: any) {
    console.error("--- ERROR IN /register ---", e.message);
    if (e.message.includes('UNIQUE constraint failed: users.email')) {
      return c.json({ error: 'This email is already in use.' }, 409);
    }
    return c.json({ error: 'Error creating account: ' + e.message }, 500);
  }
});

// --- Handle POST for /login (Updated) ---
// Now returns the user's farm_name (or null)
app.post('/login', async (c) => {
  try {
    const { email, password } = await c.req.json<{ email: string; password: string }>();

    const user = await c.env.DB.prepare(
      'SELECT password_hash, salt, farm_name FROM users WHERE email = ?'
    ).bind(email).first<{ password_hash: string; salt: string; farm_name: string | null }>();

    if (!user) {
      return c.json({ error: 'Invalid email or password' }, 401);
    }

    const saltBuffer = hexToBuffer(user.salt);
    const storedHash = user.password_hash;
    const providedHash = await hashPassword(password, saltBuffer);

    if (providedHash === storedHash) {
      // SUCCESS! Return the farm_name.
      return c.json({ farm_name: user.farm_name, message: 'Login successful!' });
    } else {
      return c.json({ error: 'Invalid email or password' }, 401);
    }
  } catch (e: any) {
    console.error("--- ERROR IN /login ---", e.message);
    return c.json({ error: 'Error logging in: ' + e.message }, 500);
  }
});

// --- NEW: Handle POST for /api/create-checkout-session ---
app.post('/api/create-checkout-session', async (c) => {
  try {
    const { email } = await c.req.json<{ email: string }>();
    const stripe = c.env.STRIPE_API_KEY;

    // This is your Price ID from the Stripe Dashboard (e.g., price_1P...)
    const PRICE_ID = "price_1SG1n3CKer7QDo5DEf04QsgI";
    const YOUR_DOMAIN = 'https://www.stallmonitor.com';

    // Create a Stripe Checkout Session
    const session = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${stripe}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        'payment_method_types[]': 'card',
        'line_items[][price]': PRICE_ID,
        'line_items[][quantity]': '1',
        'mode': 'subscription',
        'success_url': `${YOUR_DOMAIN}/create-farm?session_id={CHECKOUT_SESSION_ID}`,
        'cancel_url': `${YOUR_DOMAIN}`,
        'customer_email': email, // Pre-fill the user's email
      }),
    });

    const sessionData = await session.json<{ url: string }>();
    return c.json({ checkoutUrl: sessionData.url });

  } catch (e: any) {
    console.error("--- ERROR IN /api/create-checkout-session ---", e.message);
    return c.json({ error: 'Error creating checkout session: ' + e.message }, 500);
  }
});

// --- NEW: Handle POST for /api/set-farm-name ---
app.post('/api/set-farm-name', async (c) => {
  try {
    const { email, farm_name } = await c.req.json<{ email: string, farm_name: string }>();
    
    // We should also check if the farm_name is unique
    await c.env.DB.prepare(
      'UPDATE users SET farm_name = ? WHERE email = ?'
    ).bind(farm_name, email).run();
    
    return c.json({ farm_name: farm_name, message: 'Farm name set!' });
  } catch (e: any) {
    console.error("--- ERROR IN /api/set-farm-name ---", e.message);
    if (e.message.includes('UNIQUE constraint failed: users.farm_name')) {
      return c.json({ error: 'That farm name is already taken.' }, 409);
    }
    return c.json({ error: 'Error setting farm name: ' + e.message }, 500);
  }
});

export default app;