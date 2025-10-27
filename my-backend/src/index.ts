import { Hono } from 'hono';
import { cors } from 'hono/cors'; // Keep this import, even if we remove the middleware later

export interface Env {
  DB: D1Database;
  STRIPE_API_KEY: string;
}

// --- Crypto Helper Functions ---
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

// --- Initialize Hono ---
const app = new Hono<{ Bindings: Env }>();

// --- Apply Custom CORS Middleware ---
// Using the version that allows both www and root domain
app.use('*', async (c, next) => {
  const allowedOrigins = [
      'https://www.stallmonitor.com',
      'https://stallmonitor.com'
  ];
  const origin = c.req.header('Origin');

  if (c.req.method === 'OPTIONS') {
    if (origin && allowedOrigins.includes(origin)) {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': origin,
          'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Max-Age': '86400',
        },
      });
    } else {
      console.log(`OPTIONS request blocked. Origin: ${origin}`);
      return new Response('Forbidden - Invalid Origin', { status: 403 });
    }
  }

  await next(); // Proceed to route handler

  // Add headers AFTER route handler completes
  if (origin && allowedOrigins.includes(origin)) {
     if (c.res) {
        c.res.headers.set('Access-Control-Allow-Origin', origin);
     } else {
        console.warn("Middleware: c.res was undefined after next(). Creating default response.");
        c.res = new Response("Internal processing error", { status: 500 });
        c.res.headers.set('Access-Control-Allow-Origin', origin);
     }
  } else if (c.res && origin) {
     console.log(`Non-OPTIONS request from disallowed origin: ${origin}`);
  }
});


// --- Handle POST for /register ---
app.post('/register', async (c) => {
  try {
    const { email, password } = await c.req.json<{ email: string; password: string }>();
    if (!email || !password) {
      return c.json({ error: 'Email and password are required' }, 400);
    }
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const passwordHash = await hashPassword(password, salt);
    const saltHex = bufferToHex(salt);
    await c.env.DB.prepare('INSERT INTO users (email, password_hash, salt) VALUES (?, ?, ?)')
      .bind(email, passwordHash, saltHex).run();
    return c.json({ email: email, message: 'User account created!' }, 201);
  } catch (e: any) {
    console.error("--- ERROR IN /register ---", e.message);
    if (e.message.includes('UNIQUE constraint failed: users.email')) {
      return c.json({ error: 'This email is already in use.' }, 409);
    }
    return c.json({ error: 'Error creating account: ' + e.message }, 500);
  }
});

// --- Handle POST for /login ---
app.post('/login', async (c) => {
  try {
    const { email, password } = await c.req.json<{ email: string; password: string }>();
    const user = await c.env.DB.prepare('SELECT password_hash, salt, farm_name FROM users WHERE email = ?')
      .bind(email).first<{ password_hash: string; salt: string; farm_name: string | null }>();

    if (!user) {
      // Create the response first
      const errorResponse = c.json({ error: 'Invalid email or password' }, 401);
      // Middleware should add CORS, but we keep this as backup
      errorResponse.headers.set('Access-Control-Allow-Origin', 'https://www.stallmonitor.com');
      return errorResponse;
    }
    const saltBuffer = hexToBuffer(user.salt);
    const storedHash = user.password_hash;
    const providedHash = await hashPassword(password, saltBuffer);

    if (providedHash === storedHash) {
      // SUCCESS!
      const successResponse = c.json({ farm_name: user.farm_name, message: 'Login successful!' }, 200);
       // Middleware should add CORS, but we keep this as backup
      successResponse.headers.set('Access-Control-Allow-Origin', 'https://www.stallmonitor.com');
      return successResponse;
    } else {
      // Password mismatch
      const errorResponse = c.json({ error: 'Invalid email or password' }, 401);
       // Middleware should add CORS, but we keep this as backup
      errorResponse.headers.set('Access-Control-Allow-Origin', 'https://www.stallmonitor.com');
      return errorResponse;
    }
  } catch (e: any) {
    console.error("--- ERROR IN /login ---", e.message);
    const errorResponse = c.json({ error: 'Error logging in: ' + e.message }, 500);
     // Middleware should add CORS, but we keep this as backup
    errorResponse.headers.set('Access-Control-Allow-Origin', 'https://www.stallmonitor.com');
    return errorResponse;
  }
});


// --- Handle POST for /api/create-checkout-session (WITH ADDED LOGGING) ---
app.post('/api/create-checkout-session', async (c) => {
  try {
    console.log("Received request for /api/create-checkout-session"); // <-- ADDED
    const { email } = await c.req.json<{ email: string }>();
    const stripe = c.env.STRIPE_API_KEY;
    const PRICE_ID = "price_1SG1n3CKer7QDo5DEf04QsgI"; // Double-check this ID!
    const YOUR_DOMAIN = 'https://www.stallmonitor.com';

    if (!email) { // <-- ADDED check
        console.error("Email missing from request body");
        return c.json({ error: 'Email is required' }, 400);
    }
    if (!stripe) { // <-- ADDED check
        console.error("Stripe API Key secret is missing in worker environment");
        return c.json({ error: 'Server configuration error [Stripe Key Missing]' }, 500);
    }

    console.log(`Creating Stripe session for email: ${email} with Price ID: ${PRICE_ID}`); // <-- ADDED

    // Create a Stripe Checkout Session
    const sessionResponse = await fetch('https://api.stripe.com/v1/checkout/sessions', {
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
        'customer_email': email,
      }),
    });

    console.log(`Stripe API response status: ${sessionResponse.status}`); // <-- ADDED

    // IMPORTANT: Clone the response to read it multiple times if needed
    const responseClone = sessionResponse.clone();
    const sessionData = await sessionResponse.json<{ url?: string; error?: any }>();

    // More detailed error checking for Stripe response
    if (!sessionResponse.ok || sessionData.error) {
        console.error("Stripe API Error Response Body:", JSON.stringify(sessionData, null, 2)); // <-- ADDED log of Stripe's error
        // Attempt to read body as text if JSON parsing failed initially or error exists
        let errorBodyText = sessionData.error?.message || `Stripe API responded with status ${sessionResponse.status}`;
        if (!sessionData.error) {
             try { errorBodyText = await responseClone.text(); } catch {} // Safely read text
        }
        console.error("Full Stripe Error Response Text:", errorBodyText); // <-- ADDED
        throw new Error(sessionData.error?.message || `Stripe API responded with status ${sessionResponse.status}`);
    }
    if (!sessionData.url) {
      console.error("Stripe API did not return a URL. Response Body:", JSON.stringify(sessionData, null, 2)); // <-- ADDED log
      throw new Error("Could not create Stripe session URL.");
    }

    console.log("Successfully created Stripe session. URL:", sessionData.url); // <-- ADDED
    return c.json({ checkoutUrl: sessionData.url }); // This should now send 200 OK

  } catch (e: any) {
    // Log the error caught by the main try...catch
    console.error("--- CATCH BLOCK in /api/create-checkout-session ---", e.message, e.stack);
    // Ensure the response has CORS headers even on error
    const errorResponse = c.json({ error: 'Error creating checkout session: ' + e.message }, 500);
    // Middleware should add CORS, but keep backup manual header
    errorResponse.headers.set('Access-Control-Allow-Origin', 'https://www.stallmonitor.com');
    return errorResponse;
  }
});


// --- Handle POST for /api/set-farm-name ---
app.post('/api/set-farm-name', async (c) => {
  try {
    const { email, farm_name } = await c.req.json<{ email: string, farm_name: string }>();
    if (!email || !farm_name) {
       return c.json({ error: 'Email and farm name are required' }, 400);
    }
    await c.env.DB.prepare('UPDATE users SET farm_name = ? WHERE email = ?')
      .bind(farm_name, email).run();
    return c.json({ farm_name: farm_name, message: 'Farm name set!' });
  } catch (e: any) {
    console.error("--- ERROR IN /api/set-farm-name ---", e.message, e.stack);
    if (e.message.includes('UNIQUE constraint failed: users.farm_name')) {
      return c.json({ error: 'That farm name is already taken.' }, 409);
    }
    return c.json({ error: 'Error setting farm name: ' + e.message }, 500);
  }
});

// --- Fallback Route (404 Not Found) ---
app.notFound((c) => {
  // Middleware adds CORS headers
  return c.json({ error: 'Not Found' }, 404);
})

export default app;