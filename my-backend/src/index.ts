import { Hono } from 'hono';
import Stripe from 'stripe';
import jwt from '@tsndr/cloudflare-worker-jwt';

export interface Env {
  DB: D1Database;
  TUNNEL_STORE: KVNamespace; // <--- Added for Tunnel Storage
  STRIPE_API_KEY: string;
  STRIPE_WEBHOOK_SECRET: string;
  RESEND_API_KEY: string;
  JWT_SECRET: string;
}

// --- Crypto Helper Functions (Unchanged) ---
function bufferToHex(buffer: ArrayBuffer): string {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('');
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

// --- Custom CORS Middleware (Unchanged) ---
app.use('*', async (c, next) => {
  const allowedOrigins = ['https://www.stallmonitor.com', 'https://stallmonitor.com', 'null', '*'];
  const origin = c.req.header('Origin');
  if (c.req.method === 'OPTIONS') {
    if (origin && allowedOrigins.includes(origin)) {
      return new Response(null, {
        status: 204, headers: { /* CORS Headers */
          'Access-Control-Allow-Origin': origin,
          'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          'Access-Control-Max-Age': '86400',
        }
      });
    } else { return new Response('Forbidden - Invalid Origin', { status: 403 }); }
  }
  await next();
  if (origin && allowedOrigins.includes(origin) && c.res) { c.res.headers.set('Access-Control-Allow-Origin', origin); }
});

// --- JWT Verification Middleware ---
const authMiddleware = async (c: any, next: any) => {
  const authHeader = c.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  const token = authHeader.substring(7);
  try {
    const decoded = await jwt.verify(token, c.env.JWT_SECRET);
    if (!decoded) {
      return c.json({ error: 'Unauthorized' }, 401);
    }
    c.set('user', decoded);
    await next();
  } catch (e) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
};

// --- Handle POST for /register ---
app.post('/register', async (c) => {
  try {
    const { email, password, farm_name } = await c.req.json<{ email: string; password: string; farm_name: string }>();
    if (!email || !password || !farm_name) {
      return c.json({ error: 'Email, password, and farm name are required' }, 400);
    }
    if (!/^[a-zA-Z0-9\s-]+$/.test(farm_name) || farm_name.length < 3 || farm_name.length > 50) {
      return c.json({ error: 'Invalid farm name (3-50 chars, letters, numbers, spaces, hyphens only)' }, 400);
    }

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const passwordHash = await hashPassword(password, salt);
    const saltHex = bufferToHex(salt);

    await c.env.DB.prepare(
      'INSERT INTO users (email, password_hash, salt, farm_name) VALUES (?, ?, ?, ?)'
    ).bind(email, passwordHash, saltHex, farm_name).run();

    return c.json({ email: email, farm_name: farm_name, message: 'User account created!' }, 201);

  } catch (e: any) {
    console.error("--- ERROR IN /register ---", e);
    if (e instanceof Error && e.message.includes('UNIQUE constraint failed: users.email')) {
      return c.json({ error: 'This email is already in use.' }, 409);
    }
    if (e instanceof Error && e.message.includes('UNIQUE constraint failed: users.farm_name')) {
      return c.json({ error: 'That farm name is already taken.' }, 409);
    }
    return c.json({ error: 'Error creating account: ' + (e instanceof Error ? e.message : String(e)) }, 500);
  }
});

// --- Handle POST for /login ---
app.post('/login', async (c) => {
  try {
    const { identifier, password } = await c.req.json<{ identifier: string; password: string }>();
    console.log(`Login attempt for identifier: ${identifier}`);
    if (!identifier || !password) {
      return c.json({ error: 'Identifier (email or farm name) and password are required' }, 400);
    }

    const isEmail = identifier.includes('@');
    const query = isEmail
      ? 'SELECT email, password_hash, salt, farm_name FROM users WHERE email = ?'
      : 'SELECT email, password_hash, salt, farm_name FROM users WHERE farm_name = ?';

    const user = await c.env.DB.prepare(query)
      .bind(identifier)
      .first<{ email: string; password_hash: string; salt: string; farm_name: string | null }>();

    const corsHeader = { 'Access-Control-Allow-Origin': c.req.header('Origin') || '*' };

    if (!user) {
      return c.json({ error: 'Invalid credentials' }, 401, corsHeader);
    }

    const saltBuffer = hexToBuffer(user.salt);
    const storedHash = user.password_hash;
    const providedHash = await hashPassword(password, saltBuffer);

    if (providedHash === storedHash) {
      const token = await jwt.sign({
        email: user.email,
        farm_name: user.farm_name,
        exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 7) // 7 days
      }, c.env.JWT_SECRET);

      return c.json({ email: user.email, farm_name: user.farm_name, token: token, message: 'Login successful!' }, 200, corsHeader);
    } else {
      return c.json({ error: 'Invalid credentials' }, 401, corsHeader);
    }
  } catch (e: any) {
    console.error("--- ERROR IN /login ---", e);
    return c.json({ error: 'Error logging in: ' + (e instanceof Error ? e.message : String(e)) }, 500, { 'Access-Control-Allow-Origin': c.req.header('Origin') || '*' });
  }
});

// --- Handle POST for /api/create-checkout-session ---
app.post('/api/create-checkout-session', async (c) => {
  try {
    const { email, farm_name } = await c.req.json<{ email: string; farm_name: string }>();
    const stripe = new Stripe(c.env.STRIPE_API_KEY);
    const PRICE_ID = "price_1SG1n3CKer7QDo5DEf04QsgI";
    const YOUR_DOMAIN = 'https://www.stallmonitor.com';

    if (!email || !farm_name) {
      return c.json({ error: 'Email and farm name are required' }, 400);
    }

    const farmNameSlug = encodeURIComponent(farm_name);

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{ price: PRICE_ID, quantity: 1 }],
      mode: 'subscription',
      success_url: `${YOUR_DOMAIN}/setup.html?farm=${farmNameSlug}&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${YOUR_DOMAIN}`,
      customer_email: email,
    });

    if (!session.url) {
      throw new Error('Could not create Stripe checkout session.');
    }

    return c.json({ checkoutUrl: session.url });

  } catch (e: any) {
    console.error("--- CATCH BLOCK /api/create-checkout-session ---", e);
    return c.json({ error: 'Error creating checkout session: ' + (e instanceof Error ? e.message : String(e)) }, 500);
  }
});

// --- Handle POST for /api/cancel-subscription ---
app.post('/api/cancel-subscription', authMiddleware, async (c) => {
  try {
    const userFromToken = c.get('user');
    const email = userFromToken.email;

    if (!email) {
      return c.json({ error: 'Email not found in token' }, 400);
    }

    const dbUser = await c.env.DB.prepare(
      'SELECT stripe_subscription_id FROM users WHERE email = ?'
    ).bind(email).first<{ stripe_subscription_id: string }>();

    if (!dbUser || !dbUser.stripe_subscription_id) {
      return c.json({ error: 'Active subscription not found for this email.' }, 404);
    }

    const stripe = new Stripe(c.env.STRIPE_API_KEY);
    await stripe.subscriptions.update(dbUser.stripe_subscription_id, {
      cancel_at_period_end: true,
    });

    await c.env.DB.prepare(
      'UPDATE users SET stripe_subscription_status = ? WHERE email = ?'
    ).bind('canceling', email).run();

    return c.json({ message: 'Your subscription has been scheduled for cancellation at the end of the current billing period.' });

  } catch (e: any) {
    console.error("--- ERROR IN /api/cancel-subscription ---", e);
    return c.json({ error: 'Error canceling subscription: ' + (e instanceof Error ? e.message : String(e)) }, 500);
  }
});

// --- Handle POST for /api/contact ---
app.post('/api/contact', async (c) => {
  try {
    const { name, email, message } = await c.req.json<{ name: string; email: string; message: string }>();
    if (!name || !email || !message) {
      return c.json({ error: 'Name, email, and message are required' }, 400);
    }

    const SENDER_EMAIL = 'contact@stallmonitor.com';
    const RESEND_API_KEY = c.env.RESEND_API_KEY;

    const mailPayload = {
      from: `Stall Monitor Contact Form <${SENDER_EMAIL}>`,
      to: SENDER_EMAIL,
      subject: `New Contact Form Submission from ${name}`,
      text: `Name: ${name}\nEmail: ${email}\nMessage: ${message}`,
    };

    const mailResponse = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${RESEND_API_KEY}`,
      },
      body: JSON.stringify(mailPayload),
    });

    if (!mailResponse.ok) {
      return c.json({ error: 'Failed to send email via Resend.' }, 500);
    }

    return c.json({ message: 'Message received successfully and email sent!' });

  } catch (e: any) {
    console.error("--- ERROR IN /api/contact ---", e);
    return c.json({ error: 'Error processing contact form: ' + (e instanceof Error ? e.message : String(e)) }, 500);
  }
});

// --- NEW: Update Tunnel URL (Called by Python App) ---
app.post('/api/update-tunnel', async (c) => {
  try {
    const { farm_name, tunnel_url } = await c.req.json<{ farm_name: string; tunnel_url: string }>();

    if (!farm_name || !tunnel_url) {
      return c.json({ error: 'farm_name and tunnel_url are required' }, 400);
    }

    console.log(`Updating tunnel for ${farm_name} to ${tunnel_url}`);

    // Save to Cloudflare KV
    await c.env.TUNNEL_STORE.put(`tunnel_${farm_name}`, tunnel_url);

    return c.json({ status: 'saved', url: tunnel_url });
  } catch (e: any) {
    console.error("--- ERROR IN /api/update-tunnel ---", e);
    return c.json({ error: 'Failed to save tunnel URL: ' + (e instanceof Error ? e.message : String(e)) }, 500);
  }
});

// --- NEW: Get Tunnel URL (Called by Dashboard) ---
app.get('/api/get-tunnel', async (c) => {
  try {
    const farm_name = c.req.query('farm');

    if (!farm_name) {
      return c.json({ error: 'farm query param is required' }, 400);
    }

    // Read from Cloudflare KV
    const tunnel_url = await c.env.TUNNEL_STORE.get(`tunnel_${farm_name}`);

    return c.json({ tunnel_url: tunnel_url || null });
  } catch (e: any) {
    console.error("--- ERROR IN /api/get-tunnel ---", e);
    return c.json({ error: 'Failed to get tunnel URL: ' + (e instanceof Error ? e.message : String(e)) }, 500);
  }
});

// --- Handle POST for /webhook ---
app.post('/webhook', async (c) => {
  const stripe = new Stripe(c.env.STRIPE_API_KEY);
  const signature = c.req.header('stripe-signature');
  const body = await c.req.text();

  try {
    const event = await stripe.webhooks.constructEventAsync(
      body,
      signature!,
      c.env.STRIPE_WEBHOOK_SECRET
    );

    let subscription: Stripe.Subscription;
    let customerEmail: string | null;

    switch (event.type) {
      case 'checkout.session.completed':
        const session = event.data.object as Stripe.Checkout.Session;
        customerEmail = session.customer_email;
        if (session.subscription && customerEmail) {
          await c.env.DB.prepare(
            'UPDATE users SET stripe_subscription_id = ?, stripe_subscription_status = ? WHERE email = ?'
          ).bind(session.subscription, 'active', customerEmail).run();
        }
        break;

      case 'customer.subscription.updated':
        subscription = event.data.object as Stripe.Subscription;
        const customer = await stripe.customers.retrieve(subscription.customer as string) as Stripe.Customer;
        customerEmail = customer.email;
        if (customerEmail) {
          const newStatus = subscription.cancel_at_period_end ? 'canceling' : subscription.status;
          await c.env.DB.prepare(
            'UPDATE users SET stripe_subscription_status = ? WHERE stripe_subscription_id = ?'
          ).bind(newStatus, subscription.id).run();
        }
        break;

      case 'customer.subscription.deleted':
        subscription = event.data.object as Stripe.Subscription;
        await c.env.DB.prepare(
          'UPDATE users SET stripe_subscription_status = ? WHERE stripe_subscription_id = ?'
        ).bind('canceled', subscription.id).run();
        break;
    }

    return c.json({ received: true });
  } catch (e: any) {
    console.error("--- ERROR IN /webhook ---", e);
    return c.json({ error: 'Error processing webhook: ' + (e instanceof Error ? e.message : String(e)) }, 400);
  }
});

// --- Handle GET for /check-subscription ---
app.get('/check-subscription/:identifier', async (c) => {
  try {
    const identifier = c.req.param('identifier');

    if (!identifier) {
      return c.json({ error: 'Identifier (email or farm name) is required' }, 400);
    }

    const isEmail = identifier.includes('@');
    const query = isEmail
      ? 'SELECT stripe_subscription_id, stripe_subscription_status FROM users WHERE email = ?'
      : 'SELECT stripe_subscription_id, stripe_subscription_status FROM users WHERE farm_name = ?';

    const user = await c.env.DB.prepare(query)
      .bind(identifier)
      .first<{ stripe_subscription_id: string; stripe_subscription_status: string }>();

    if (!user) {
      return c.json({ error: 'User not found' }, 404);
    }

    const isActive = user.stripe_subscription_status === 'active';
    return c.json({ subscription_active: isActive });

  } catch (e: any) {
    console.error("--- ERROR IN /check-subscription ---", e);
    return c.json({ error: 'Error checking subscription: ' + (e instanceof Error ? e.message : String(e)) }, 500);
  }
});

// --- Subdomain Proxy Logic ---
app.all('*', async (c) => {
  const url = new URL(c.req.url);
  const hostname = url.hostname; // e.g., "myfarm.stallmonitor.com" or "stallmonitor.com"

  // Extract subdomain
  // This logic assumes you are using exactly "something.stallmonitor.com" or "something.your-worker.workers.dev"
  const parts = hostname.split('.');

  // Basic check: if we have more than 2 parts (e.g. top.domain.com), we might have a subdomain
  // Adjust logic if you use a 2-part TLD like ".co.uk"
  let subdomain = '';
  if (parts.length > 2) {
    // If testing on localhost or workers.dev, the logic might differ.
    // robust way for ".stallmonitor.com":
    if (hostname.endsWith('stallmonitor.com')) {
      // parts: ["myfarm", "stallmonitor", "com"] -> subdomain "myfarm"
      // parts: ["www", "stallmonitor", "com"] -> subdomain "www" (ignore?)
      if (parts.length === 3) {
        subdomain = parts[0];
      }
    }
  }

  // If no subdomain or it's 'www' or 'api' or 'my-backend', return 404 or just fall through
  if (!subdomain || subdomain === 'www' || subdomain === 'api' || subdomain === 'my-backend') {
    return c.json({ error: 'Not Found' }, 404);
  }

  // 1. Lookup the tunnel URL
  const tunnelUrl = await c.env.TUNNEL_STORE.get(`tunnel_${subdomain}`);

  if (!tunnelUrl) {
    return new Response(`Farm "${subdomain}" not found or offline.`, { status: 404 });
  }

  // 2. Proxy the request
  try {
    // Construct the new URL
    // existing: https://myfarm.stallmonitor.com/assets/icon.png?foo=bar
    // target:   https://<tunnel-id>.trycloudflare.com/assets/icon.png?foo=bar

    // tunnelUrl is stored as "https://<tunnel-id>.trycloudflare.com"
    const targetUrl = new URL(tunnelUrl);
    targetUrl.pathname = url.pathname;
    targetUrl.search = url.search;

    // Create a new request to send to the tunnel
    const proxyReq = new Request(targetUrl.toString(), {
      method: c.req.method,
      headers: c.req.header(), // Pass through original headers
      body: c.req.raw.body,    // Pass through body (if POST/PUT)
      redirect: 'follow'
    });

    // Important: Cloudflare Tunnels might expect the Host header to match the tunnel domain,
    // NOT "myfarm.stallmonitor.com".
    // We overwrite the Host header to match the tunnel's hostname.
    proxyReq.headers.set('Host', targetUrl.hostname);

    const response = await fetch(proxyReq);

    // FIX: For WebSockets (status 101), we must return the response directly
    // Wrapping it in `new Response()` breaks the WebSocket upgrade flow in Workers.
    if (response.status === 101) {
      return response;
    }

    // Create a new response to return to the user
    // We need to recreate it to ensure it's mutable if needed, though usually we can just return it.
    // However, if we need to modify headers (like CORS or Cookies), we do it safely here.
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers
    });

  } catch (e: any) {
    console.error(`Proxy error for ${subdomain}:`, e);
    return new Response('Error connecting to farm dashboard.', { status: 502 });
  }
});

export default app;