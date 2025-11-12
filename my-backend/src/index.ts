import { Hono } from 'hono';
import Stripe from 'stripe';

export interface Env {
  DB: D1Database;
  STRIPE_API_KEY: string;
  STRIPE_WEBHOOK_SECRET: string;
  RESEND_API_KEY: string;
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
      return new Response(null, { status: 204, headers: { /* CORS Headers */
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Max-Age': '86400',
       }});
    } else { return new Response('Forbidden - Invalid Origin', { status: 403 }); }
  }
  await next();
  if (origin && allowedOrigins.includes(origin) && c.res) { c.res.headers.set('Access-Control-Allow-Origin', origin); }
});

// --- Handle POST for /register (UPDATED) ---
// Now accepts and saves farm_name
app.post('/register', async (c) => {
  try {
    const { email, password, farm_name } = await c.req.json<{ email: string; password: string; farm_name: string }>(); // Added farm_name
    if (!email || !password || !farm_name) { // Check all three
      return c.json({ error: 'Email, password, and farm name are required' }, 400);
    }
    // Basic validation for farm name (adjust as needed)
    if (!/^[a-zA-Z0-9\s-]+$/.test(farm_name) || farm_name.length < 3 || farm_name.length > 50) {
        return c.json({ error: 'Invalid farm name (3-50 chars, letters, numbers, spaces, hyphens only)' }, 400);
    }

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const passwordHash = await hashPassword(password, salt);
    const saltHex = bufferToHex(salt);

    // Insert all data including farm_name
    await c.env.DB.prepare(
      'INSERT INTO users (email, password_hash, salt, farm_name) VALUES (?, ?, ?, ?)'
    ).bind(email, passwordHash, saltHex, farm_name).run(); // Added farm_name binding

    // Return email AND farm_name
    return c.json({ email: email, farm_name: farm_name, message: 'User account created!' }, 201);

  } catch (e: any) {
    console.error("--- ERROR IN /register ---", e);
    if (e instanceof Error && e.message.includes('UNIQUE constraint failed: users.email')) {
      return c.json({ error: 'This email is already in use.' }, 409);
    }
    if (e instanceof Error && e.message.includes('UNIQUE constraint failed: users.farm_name')) { // Check for farm name conflict
      return c.json({ error: 'That farm name is already taken.' }, 409);
    }
    return c.json({ error: 'Error creating account: ' + (e instanceof Error ? e.message : String(e)) }, 500);
  }
});

// --- Handle POST for /login (UPDATED) ---
// Now accepts 'identifier' which can be email or farm_name
app.post('/login', async (c) => {
  try {
    const { identifier, password } = await c.req.json<{ identifier: string; password: string }>(); // Changed 'email' to 'identifier'
    console.log(`Login attempt for identifier: ${identifier}`);
    if (!identifier || !password) {
        console.log('Missing identifier or password');
        return c.json({ error: 'Identifier (email or farm name) and password are required' }, 400);
    }

    // Determine if identifier is email or farm name (simple check)
    const isEmail = identifier.includes('@');
    const query = isEmail
      ? 'SELECT email, password_hash, salt, farm_name FROM users WHERE email = ?'
      : 'SELECT email, password_hash, salt, farm_name FROM users WHERE farm_name = ?';

    console.log(`Querying database with: ${query} for identifier: ${identifier}`);
    const user = await c.env.DB.prepare(query)
      .bind(identifier) // Bind the identifier
      .first<{ email: string; password_hash: string; salt: string; farm_name: string | null }>();

    console.log(`Database query result for ${identifier}: ${user ? 'User found' : 'User not found'}`);

    // Manual CORS headers (keep as backup)
    const corsHeader = { 'Access-Control-Allow-Origin': c.req.header('Origin') || '*' };

    if (!user) {
      return c.json({ error: 'Invalid credentials' }, 401, corsHeader); // Generic error
    }

    const saltBuffer = hexToBuffer(user.salt);
    const storedHash = user.password_hash;
    const providedHash = await hashPassword(password, saltBuffer);

    console.log(`Stored Salt: ${user.salt}`);
    console.log(`Stored Hash: ${storedHash}`);
    console.log(`Provided Hash: ${providedHash}`);

    if (providedHash === storedHash) {
      // SUCCESS! Return email AND farm_name
      return c.json({ email: user.email, farm_name: user.farm_name, message: 'Login successful!' }, 200, corsHeader);
    } else {
      // Password mismatch
      console.log('Password mismatch');
      return c.json({ error: 'Invalid credentials' }, 401, corsHeader); // Generic error
    }
  } catch (e: any) {
    console.error("--- ERROR IN /login ---", e);
    return c.json({ error: 'Error logging in: ' + (e instanceof Error ? e.message : String(e)) }, 500, { 'Access-Control-Allow-Origin': c.req.header('Origin') || '*' });
  }
});

// --- Handle POST for /api/create-checkout-session (UPDATED) ---
// Now looks up farm_name to set success_url
app.post('/api/create-checkout-session', async (c) => {
  try {
    console.log("Received request for /api/create-checkout-session");
    const { email, farm_name } = await c.req.json<{ email: string; farm_name: string }>();
    const stripe = new Stripe(c.env.STRIPE_API_KEY);
    const PRICE_ID = "price_1SG1n3CKer7QDo5DEf04QsgI"; // Your Price ID
    const YOUR_DOMAIN = 'https://www.stallmonitor.com'; // Use your actual domain variable

    if (!email || !farm_name) { 
      return c.json({ error: 'Email and farm name are required' }, 400); 
    }

    // --- Use the farm name from the request body ---
    const farmNameSlug = encodeURIComponent(farm_name); // Ensure URL safety

    console.log(`Creating Stripe session for email: ${email}, redirecting to farm: ${farm_name}`);

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

    console.log("Successfully created Stripe session. URL:", session.url);
    return c.json({ checkoutUrl: session.url }); // Send 200 OK

  } catch (e: any) {
    console.error("--- CATCH BLOCK /api/create-checkout-session ---", e);
    return c.json({ error: 'Error creating checkout session: ' + (e instanceof Error ? e.message : String(e)) }, 500);
  }
});

// --- REMOVED /api/set-farm-name endpoint ---

// --- Handle POST for /api/cancel-subscription (NEW) ---
app.post('/api/cancel-subscription', async (c) => {
  try {
    const { email } = await c.req.json<{ email: string }>();
    if (!email) {
      return c.json({ error: 'Email is required' }, 400);
    }

    console.log(`Cancellation request for email: ${email}`);

    // 1. Find the user and their subscription ID
    const user = await c.env.DB.prepare(
      'SELECT stripe_subscription_id FROM users WHERE email = ?'
    ).bind(email).first<{ stripe_subscription_id: string }>();

    if (!user || !user.stripe_subscription_id) {
      return c.json({ error: 'Active subscription not found for this email.' }, 404);
    }

    // 2. Initialize Stripe and cancel the subscription
    const stripe = new Stripe(c.env.STRIPE_API_KEY);
    await stripe.subscriptions.update(user.stripe_subscription_id, {
      cancel_at_period_end: true,
    });

    console.log(`Subscription ${user.stripe_subscription_id} for ${email} scheduled for cancellation.`);

    // 3. The webhook will handle the DB update when the subscription is officially canceled.
    // We can optionally update the status to 'canceling' here if we want.
    await c.env.DB.prepare(
      'UPDATE users SET stripe_subscription_status = ? WHERE email = ?'
    ).bind('canceling', email).run();


    return c.json({ message: 'Your subscription has been scheduled for cancellation at the end of the current billing period.' });

  } catch (e: any) {
    console.error("--- ERROR IN /api/cancel-subscription ---", e);
    return c.json({ error: 'Error canceling subscription: ' + (e instanceof Error ? e.message : String(e)) }, 500);
  }
});

// --- Handle POST for /api/contact (NEW) ---
app.post('/api/contact', async (c) => {
  try {
    const { name, email, message } = await c.req.json<{ name: string; email: string; message: string }>();
    if (!name || !email || !message) {
      return c.json({ error: 'Name, email, and message are required' }, 400);
    }

    console.log('--- CONTACT FORM SUBMISSION ---');
    console.log(`Name: ${name}`);
    console.log(`Email: ${email}`);
    console.log(`Message: ${message}`);
    console.log('-----------------------------');

    const SENDER_EMAIL = 'contact@stallmonitor.com'; // Replace with your sender email
    const RESEND_API_KEY = c.env.RESEND_API_KEY; // Assuming you set this in your Worker secrets

    const mailPayload = {
      from: `Stall Monitor Contact Form <${SENDER_EMAIL}>`,
      to: SENDER_EMAIL,
      subject: `New Contact Form Submission from ${name}`,
      text: `Name: ${name}\nEmail: ${email}\nMessage: ${message}`,
    };

    try {
      const mailResponse = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${RESEND_API_KEY}`,
        },
        body: JSON.stringify(mailPayload),
      });

      if (!mailResponse.ok) {
        const errorText = await mailResponse.text();
        console.error('Resend API error:', mailResponse.status, errorText);
        return c.json({ error: 'Failed to send email via Resend.' }, 500);
      }

      console.log('Email sent successfully via Resend.');
      return c.json({ message: 'Message received successfully and email sent!' });

    } catch (mailError) {
      console.error('Error sending email via Resend:', mailError);
      return c.json({ error: 'Error sending email.' }, 500);
    }

  } catch (e: any) {
    console.error("--- ERROR IN /api/contact ---", e);
    return c.json({ error: 'Error processing contact form: ' + (e instanceof Error ? e.message : String(e)) }, 500);
  }
});


// --- Handle POST for /webhook (EXPANDED) ---
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
          console.log(`Webhook: Activated subscription for ${customerEmail}`);
        }
        break;

      case 'customer.subscription.updated':
        subscription = event.data.object as Stripe.Subscription;
        // The customer ID is on the subscription object
        const customer = await stripe.customers.retrieve(subscription.customer as string) as Stripe.Customer;
        customerEmail = customer.email;
        if (customerEmail) {
            const newStatus = subscription.cancel_at_period_end ? 'canceling' : subscription.status;
            await c.env.DB.prepare(
                'UPDATE users SET stripe_subscription_status = ? WHERE stripe_subscription_id = ?'
            ).bind(newStatus, subscription.id).run();
            console.log(`Webhook: Updated subscription for ${customerEmail} to status ${newStatus}`);
        }
        break;

      case 'customer.subscription.deleted':
        subscription = event.data.object as Stripe.Subscription;
        // When a subscription is deleted, its status is 'canceled'.
        await c.env.DB.prepare(
          'UPDATE users SET stripe_subscription_status = ? WHERE stripe_subscription_id = ?'
        ).bind('canceled', subscription.id).run();
        console.log(`Webhook: Canceled subscription ${subscription.id}`);
        break;
        
      default:
        console.log(`Webhook: Unhandled event type ${event.type}`);
    }

    return c.json({ received: true });
  } catch (e: any) {
    console.error("--- ERROR IN /webhook ---", e);
    return c.json({ error: 'Error processing webhook: ' + (e instanceof Error ? e.message : String(e)) }, 400); // Use 400 for webhook errors
  }
});

// --- Handle GET for /check-subscription (NEW) ---
app.get('/check-subscription/:identifier', async (c) => {
  try {
    const encodedIdentifier = c.req.param('identifier');
    // Note: The identifier from the path is already decoded by Hono.
    // No need for decodeURIComponent.
    const identifier = encodedIdentifier; 

    console.log(`Checking subscription for identifier: ${identifier}`);

    if (!identifier) {
      return c.json({ error: 'Identifier (email or farm name) is required' }, 400);
    }

    const isEmail = identifier.includes('@');
    const query = isEmail
      ? 'SELECT stripe_subscription_id, stripe_subscription_status FROM users WHERE email = ?'
      : 'SELECT stripe_subscription_id, stripe_subscription_status FROM users WHERE farm_name = ?';

    console.log(`Querying database with: ${query} for identifier: ${identifier}`);
    const user = await c.env.DB.prepare(query)
      .bind(identifier)
      .first<{ stripe_subscription_id: string; stripe_subscription_status: string }>(); // Corrected type

    console.log(`Database query result for ${identifier}: ${user ? 'User found' : 'User not found'}`);

    if (!user) {
      return c.json({ error: 'User not found' }, 404);
    }

    const isActive = user.stripe_subscription_status === 'active';
    console.log(`Subscription status for ${identifier}: ${isActive ? 'active' : 'inactive'}`);
    return c.json({ subscription_active: isActive });

  } catch (e: any) { // <-- FIX: ADDED CATCH BLOCK
    console.error("--- ERROR IN /check-subscription ---", e);
    return c.json({ error: 'Error checking subscription: ' + (e instanceof Error ? e.message : String(e)) }, 500);
  }
}); // <-- FIX: ADDED CLOSING FOR app.get

// --- Fallback Route (404 Not Found) ---
app.notFound((c) => {
  return c.json({ error: 'Not Found' }, 404); // Middleware adds CORS
});

export default app;
// <-- FIX: REMOVED EXTRA '}' FROM END OF FILE