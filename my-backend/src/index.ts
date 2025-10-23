// Define the 'Env' interface to tell TypeScript about our D1 database
export interface Env {
	DB: D1Database;
}

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		// Get the URL and split up the path
		const { pathname } = new URL(request.url);

		// Handle GET requests to "/api/messages"
		if (request.method === 'GET' && pathname === '/api/messages') {
			try {
				// 1. Find all messages in the database
				const { results } = await env.DB.prepare('SELECT * FROM messages ORDER BY id DESC').all();

				// 2. Return the messages as JSON
				return Response.json(results);
			} catch (e: any) {
				return new Response(e.message, { status: 500 });
			}
		}

		// Handle POST requests to "/api/messages"
		if (request.method === 'POST' && pathname === '/api/messages') {
			try {
				// 1. Get the new message data from the request
				const message = await request.json<{ name: string; body: string }>();

				// 2. Insert it into the database
				await env.DB.prepare('INSERT INTO messages (name, body) VALUES (?, ?)')
					.bind(message.name, message.body)
					.run();

				// 3. Return a success response
				return new Response('Message added!', { status: 201 });
			} catch (e: any) {
				return new Response(e.message, { status: 500 });
			}
		}

		// If no route matches, return a 404
		return new Response('Not found', { status: 404 });
	},
};