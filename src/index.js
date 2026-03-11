
export class FraudTracker {
  constructor(state, env) {
    this.state = state;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const storage = this.state.storage;

    // --- ADMIN COMMANDS ---
    if (url.pathname === "/admin/ban") {
      await storage.put("permanentlyBanned", true);
      return new Response("ID has been BANNED");
    }

    if (url.pathname === "/admin/unban") {
      await storage.delete("permanentlyBanned");
      await storage.put("count", 0); // Reset their rate limit too
      return new Response("ID has been UNBANNED");
    }

	// NEW: Inspect the DO contents
    if (url.pathname === "/admin/inspect") {
      const allData = await storage.list();
      const alarm = await storage.getAlarm();
      
      // Convert Map to a standard Object for JSON response
      return new Response(JSON.stringify({
        id: this.state.id.toString(),
        data: Object.fromEntries(allData),
        alarmScheduled: alarm ? new Date(alarm).toISOString() : "None",
        msUntilAlarm: alarm ? alarm - Date.now() : null
      }, null, 2), {
        headers: { "Content-Type": "application/json" }
      });
    }

    // --- NORMAL CHECKING LOGIC ---
    const isManualBan = await storage.get("permanentlyBanned") || false;
    let count = (await storage.get("count")) || 0;

    // Increment request count
    count++;
    await storage.put("count", count);
	console.log(`[DO] ID: ${this.state.id.toString()} | Current Count: ${count}`);

    // Auto-reset rate-limit count every 1 hour (but keep manual bans)
    const alarm = await storage.getAlarm();
    if (!alarm) {
      await storage.setAlarm(Date.now() + 3600000); 
    }

    return new Response(JSON.stringify({
      isBanned: isManualBan || count > 5, // Ban if manual OR > 5 hits/hr
      count: count,
	  isManualBan: isManualBan
    }));
  }

  // Resets the temporary counter every hour
  async alarm() {
    const isManualBan = await this.state.storage.get("permanentlyBanned");
    await this.state.storage.deleteAll();
    if (isManualBan) await this.state.storage.put("permanentlyBanned", true);
  }
}

/**
 * THE  (Main Worker)
 */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

	// We must clone immediately to keep the body available
    const originalBody = await request.clone().arrayBuffer();

    // 1. ADMIN ROUTES
    if (url.pathname.startsWith("/admin/")) {
      const secret = url.searchParams.get("key");
      const targetId = url.searchParams.get("id");

      if (secret !== env.ADMIN_SECRET) return new Response("Wrong Secret Key", { status: 401 });
      if (!targetId) return new Response("Missing 'id' parameter", { status: 400 });

      const doId = env.FRAUD_TRACKER.idFromName(targetId);
      const stub = env.FRAUD_TRACKER.get(doId);
      return stub.fetch(request);
    }

    // 2. PROTECTION LOGIC (Adjusted for JSON)
    if (request.method === "POST") {
      try {

		// We use a separate clone for Turnstile/DO logic
        const bodyForLogic = JSON.parse(new TextDecoder().decode(originalBody));
        const token = bodyForLogic.turnstileToken;

		const cf_connecting_ip = request.headers.get("cf-connecting-ip");

        if (!token) {
          return new Response("Missing Turnstile Token", { status: 400 });
        }

        // Verify with Cloudflare
        const verifyResp = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: `secret=${env.TURNSTILE_SECRET_KEY}&response=${encodeURIComponent(token)}&remoteip=${cf_connecting_ip}&remoteip_leniency="relaxed"`
        });



        const outcome = await verifyResp.json();
		console.log("Turnstile verification outcome:", outcome);

		if (!outcome.success) {
			return new Response(JSON.stringify({ error: "Turnstile verification failed" }), { 
					status: 403,
					headers: { "Content-Type": "application/json" }
				});
		}

		const ephId = outcome.metadata?.ephemeral_id;	

        if (ephId) {
          // Ask the Durable Object for this specific ID
          const doId = env.FRAUD_TRACKER.idFromName(ephId);
          const stub = env.FRAUD_TRACKER.get(doId);
          
          // We pass the request to the DO to let it increment counts
          const securityResponse = await stub.fetch(request);
          const securityCheck = await securityResponse.json();

          console.log("DO says:", securityCheck); // Verify this in 'wrangler tail'


          if (securityCheck.isBanned) {
			if (securityCheck.isManualBan) {
				return new Response(JSON.stringify({ error: "Manual Ban" }), { 
					status: 403,
					headers: { "Content-Type": "application/json" }
				});
			} else {
				return new Response(JSON.stringify({ error: "TOO MUCH!! Unauthorized Device" }), { 
					status: 403,
					headers: { "Content-Type": "application/json" }
				});
			}
          }
        }
		
      } catch (e) {
        // If JSON parsing fails, decide if you want to block or pass
        return new Response("Invalid JSON Payload", { status: 400 });
      }
    }

    // 3. PASS-THROUGH: Forward original request to your backend
    return fetch(new Request(request.url, {
      method: request.method,
      headers: request.headers,
      body: originalBody 
    }));
  }
};