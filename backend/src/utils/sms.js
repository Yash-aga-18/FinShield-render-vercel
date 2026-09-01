// src/utils/sms.js

/*
 * SMS delivery (for texted one-time codes).
 *
 * Two providers are supported, chosen by SMS_PROVIDER (unset = auto-detect:
 * gateway URL set → android_gateway, else Twilio keys → twilio, else console):
 *
 *   1. Android SMS Gateway — an old Android phone with a SIM running the
 *      "SMS Gateway" app's local server (free, texts go out on the SIM's own
 *      plan). Set in .env:
 *        SMS_GATEWAY_URL            — e.g. http://192.168.1.6:8080 (LAN) or a public address
 *        SMS_GATEWAY_USERNAME       — the app's local-server login
 *        SMS_GATEWAY_PASSWORD       — the app's local-server password
 *        SMS_GATEWAY_DEVICE_ID      — optional, route through one specific
 *                                      paired device when several exist
 *
 *   2. Twilio (paid, for production volume):
 *        TWILIO_ACCOUNT_SID
 *        TWILIO_AUTH_TOKEN
 *        TWILIO_FROM_NUMBER         — a Twilio phone number, e.g. +15551234567
 *        (or TWILIO_MESSAGING_SERVICE_SID instead of a from number)
 *
 * With nothing set, messages fall back to the server console — the flow stays
 * fully testable in development without any external account, exactly like
 * the mailer's console fallback.
 *
 * sendSms() returns { channel, warning? } so callers can tell the user when
 * the provider rejected the send (the text never left) instead of letting
 * them wait for a code that will never arrive.
 */

const TWILIO_API_BASE = "https://api.twilio.com/2010-04-01/Accounts";

export function isSmsConfigured() {
  // Read at call time (not module load) so tests / runtime toggles work.
  return Boolean(
    (process.env.SMS_GATEWAY_URL &&
      process.env.SMS_GATEWAY_USERNAME &&
      process.env.SMS_GATEWAY_PASSWORD) ||
      (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN),
  );
}

// Which provider a send should use. An explicit SMS_PROVIDER wins; otherwise
// the gateway is preferred when its URL is present (it's the free one), then
// Twilio.
const activeProvider = () => {
  if (process.env.SMS_PROVIDER === "android_gateway") return "android_gateway";
  if (process.env.SMS_PROVIDER === "twilio") return "twilio";
  if (process.env.SMS_GATEWAY_URL) return "android_gateway";
  return "twilio";
};

const sendViaGateway = async (to, text) => {
  // Trailing slashes would break the path join below.
  const base = process.env.SMS_GATEWAY_URL.replace(/\/+$/, "");
  const auth = Buffer.from(
    `${process.env.SMS_GATEWAY_USERNAME}:${process.env.SMS_GATEWAY_PASSWORD}`,
  ).toString("base64");
  const headers = {
    Authorization: `Basic ${auth}`,
    "Content-Type": "application/json",
  };

  // The gateway has two faces with different REST paths: the phone app's
  // LAN server (/message) and the manufacturer's cloud relay at
  // api.sms-gate.app (/3rdparty/v1/messages, from its /docs OpenAPI spec).
  // Everything else — Basic auth, the phoneNumbers/message body, the
  // {id} state poll, the state names — is identical.
  const cloudRelay = new URL(base).hostname === "api.sms-gate.app";
  const messagesPath = cloudRelay ? "/3rdparty/v1/messages" : "/message";

  // Same body shape the gateway's local server expects (verified with curl):
  // phoneNumbers is an array even for a single recipient. The message text
  // differs per face: the cloud relay wants it structured (textMessage.text,
  // verified with a live send) — the plain `message` string is deprecated
  // there — while the LAN server only knows the plain string.
  const payload = {
    phoneNumbers: [to],
    ...(cloudRelay ? { textMessage: { text } } : { message: text }),
  };
  if (process.env.SMS_GATEWAY_DEVICE_ID) {
    // Field name differs between the two faces: the LAN server takes an
    // array (deviceIds), the cloud relay a single string (deviceId).
    if (cloudRelay) payload.deviceId = process.env.SMS_GATEWAY_DEVICE_ID;
    else payload.deviceIds = [process.env.SMS_GATEWAY_DEVICE_ID];
  }

  // The cloud relay answers 202 Accepted for an enqueued message; the LAN
  // server 200/201. res.ok covers all of them.
  const res = await fetch(`${base}${messagesPath}`, { method: "POST", headers, body: JSON.stringify(payload) });

  if (!res.ok) {
    throw new Error(`SMS gateway rejected the send (${res.status}): ${await res.text()}`);
  }

  // The gateway queues the text; the phone's modem sends it a moment later —
  // the POST only means "accepted". Poll the message a few times so a modem
  // failure (no signal, dead SIM, no SMS balance) surfaces here instead of
  // letting the user wait for a code that will never arrive.
  const data = await res.json().catch(() => null);
  const messageId = data?.id ? String(data.id) : null;
  if (messageId) {
    for (let i = 0; i < 3; i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 700));
      const status = await fetch(`${base}${messagesPath}/${encodeURIComponent(messageId)}`, { headers });
      if (!status.ok) break;
      const state = await status.json().catch(() => null);
      if (state?.state === "Failed") {
        throw new Error(
          `The phone failed to send the text: ${state.recipients?.[0]?.error ?? "modem error"}`,
        );
      }
      // "Sent"/"Delivered" (or anything terminal-but-fine) — done waiting.
      if (state?.state && state.state !== "Pending" && state.state !== "Processed") break;
    }
  }

  // The queue id keeps a message findable in the app's log if it goes out late.
  return messageId;
};

const sendViaTwilio = async (to, text) => {
  const sid = process.env.TWILIO_ACCOUNT_SID;
  const auth = Buffer.from(`${sid}:${process.env.TWILIO_AUTH_TOKEN}`).toString("base64");

  // Twilio's Messages API takes form-encoded fields, not JSON.
  const params = new URLSearchParams({ To: to, Body: text });
  if (process.env.TWILIO_MESSAGING_SERVICE_SID) {
    params.set("MessagingServiceSid", process.env.TWILIO_MESSAGING_SERVICE_SID);
  } else {
    params.set("From", process.env.TWILIO_FROM_NUMBER || "");
  }

  const res = await fetch(`${TWILIO_API_BASE}/${sid}/Messages.json`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${auth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: params.toString(),
  });

  if (!res.ok) {
    throw new Error(`Twilio delivery failed (${res.status}): ${await res.text()}`);
  }
};

const sendSms = async (to, text) => {
  // Tests must never talk to a real SMS provider (quota burn, network
  // flakiness). The console fallback is deterministic.
  if (process.env.NODE_ENV === "test") {
    console.log(`[sms:test] To: ${to} — ${text}`);
    return { channel: "test" };
  }

  if (isSmsConfigured()) {
    const provider = activeProvider();
    try {
      if (provider === "android_gateway") {
        const messageId = await sendViaGateway(to, text);
        // One quiet line so "did it really send?" is answerable from the logs.
        console.log(`[sms] Queued on the Android gateway (${messageId ?? "no id"}) for ${to}`);
        return { channel: "gateway" };
      }
      await sendViaTwilio(to, text);
      // One quiet line so "did it really send?" is answerable from the logs.
      console.log(`[sms] Sent via Twilio to ${to}`);
      return { channel: "twilio" };
    } catch (error) {
      if (process.env.NODE_ENV === "production") throw error;
      // Dev: the provider rejected the send (phone offline / gateway
      // unreachable, trial account limits, unverified recipient number, …).
      // Fall through to the console so local flows keep working instead of
      // hard-failing every admin login.
      console.warn(`[sms] ${provider} send failed, falling back to console: ${error.message}`);
      return { channel: "console", warning: error.message };
    }
  }

  // Development fallback — no external account needed.
  console.log("──────────────────────────────────────────────────");
  console.log(`[sms] To: ${to}`);
  console.log(`[sms] ${text}`);
  console.log("──────────────────────────────────────────────────");
  return { channel: "console" };
};

/* ============================================================
   Message types
   ============================================================ */

export async function sendSmsOtp(phone, code, purpose, actionLabel = "", expiryMinutes = 10) {
  // Deliberately SHORT: some gateway phones fail to send longer texts — on
  // the test device everything up to ~71 chars delivered while the original
  // ~128-char wording (code + expiry + a purpose sentence) failed with
  // RESULT_MODEM_ERROR every time. The screen the user is on already says
  // what the code is for, so the text carries just the code and its expiry.
  void purpose;
  void actionLabel;
  const text = `FinShield: ${code} is your security code. It expires in ${expiryMinutes} minutes.`;
  return sendSms(phone, text);
}
