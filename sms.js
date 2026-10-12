// Sends the "milk received" confirmation text to a farmer.
//
// The provider is chosen by which environment variables are set on the server:
//
//   TextBee (texts go out from your own Android phone's SIM):
//     TEXTBEE_API_KEY     API key from the TextBee dashboard
//     TEXTBEE_DEVICE_ID   (optional) pick one phone if you registered several
//
//   Africa's Talking (used only when TEXTBEE_API_KEY is not set):
//     AFRICASTALKING_USERNAME, AFRICASTALKING_API_KEY
//
//   SMS_ENABLED=false     (optional) switches all texting off

function formatKenyanPhone(value) {
    const phone = String(value || "").replace(/[\s()-]/g, "");
    if (/^0[17]\d{8}$/.test(phone)) return `+254${phone.slice(1)}`;
    if (/^254[17]\d{8}$/.test(phone)) return `+${phone}`;
    if (/^\+254[17]\d{8}$/.test(phone)) return phone;
    return null;
}

const textbeeKey = () => (process.env.TEXTBEE_API_KEY || "").trim();
const atKey = () => (process.env.AFRICASTALKING_API_KEY || "").trim();
const atUsername = () => (process.env.AFRICASTALKING_USERNAME || "sandbox").trim();

async function sendWithTextbee(to, message) {
    const body = { recipients: [to], message };
    if (process.env.TEXTBEE_DEVICE_ID) body.deviceId = process.env.TEXTBEE_DEVICE_ID.trim();
    const baseUrl = (process.env.TEXTBEE_BASE_URL || "https://api.textbee.dev/api/v1").replace(/\/+$/, "");

    const response = await fetch(`${baseUrl}/gateway/send-sms`, {
        method: "POST",
        headers: { "x-api-key": textbeeKey(), "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(15000)
    });
    if (!response.ok) {
        const detail = await response.text().catch(() => "");
        console.error(`TextBee collection SMS failed (HTTP ${response.status}): ${detail.slice(0, 300)}`);
        return { status: "rejected", statusCode: response.status };
    }
    // 200 means TextBee queued it for the phone, not that the farmer has received it yet.
    return { status: "accepted" };
}

async function sendWithAfricasTalking(to, message) {
    const AfricasTalking = require("africastalking");
    const at = AfricasTalking({ username: atUsername(), apiKey: atKey() });
    const response = await at.SMS.send({ to: [to], message });
    const recipient = response.SMSMessageData?.Recipients?.[0];
    if (!recipient) return { status: "no_recipient_status" };
    if (![100, 101, 102].includes(Number(recipient.statusCode))) {
        console.error(`Collection SMS was not accepted (status ${recipient.statusCode}).`);
        return { status: "rejected", statusCode: Number(recipient.statusCode) };
    }
    return { status: "accepted", statusCode: Number(recipient.statusCode) };
}

// Never throws and never blocks the milk record: a failed text is only logged.
async function sendConfirmation({ phone, firstName, farmerNumber, quantityKg, collectionDate }) {
    if (String(process.env.SMS_ENABLED).toLowerCase() === "false") return { status: "disabled" };

    const useTextbee = Boolean(textbeeKey());
    if (!useTextbee && !atKey()) {
        console.warn("Collection SMS skipped: no TEXTBEE_API_KEY or AFRICASTALKING_API_KEY is set.");
        return { status: "not_configured" };
    }

    const to = formatKenyanPhone(phone);
    if (!to) {
        console.warn(`Collection SMS skipped: invalid phone for farmer ${farmerNumber}.`);
        return { status: "invalid_phone" };
    }

    const message = `Hello ${firstName || "farmer"}, ${Number(quantityKg).toLocaleString()} kg of milk was recorded for ${collectionDate} by Kwikas SACCO. Thank you.`;

    try {
        const result = useTextbee ? await sendWithTextbee(to, message) : await sendWithAfricasTalking(to, message);
        if (result.status === "accepted") console.log(`Collection SMS queued for farmer ${farmerNumber} via ${useTextbee ? "TextBee" : "Africa's Talking"}.`);
        return result;
    } catch (error) {
        console.error("Collection SMS failed:", error.message);
        return { status: "error" };
    }
}

function getSmsStatus() {
    if (textbeeKey()) return { configured: true, mode: "textbee" };
    return { configured: Boolean(atKey()), mode: atUsername() === "sandbox" ? "sandbox" : "live" };
}

module.exports = { sendConfirmation, getSmsStatus };
