const AfricasTalking = require("africastalking");

function formatKenyanPhone(value) {
    const phone = String(value || "").replace(/[\s()-]/g, "");
    if (/^0[17]\d{8}$/.test(phone)) return `+254${phone.slice(1)}`;
    if (/^254[17]\d{8}$/.test(phone)) return `+${phone}`;
    if (/^\+254[17]\d{8}$/.test(phone)) return phone;
    return null;
}

async function sendConfirmation({ phone, firstName, farmerNumber, quantityKg, collectionDate }) {
    const apiKey = process.env.AFRICASTALKING_API_KEY;
    const username = process.env.AFRICASTALKING_USERNAME || "sandbox";
    if (!apiKey) return;

    const to = formatKenyanPhone(phone);
    if (!to) {
        console.warn(`Collection SMS skipped: invalid phone for farmer ${farmerNumber}.`);
        return;
    }

    try {
        const at = AfricasTalking({ username, apiKey });
        const response = await at.SMS.send({
            to: [to],
            message: `Hello ${firstName || "farmer"}, ${Number(quantityKg).toLocaleString()} kg of milk was recorded for ${collectionDate} by Kwikas SACCO. Thank you.`
        });
        const recipient = response.SMSMessageData?.Recipients?.[0];
        if (recipient && ![100, 101, 102].includes(Number(recipient.statusCode))) {
            console.error(`Collection SMS was not accepted (status ${recipient.statusCode}).`);
        }
    } catch (error) {
        console.error("Africa's Talking collection SMS failed:", error.message);
    }
}

module.exports = { sendConfirmation };
