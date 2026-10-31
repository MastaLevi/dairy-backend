const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
require("dotenv").config();
const db = require("./db");
const app = express();
const { sendConfirmation, sendFarmerLoginCode, getSmsStatus } = require("./sms");
const allowedOrigins = new Set((process.env.CORS_ORIGINS || "https://localhost,capacitor://localhost,http://localhost:3000,http://localhost:3003")
    .split(",").map((origin) => origin.trim()).filter(Boolean));
const trustProxyHops = Number(process.env.TRUST_PROXY_HOPS || 0);
if (!Number.isSafeInteger(trustProxyHops) || trustProxyHops < 0) throw new Error("TRUST_PROXY_HOPS must be a non-negative integer.");
app.set("trust proxy", trustProxyHops);
app.use(cors({ allowedHeaders: ["Content-Type", "Authorization", "X-App-Brand"], origin(origin, callback) {
    if (!origin || allowedOrigins.has(origin)) return callback(null, true);
    return callback(new Error("Origin is not allowed."));
} }));
app.use(express.json({ limit: "32kb" }));

const tokenSecret = process.env.WORKER_TOKEN_SECRET || (process.env.NODE_ENV === "production" ? "" : "local-development-secret-change-me");
if (process.env.NODE_ENV === "production" && (Buffer.byteLength(tokenSecret) < 32 || /^(replace|change|example|local-development)/i.test(tokenSecret))) {
    throw new Error("WORKER_TOKEN_SECRET must be set to a random value of at least 32 bytes in production.");
}
const webAuthnRpId = process.env.WEBAUTHN_RP_ID || "localhost";
const webAuthnOrigins = (process.env.WEBAUTHN_ORIGIN || "http://localhost:3003")
    .split(",").map((origin) => origin.trim()).filter(Boolean);
const pendingChallenges = new Map();
const authBuckets = new Map();
const AUTH_WINDOW_MS = 15 * 60 * 1000;
const AUTH_MAX_PER_ACCOUNT_IP = 10;
const AUTH_MAX_PER_IP = 60;
const loginRateLimit = (req, res, next) => {
    const now = Date.now();
    const ip = String(req.ip || req.socket.remoteAddress || "unknown").slice(0, 100);
    const identity = String(req.body?.workerId || req.body?.username || req.body?.farmerNumber || "unknown").trim().toLowerCase().slice(0, 100);
    const keys = [`ip:${ip}`, `account:${ip}:${identity}`];
    for (const [key, bucket] of authBuckets) if (bucket.expiresAt <= now) authBuckets.delete(key);
    const limits = [AUTH_MAX_PER_IP, AUTH_MAX_PER_ACCOUNT_IP];
    const current = keys.map((key, index) => {
        let bucket = authBuckets.get(key);
        if (!bucket || bucket.expiresAt <= now) {
            bucket = { attempts: 0, expiresAt: now + AUTH_WINDOW_MS };
            authBuckets.set(key, bucket);
        }
        return { key, bucket, limit: limits[index] };
    });
    const blocked = current.find(({ bucket, limit }) => bucket.attempts >= limit);
    if (blocked) {
        res.set("Retry-After", String(Math.max(1, Math.ceil((blocked.bucket.expiresAt - now) / 1000))));
        return res.status(429).json({ message: "Too many sign-in attempts. Wait before trying again." });
    }
    current.forEach(({ bucket }) => { bucket.attempts += 1; });
    const sendJson = res.json.bind(res);
    res.json = (body) => {
        if (res.statusCode < 400 && req.path !== "/workers/passkeys/login-options" && req.path !== "/farmers/otp/request") current.forEach(({ key }) => authBuckets.delete(key));
        return sendJson(body);
    };
    next();
};
const requestBrandName = (req) => String(req.get("x-app-brand") || "").toLowerCase() === "dairyflow" ? "DairyFlow" : "Kwikas SACCO";
const storeChallenge = (key) => {
    const challenge = crypto.randomBytes(32).toString("base64url");
    pendingChallenges.set(key, { challenge, expires: Date.now() + 5 * 60 * 1000 });
    return challenge;
};
const readClientData = (encoded, expectedType, challengeKey, res) => {
    try {
        const json = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
        const pending = pendingChallenges.get(challengeKey);
        pendingChallenges.delete(challengeKey);
        if (!pending || pending.expires < Date.now() || pending.challenge !== json.challenge || json.type !== expectedType || !webAuthnOrigins.includes(json.origin) || json.crossOrigin) {
            res.status(401).json({ message: "Passkey check expired or could not be verified. Try again." });
            return null;
        }
        return Buffer.from(encoded, "base64url");
    } catch {
        pendingChallenges.delete(challengeKey);
        res.status(400).json({ message: "Invalid passkey response." });
        return null;
    }
};
const decodeCbor = (buffer, offset = 0) => {
    const initial = buffer[offset++];
    const major = initial >> 5;
    const info = initial & 31;
    let length = info;
    if (info === 24) length = buffer[offset++];
    else if (info === 25) { length = buffer.readUInt16BE(offset); offset += 2; }
    else if (info === 26) { length = buffer.readUInt32BE(offset); offset += 4; }
    else if (info === 27) { length = Number(buffer.readBigUInt64BE(offset)); offset += 8; }
    if (major === 0) return [length, offset];
    if (major === 1) return [-1 - length, offset];
    if (major === 2 || major === 3) {
        const bytes = buffer.subarray(offset, offset + length);
        return [major === 2 ? bytes : bytes.toString("utf8"), offset + length];
    }
    if (major === 4) {
        const values = [];
        for (let i = 0; i < length; i++) { const [value, next] = decodeCbor(buffer, offset); values.push(value); offset = next; }
        return [values, offset];
    }
    if (major === 5) {
        const values = new Map();
        for (let i = 0; i < length; i++) {
            const [key, afterKey] = decodeCbor(buffer, offset);
            const [value, afterValue] = decodeCbor(buffer, afterKey);
            values.set(key, value); offset = afterValue;
        }
        return [values, offset];
    }
    if (major === 7) return [info === 20 ? false : info === 21 ? true : null, offset];
    throw new Error("Unsupported passkey data");
};
const validRpHash = (authData) => crypto.timingSafeEqual(authData.subarray(0, 32), crypto.createHash("sha256").update(webAuthnRpId).digest());
const makeToken = (workerId, sessionVersion = 0) => {
    const payload = Buffer.from(JSON.stringify({ workerId, sessionVersion: Number(sessionVersion) || 0, expires: Date.now() + 60 * 60 * 1000 })).toString("base64url");
    const signature = crypto.createHmac("sha256", tokenSecret).update(payload).digest("base64url");
    return `${payload}.${signature}`;
};
const makeAdminToken = (adminId) => {
    const payload = Buffer.from(JSON.stringify({ admin: true, adminId, expires: Date.now() + 60 * 60 * 1000 })).toString("base64url");
    const signature = crypto.createHmac("sha256", tokenSecret).update(payload).digest("base64url");
    return `${payload}.${signature}`;
};
const phoneFingerprint = (phone) => crypto.createHmac("sha256", tokenSecret).update(String(phone || "").replace(/[\s()-]/g, "")).digest("base64url");
const makeFarmerToken = (farmerNumber, phone) => {
    const payload = Buffer.from(JSON.stringify({ farmerNumber, phoneFingerprint: phoneFingerprint(phone), audience: "farmer", expires: Date.now() + 60 * 60 * 1000 })).toString("base64url");
    const signature = crypto.createHmac("sha256", tokenSecret).update(payload).digest("base64url");
    return `${payload}.${signature}`;
};
const farmerOtpSessions = new Map();
const farmerOtpSends = new Map();
const otpDigest = (farmerNumber, code, expires) => crypto.createHmac("sha256", tokenSecret).update(`${farmerNumber}:${code}:${expires}`).digest();
const cleanExpiredFarmerAuth = (now = Date.now()) => {
    for (const [key, otp] of farmerOtpSessions) if (otp.expiresAt <= now) farmerOtpSessions.delete(key);
    for (const [key, timestamps] of farmerOtpSends) {
        const recent = timestamps.filter((stamp) => now - stamp < 60 * 60 * 1000);
        if (recent.length) farmerOtpSends.set(key, recent); else farmerOtpSends.delete(key);
    }
};
const requireFarmer = (req, res, next) => {
    const [payload, signature] = (req.get("authorization") || "").replace(/^Bearer\s+/i, "").split(".");
    if (!payload || !signature) return res.status(401).json({ message: "Please sign in to view your dairy account." });
    const expected = crypto.createHmac("sha256", tokenSecret).update(payload).digest();
    const supplied = Buffer.from(signature, "base64url");
    if (expected.length !== supplied.length || !crypto.timingSafeEqual(expected, supplied)) return res.status(401).json({ message: "Invalid farmer session. Sign in again." });
    try {
        const session = JSON.parse(Buffer.from(payload, "base64url").toString());
        if (session.audience !== "farmer" || !session.farmerNumber || session.expires < Date.now()) return res.status(401).json({ message: "Your farmer session has expired. Sign in again." });
        db.query("SELECT farmer_number, phone FROM farmers WHERE farmer_number = ? AND status = 'active' LIMIT 1", [session.farmerNumber], (err, rows) => {
            if (err) return res.status(503).json({ message: "Could not validate your farmer account. Try again shortly." });
            if (!rows.length || !rows[0].phone || session.phoneFingerprint !== phoneFingerprint(rows[0].phone)) return res.status(401).json({ message: "This farmer session is no longer valid. Sign in again." });
            req.farmerNumber = rows[0].farmer_number;
            next();
        });
    } catch { return res.status(401).json({ message: "Invalid farmer session. Sign in again." }); }
};
const requireAdmin = (req, res, next) => {
    const [payload, signature] = (req.get("authorization") || "").replace(/^Bearer\s+/i, "").split(".");
    if (!payload || !signature) return res.status(401).json({ message: "Office admin sign-in is required." });
    const expected = crypto.createHmac("sha256", tokenSecret).update(payload).digest();
    const supplied = Buffer.from(signature, "base64url");
    if (expected.length !== supplied.length || !crypto.timingSafeEqual(expected, supplied)) return res.status(401).json({ message: "Invalid office admin session." });
    try {
        const session = JSON.parse(Buffer.from(payload, "base64url").toString());
        if (!session.admin || session.expires < Date.now()) return res.status(401).json({ message: "Office admin session expired. Sign in again." });
        req.adminId = session.adminId || "office";
        next();
    } catch { return res.status(401).json({ message: "Invalid office admin session." }); }
};
const recordSecurityEvent = (req, action, targetType, targetId, details = {}) => {
    db.query("INSERT INTO security_audit_events (actor_id, action, target_type, target_id, details, source_ip) VALUES (?, ?, ?, ?, ?, ?)",
        [req.adminId || "office", action, targetType, String(targetId), JSON.stringify(details), String(req.ip || "").slice(0, 45) || null],
        (err) => { if (err) console.error("Security audit write failed:", err.code || err.message); });
};
const requireWorker = (req, res, next) => {
    const [payload, signature] = (req.get("authorization") || "").replace(/^Bearer\s+/i, "").split(".");
    if (!payload || !signature) return res.status(401).json({ message: "Please sign in to continue." });
    const expected = crypto.createHmac("sha256", tokenSecret).update(payload).digest();
    let supplied;
    try { supplied = Buffer.from(signature, "base64url"); } catch { return res.status(401).json({ message: "Invalid sign-in. Please sign in again." }); }
    if (expected.length !== supplied.length || !crypto.timingSafeEqual(expected, supplied)) return res.status(401).json({ message: "Invalid sign-in. Please sign in again." });
    try {
        const session = JSON.parse(Buffer.from(payload, "base64url").toString());
        if (!session.workerId || session.expires < Date.now()) return res.status(401).json({ message: "Your session has expired. Please sign in again." });
        db.query("SELECT w.active, w.route_id AS routeId, w.session_version AS sessionVersion, r.active AS routeActive FROM workers w LEFT JOIN collection_routes r ON r.id = w.route_id WHERE w.worker_id = ? LIMIT 1", [session.workerId], (workerError, rows) => {
            if (workerError) {
                console.error("Worker session check failed:", workerError.code || workerError.message);
                return res.status(503).json({ message: "Could not validate the worker session. Try again shortly." });
            }
            const worker = rows[0];
            if (!worker || !worker.active || Number(worker.sessionVersion || 0) !== Number(session.sessionVersion || 0)) {
                return res.status(401).json({ message: "This worker session is no longer active. Sign in again." });
            }
            req.workerId = session.workerId;
            req.workerRouteId = worker.routeId === null ? null : Number(worker.routeId);
            req.workerRouteActive = Boolean(worker.routeActive);
            next();
        });
    } catch { return res.status(401).json({ message: "Invalid sign-in. Please sign in again." }); }
};
const requireAssignedRoute = (req, res, next) => {
    if (!req.workerRouteId || !req.workerRouteActive) return res.status(403).json({ message: "This worker needs an active route assigned by the office before recording or viewing farmer records." });
    next();
};


const authenticateWorker = (req, res) => {
    const { workerId, password } = req.body || {};
    if (typeof workerId !== "string" || !workerId.trim() || workerId.trim().length > 50 || typeof password !== "string" || !password || password.length > 256) {
        return res.status(400).json({ message: "Worker ID and password are required." });
    }
    db.query("SELECT worker_id, password_hash, active, session_version AS sessionVersion FROM workers WHERE worker_id = ? LIMIT 1", [workerId.trim()], (err, rows) => {
        if (err) {
            console.error("Worker login database error:", err.code || err.message);
            if (err.code === "ER_NO_SUCH_TABLE") {
                return res.status(500).json({ message: "The database used by this API is missing its workers table. Set up the worker schema in the API database." });
            }
            if (err.code === "ER_BAD_FIELD_ERROR") {
                return res.status(500).json({ message: "The workers table is missing a required column. Apply the worker security migration to the database used by this API." });
            }
            return res.status(500).json({ message: "Could not query worker records. Check the API database connection and worker schema." });
        }
        const worker = rows[0];
        if (!worker || !worker.active) return res.status(401).json({ message: "Worker ID or password is incorrect." });
        const savedPassword = worker.password_hash;
        const hashParts = savedPassword.split(":");
        const isScryptHash = hashParts.length === 2 && /^[a-f\d]{32}$/i.test(hashParts[0]) && /^[a-f\d]{128}$/i.test(hashParts[1]);
        if (!isScryptHash) return res.status(401).json({ message: "This worker account needs a password reset before it can sign in." });
        crypto.scrypt(password, hashParts[0], 64, (hashError, derivedKey) => {
            if (hashError) return res.status(500).json({ message: "Could not verify worker credentials." });
            const expectedHash = Buffer.from(hashParts[1], "hex");
            const validPassword = derivedKey.length === expectedHash.length && crypto.timingSafeEqual(derivedKey, expectedHash);
            if (!validPassword) return res.status(401).json({ message: "Worker ID or password is incorrect." });
            res.json({ token: makeToken(worker.worker_id, worker.sessionVersion), workerId: worker.worker_id });
        });
    });
};
app.post("/workers/login", loginRateLimit, authenticateWorker);
// Office admin sign-in is checked against the `admin` table.
// `password` holds a scrypt hash written as salt:hash (see hash.js).
const verifyAdminLogin = (username, password, callback) => {
    if (!username || typeof password !== "string" || !password) return callback(null, false);
    db.query("SELECT `password` FROM `Admin` WHERE `admin` = ? LIMIT 1", [username], (err, rows) => {
        if (err) return callback(err);
        const parts = String(rows[0]?.password || "").split(":");
        if (!rows.length || parts.length !== 2 || !/^[a-f\d]{32}$/i.test(parts[0]) || !/^[a-f\d]{128}$/i.test(parts[1])) return callback(null, false);
        crypto.scrypt(password, parts[0], 64, (hashError, derivedKey) => {
            if (hashError) return callback(hashError);
            const expected = Buffer.from(parts[1], "hex");
            callback(null, derivedKey.length === expected.length && crypto.timingSafeEqual(derivedKey, expected));
        });
    });
};
app.post("/login", loginRateLimit, (req, res) => {
    const { workerId, username, password } = req.body || {};
    const loginId = String(workerId || username || "").trim();
    verifyAdminLogin(loginId, password, (err, isAdmin) => {
        if (err) console.error("Admin login lookup error:", err.code || err.message);
        if (isAdmin) return res.json({ token: makeAdminToken(loginId), role: "admin", adminId: loginId });
        req.body = { ...(req.body || {}), workerId: loginId };
        authenticateWorker(req, res);
    });
});

app.get("/workers/passkeys/register-options", requireWorker, requireAssignedRoute, (req, res) => {
    const challenge = storeChallenge(`register:${req.workerId}`);
    res.json({
        challenge, rp: { id: webAuthnRpId, name: `${requestBrandName(req)} Dairy Collection` },
        user: { id: Buffer.from(req.workerId).toString("base64url"), name: req.workerId, displayName: `Worker ${req.workerId}` },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: { authenticatorAttachment: "platform", residentKey: "preferred", userVerification: "required" },
        attestation: "none", timeout: 60000
    });
});

app.post("/workers/passkeys/register", requireWorker, requireAssignedRoute, (req, res) => {
    const { clientDataJSON, attestationObject, credentialId } = req.body || {};
    if (!clientDataJSON || !attestationObject || !credentialId) return res.status(400).json({ message: "Passkey registration response is incomplete." });
    if (!readClientData(clientDataJSON, "webauthn.create", `register:${req.workerId}`, res)) return;
    try {
        const [attestation] = decodeCbor(Buffer.from(attestationObject, "base64url"));
        const authData = attestation.get("authData");
        if (!authData || !validRpHash(authData) || !(authData[32] & 0x40) || !(authData[32] & 0x01) || !(authData[32] & 0x04)) {
            return res.status(401).json({ message: "This device could not verify the passkey." });
        }
        const credentialLength = authData.readUInt16BE(53);
        const actualCredentialId = authData.subarray(55, 55 + credentialLength).toString("base64url");
        const [coseKey] = decodeCbor(authData, 55 + credentialLength);
        const x = coseKey.get(-2); const y = coseKey.get(-3);
        if (coseKey.get(1) !== 2 || coseKey.get(-1) !== 1 || coseKey.get(3) !== -7 || actualCredentialId !== credentialId || !x || !y) {
            return res.status(400).json({ message: "This device returned an unsupported passkey." });
        }
        const publicKey = { kty: "EC", crv: "P-256", x: x.toString("base64url"), y: y.toString("base64url") };
        const counter = authData.readUInt32BE(33);
        db.query("INSERT INTO worker_passkeys (credential_id, worker_id, public_key_jwk, signature_counter) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE worker_id = VALUES(worker_id), public_key_jwk = VALUES(public_key_jwk), signature_counter = VALUES(signature_counter)", [credentialId, req.workerId, JSON.stringify(publicKey), counter], (err) => {
            if (err) { console.error("Passkey registration database error:", err); return res.status(500).json({ message: "Could not save this device passkey. Run the latest backend/schema.sql." }); }
            res.json({ message: "Device passkey enabled." });
        });
    } catch (err) {
        console.error("Passkey registration verification error:", err);
        res.status(400).json({ message: "Could not verify this device passkey." });
    }
});

app.post("/workers/passkeys/login-options", loginRateLimit, (req, res) => {
    const workerId = String(req.body?.workerId || "").trim();
    if (!workerId) return res.status(400).json({ message: "Enter your worker ID first." });
    db.query("SELECT credential_id FROM worker_passkeys WHERE worker_id = ?", [workerId], (err, rows) => {
        if (err) { console.error("Passkey lookup database error:", err); return res.status(500).json({ message: "Could not load device passkeys. Run the latest backend/schema.sql." }); }
        if (!rows.length) return res.status(404).json({ message: "No device passkey is set up for this worker yet." });
        const challenge = storeChallenge(`login:${workerId}`);
        res.json({ challenge, rpId: webAuthnRpId, userVerification: "required", timeout: 60000, allowCredentials: rows.map((row) => ({ type: "public-key", id: row.credential_id })) });
    });
});

app.post("/workers/passkeys/login", loginRateLimit, (req, res) => {
    const { workerId: rawWorkerId, credentialId, clientDataJSON, authenticatorData, signature } = req.body || {};
    const workerId = String(rawWorkerId || "").trim();
    if (!workerId || !credentialId || !clientDataJSON || !authenticatorData || !signature) return res.status(400).json({ message: "Passkey response is incomplete." });
    const clientData = readClientData(clientDataJSON, "webauthn.get", `login:${workerId}`, res);
    if (!clientData) return;
    db.query("SELECT p.public_key_jwk, p.signature_counter, w.active, w.session_version AS sessionVersion FROM worker_passkeys p JOIN workers w ON w.worker_id = p.worker_id WHERE p.worker_id = ? AND p.credential_id = ? LIMIT 1", [workerId, credentialId], (err, rows) => {
        if (err) { console.error("Passkey verification database error:", err); return res.status(500).json({ message: "Could not verify device passkey." }); }
        if (!rows.length || !rows[0].active) return res.status(401).json({ message: "This device passkey is not registered for that worker." });
        try {
            const authData = Buffer.from(authenticatorData, "base64url");
            if (authData.length < 37 || !validRpHash(authData) || !(authData[32] & 0x01) || !(authData[32] & 0x04)) return res.status(401).json({ message: "Device verification was not completed." });
            const counter = authData.readUInt32BE(33);
            if (counter && rows[0].signature_counter && counter <= Number(rows[0].signature_counter)) return res.status(401).json({ message: "This passkey response has already been used." });
            const signedData = Buffer.concat([authData, crypto.createHash("sha256").update(clientData).digest()]);
            const jwk = typeof rows[0].public_key_jwk === "string" ? JSON.parse(rows[0].public_key_jwk) : rows[0].public_key_jwk;
            const publicKey = crypto.createPublicKey({ key: jwk, format: "jwk" });
            const validSignature = crypto.verify("sha256", signedData, publicKey, Buffer.from(signature, "base64url"));
            if (!validSignature) return res.status(401).json({ message: "Device passkey could not be verified." });
            db.query("UPDATE worker_passkeys SET signature_counter = GREATEST(signature_counter, ?) WHERE worker_id = ? AND credential_id = ?", [counter, workerId, credentialId], (updateError) => {
                if (updateError) console.error("Could not update passkey counter:", updateError);
                res.json({ token: makeToken(workerId, rows[0].sessionVersion), workerId });
            });
        } catch (verifyError) {
            console.error("Passkey verification error:", verifyError);
            res.status(400).json({ message: "Could not verify device passkey." });
        }
    });
});

app.get("/", (req, res) => {
    res.json({
        message: "Milk Collection System API is running"
    });
});
app.post("/admin/login", loginRateLimit, (req, res) => {
    const suppliedUser = String(req.body?.username || "").trim();
    const suppliedPassword = String(req.body?.password || "");
    verifyAdminLogin(suppliedUser, suppliedPassword, (err, ok) => {
        if (err) { console.error("Admin login database error:", err.code || err.message); return res.status(500).json({ message: "Could not check admin sign-in. Make sure the admin table exists." }); }
        if (!ok) return res.status(401).json({ message: "The worker or office ID and password do not match." });
        res.json({ token: makeAdminToken(suppliedUser) });
    });
});
app.get("/admin/messaging/status", requireAdmin, (req, res) => res.json(getSmsStatus()));
app.get("/admin/messaging/deliveries", requireAdmin, (req, res) => {
    db.query(`SELECT s.id, s.collection_id AS collectionId, s.provider, s.status,
        s.provider_status_code AS providerStatusCode, s.attempted_at AS attemptedAt,
        mc.farmer_number AS farmerNumber, mc.quantity_kg AS quantityKg, mc.collection_date AS collectionDate
        FROM sms_delivery_attempts s
        JOIN milk_collections mc ON mc.id = s.collection_id
        ORDER BY s.id DESC LIMIT 50`, (err, rows) => {
        if (err) {
            console.error("SMS delivery history database error:", err.code || err.message);
            return res.status(503).json({ message: "SMS delivery history is not ready. Apply the SMS delivery log migration and enable logging." });
        }
        res.json(rows.map((row) => ({ ...row, quantityKg: Number(row.quantityKg) })));
    });
});
app.get("/admin/dashboard", requireAdmin, (req, res) => {
    const sql = `SELECT
        (SELECT COUNT(*) FROM farmers WHERE status = 'active') AS activeFarmers,
        (SELECT COUNT(*) FROM workers WHERE active = TRUE) AS activeWorkers,
        (SELECT COUNT(*) FROM milk_collections WHERE collection_date = CURDATE()) AS collectionsToday,
        (SELECT COALESCE(SUM(quantity_kg), 0) FROM milk_collections WHERE collection_date = CURDATE()) AS todayKg`;
    db.query(sql, (err, rows) => {
        if (err) { console.error("Admin dashboard database error:", err); return res.status(500).json({ message: "Could not load office dashboard." }); }
        const stats = rows[0];
        res.json({ activeFarmers: Number(stats.activeFarmers), activeWorkers: Number(stats.activeWorkers), collectionsToday: Number(stats.collectionsToday), todayKg: Number(stats.todayKg) });
    });
});
app.get("/admin/routes", requireAdmin, (req, res) => {
    db.query("SELECT id, route_name AS routeName FROM collection_routes WHERE active = TRUE ORDER BY route_name", (err, rows) => {
        if (err) { console.error("Admin route list database error:", err); return res.status(500).json({ message: "Could not load routes. Run the latest backend/schema.sql." }); }
        res.json(rows.map((row) => ({ id: Number(row.id), routeName: row.routeName })));
    });
});
app.get("/admin/workers", requireAdmin, (req, res) => {
    db.query(`SELECT w.worker_id AS workerId, w.active, w.route_id AS routeId, r.route_name AS routeName
        FROM workers w LEFT JOIN collection_routes r ON r.id = w.route_id ORDER BY w.worker_id`, (err, rows) => {
        if (err) { console.error("Admin worker list database error:", err.code || err.message); return res.status(500).json({ message: "Could not load workers." }); }
        res.json(rows.map((row) => ({ ...row, active: Boolean(row.active), routeId: row.routeId === null ? null : Number(row.routeId) })));
    });
});
app.get("/admin/security/audit", requireAdmin, (req, res) => {
    db.query(`SELECT id, actor_id AS actorId, action, target_type AS targetType, target_id AS targetId, details,
        source_ip AS sourceIp, created_at AS createdAt FROM security_audit_events ORDER BY id DESC LIMIT 100`, (err, rows) => {
        if (err) { console.error("Security audit list failed:", err.code || err.message); return res.status(503).json({ message: "Security audit history is not ready. Apply the security-hardening migration." }); }
        res.json(rows);
    });
});
app.put("/admin/workers/:workerId/route", requireAdmin, (req, res) => {
    const workerId = String(req.params.workerId || "").trim();
    const routeId = Number(req.body?.routeId);
    if (!workerId || !Number.isInteger(routeId) || routeId <= 0) return res.status(400).json({ message: "Choose an active route." });
    db.query("SELECT id FROM collection_routes WHERE id = ? AND active = TRUE", [routeId], (routeError, routes) => {
        if (routeError) { console.error("Worker route update validation failed:", routeError.code || routeError.message); return res.status(500).json({ message: "Could not check that route." }); }
        if (!routes.length) return res.status(400).json({ message: "Choose an active route." });
        db.query("UPDATE workers SET route_id = ?, session_version = session_version + 1 WHERE worker_id = ?", [routeId, workerId], (err, result) => {
            if (err) { console.error("Worker route update failed:", err.code || err.message); return res.status(500).json({ message: "Could not update the worker route." }); }
            if (!result.affectedRows) return res.status(404).json({ message: "Worker not found." });
            recordSecurityEvent(req, "worker_route_changed", "worker", workerId, { routeId });
            res.json({ message: "Worker route updated and active sessions revoked." });
        });
    });
});
app.post("/admin/workers/:workerId/sessions/revoke", requireAdmin, (req, res) => {
    const workerId = String(req.params.workerId || "").trim();
    db.query("UPDATE workers SET session_version = session_version + 1 WHERE worker_id = ?", [workerId], (err, result) => {
        if (err) { console.error("Worker session revocation failed:", err.code || err.message); return res.status(500).json({ message: "Could not revoke worker sessions." }); }
        if (!result.affectedRows) return res.status(404).json({ message: "Worker not found." });
        recordSecurityEvent(req, "worker_sessions_revoked", "worker", workerId);
        res.json({ message: "Worker sessions revoked." });
    });
});
app.post("/admin/workers/:workerId/active", requireAdmin, (req, res) => {
    const workerId = String(req.params.workerId || "").trim();
    const active = req.body?.active === true;
    db.query("UPDATE workers SET active = ?, session_version = session_version + 1 WHERE worker_id = ?", [active, workerId], (err, result) => {
        if (err) { console.error("Worker status update failed:", err.code || err.message); return res.status(500).json({ message: "Could not update worker status." }); }
        if (!result.affectedRows) return res.status(404).json({ message: "Worker not found." });
        recordSecurityEvent(req, active ? "worker_reactivated" : "worker_deactivated", "worker", workerId);
        res.json({ message: active ? "Worker reactivated; all previous sessions were revoked." : "Worker deactivated and sessions revoked." });
    });
});
app.post("/admin/workers", requireAdmin, (req, res) => {
    const workerId = String(req.body?.workerId || "").trim();
    const password = String(req.body?.password || "");
    const routeId = req.body?.routeId ? Number(req.body.routeId) : null;
    if (!workerId || workerId.length > 50 || password.length < 12 || !Number.isInteger(routeId) || routeId <= 0) return res.status(400).json({ message: "Enter a worker ID, a password of at least 12 characters, and an active route." });
    const insert = (route) => {
        const salt = crypto.randomBytes(16).toString("hex");
        crypto.scrypt(password, salt, 64, (hashError, key) => {
            if (hashError) return res.status(500).json({ message: "Could not secure the worker password." });
            db.query("INSERT INTO workers (worker_id, password_hash, route_id) VALUES (?, ?, ?)", [workerId, `${salt}:${key.toString("hex")}`, route], (err) => {
                if (err?.code === "ER_DUP_ENTRY") return res.status(409).json({ message: "That worker ID is already in use." });
                if (err) { console.error("Admin worker insert database error:", err); return res.status(500).json({ message: "Could not add worker." }); }
                res.status(201).json({ message: "Worker added.", workerId });
            });
        });
    };
    db.query("SELECT id FROM collection_routes WHERE id = ? AND active = TRUE", [routeId], (err, rows) => {
        if (err) { console.error("Admin worker route validation error:", err); return res.status(500).json({ message: "Could not check that route." }); }
        if (!rows.length) return res.status(400).json({ message: "Choose an active collection route." });
        insert(routeId);
    });
});
app.get("/admin/farmers/unassigned", requireAdmin, (req, res) => {
    db.query("SELECT farmer_number AS farmerNumber, first_name AS firstName FROM farmers WHERE status = 'active' AND route_id IS NULL ORDER BY farmer_number LIMIT 500", (err, rows) => {
        if (err) { console.error("Unassigned farmer list failed:", err.code || err.message); return res.status(500).json({ message: "Could not load farmers without routes." }); }
        res.json(rows);
    });
});
app.get("/admin/farmers/:farmerNumber", requireAdmin, (req, res) => {
    const farmerNumber = String(req.params.farmerNumber || "").trim();
    if (!farmerNumber || farmerNumber.length > 20) return res.status(400).json({ message: "Enter a valid farmer account number." });
    db.query(`SELECT f.farmer_number AS farmerNumber, f.first_name AS firstName, f.phone,
                     f.status, f.zone, f.route_id AS routeId, cr.route_name AS routeName
              FROM farmers f LEFT JOIN collection_routes cr ON cr.id = f.route_id
              WHERE f.farmer_number = ? LIMIT 1`, [farmerNumber], (err, rows) => {
        if (err) { console.error("Admin farmer lookup failed:", err.code || err.message); return res.status(500).json({ message: "Could not look up this farmer." }); }
        if (!rows.length) return res.status(404).json({ message: "No farmer account matches that number." });
        res.json(rows[0]);
    });
});
app.put("/admin/farmers/:farmerNumber/route", requireAdmin, (req, res) => {
    const farmerNumber = String(req.params.farmerNumber || "").trim();
    const routeId = Number(req.body?.routeId);
    if (!farmerNumber || !Number.isInteger(routeId) || routeId <= 0) return res.status(400).json({ message: "Choose an active route." });
    db.query("SELECT id, route_name AS routeName FROM collection_routes WHERE id = ? AND active = TRUE", [routeId], (routeError, routes) => {
        if (routeError) { console.error("Farmer route validation failed:", routeError.code || routeError.message); return res.status(500).json({ message: "Could not check that route." }); }
        if (!routes.length) return res.status(400).json({ message: "Choose an active route." });
        db.query("UPDATE farmers SET route_id = ?, zone = ? WHERE farmer_number = ? AND status = 'active'", [routeId, routes[0].routeName, farmerNumber], (err, result) => {
            if (err) { console.error("Farmer route update failed:", err.code || err.message); return res.status(500).json({ message: "Could not update the farmer route." }); }
            if (!result.affectedRows) return res.status(404).json({ message: "Active farmer not found." });
            recordSecurityEvent(req, "farmer_route_changed", "farmer", farmerNumber, { routeId });
            res.json({ message: "Farmer route updated." });
        });
    });
});
app.put("/admin/farmers/:farmerNumber/phone", requireAdmin, (req, res) => {
    const farmerNumber = String(req.params.farmerNumber || "").trim();
    const phone = String(req.body?.phone || "").trim();
    const normalizedPhone = phone.replace(/[\s()-]/g, "");
    if (!farmerNumber || farmerNumber.length > 20 || phone.length > 20 || !/^(?:0[17]\d{8}|254[17]\d{8}|\+254[17]\d{8})$/.test(normalizedPhone)) {
        return res.status(400).json({ message: "Enter a valid Kenyan mobile number." });
    }
    db.query("UPDATE farmers SET phone = ? WHERE farmer_number = ? AND status = 'active'", [phone, farmerNumber], (err, result) => {
        if (err) { console.error("Farmer phone update failed:", err.code || err.message); return res.status(500).json({ message: "Could not update the farmer phone number." }); }
        const finish = (found) => {
            if (!found) return res.status(404).json({ message: "Active farmer not found." });
            recordSecurityEvent(req, "farmer_phone_updated", "farmer", farmerNumber);
            res.json({ message: "Farmer sign-in phone number updated." });
        };
        if (result.affectedRows) return finish(true);
        db.query("SELECT farmer_number FROM farmers WHERE farmer_number = ? AND status = 'active' LIMIT 1", [farmerNumber], (lookupError, rows) => {
            if (lookupError) return res.status(500).json({ message: "Could not verify the farmer account." });
            finish(rows.length > 0);
        });
    });
});
app.post("/admin/farmers", requireAdmin, (req, res) => {
    const farmerNumber = String(req.body?.farmerNumber || "").trim();
    const firstName = String(req.body?.firstName || "").trim();
    const phone = String(req.body?.phone || "").trim();
    const routeId = req.body?.routeId ? Number(req.body.routeId) : null;
    if (!farmerNumber || farmerNumber.length > 20 || !firstName || firstName.length > 50 || !phone || phone.length > 20 || !Number.isInteger(routeId) || routeId <= 0) return res.status(400).json({ message: "Enter a farmer number, name, phone, and an active route." });
    const cleanPhone = phone.replace(/[\s()-]/g, "");
    if (!/^(?:0[17]\d{8}|254[17]\d{8}|\+254[17]\d{8})$/.test(cleanPhone)) return res.status(400).json({ message: "Enter a valid Kenyan mobile number, such as 0712 345 678 or +254 712 345 678." });
    const insert = (route) => db.query("INSERT INTO farmers (farmer_number, first_name, phone, status, zone, route_id) VALUES (?, ?, ?, 'active', ?, ?)", [farmerNumber, firstName, phone, route?.routeName || null, route?.id || null], (err) => {
        if (err?.code === "ER_DUP_ENTRY") return res.status(409).json({ message: "That farmer number already exists." });
        if (err) { console.error("Admin farmer insert database error:", err); return res.status(500).json({ message: "Could not add farmer." }); }
        res.status(201).json({ message: "Farmer added.", farmerNumber });
    });
    db.query("SELECT id, route_name AS routeName FROM collection_routes WHERE id = ? AND active = TRUE", [routeId], (err, rows) => {
        if (err) { console.error("Admin farmer route validation error:", err); return res.status(500).json({ message: "Could not check that route." }); }
        if (!rows.length) return res.status(400).json({ message: "Choose an active collection route." });
        insert(rows[0]);
    });
});
app.get("/workers/dashboard", requireWorker, requireAssignedRoute, (req, res) => {
    const todaySql = `SELECT COALESCE(SUM(quantity_kg), 0) AS todayKg, COUNT(*) AS todayCount
        FROM milk_collections WHERE collector_id = ? AND collection_date = CURDATE()`;
    const routeSql = `SELECT r.route_name AS routeName,
        COALESCE(SUM(CASE WHEN collecting_worker.route_id = w.route_id AND collected_farmer.route_id = w.route_id THEN mc.quantity_kg ELSE 0 END), 0) AS routeKg,
        COUNT(CASE WHEN collecting_worker.route_id = w.route_id AND collected_farmer.route_id = w.route_id THEN mc.id END) AS routeCount,
        COUNT(DISTINCT CASE WHEN collecting_worker.route_id = w.route_id AND collected_farmer.route_id = w.route_id AND collected_farmer.status = 'active' THEN mc.farmer_number END) AS farmersCollected,
        (SELECT COUNT(*) FROM farmers f WHERE f.status = 'active' AND f.route_id = w.route_id) AS farmersOnRoute
        FROM workers w LEFT JOIN collection_routes r ON r.id = w.route_id
        LEFT JOIN milk_collections mc ON mc.collection_date = CURDATE()
        LEFT JOIN workers collecting_worker ON collecting_worker.worker_id = mc.collector_id
        LEFT JOIN farmers collected_farmer ON collected_farmer.farmer_number = mc.farmer_number
        WHERE w.worker_id = ? GROUP BY r.route_name`;
    const recentSql = `SELECT mc.farmer_number AS farmerNumber, f.first_name AS firstName,
        mc.quantity_kg AS quantityKg, DATE_FORMAT(mc.collection_date, '%Y-%m-%d') AS collectionDate,
        (mc.collector_id IS NULL) AS unassigned
        FROM milk_collections mc LEFT JOIN farmers f ON f.farmer_number = mc.farmer_number
        WHERE (mc.collector_id = ? OR mc.collector_id IS NULL) AND f.route_id = (SELECT route_id FROM workers WHERE worker_id = ?)
        ORDER BY mc.collection_date DESC, mc.id DESC LIMIT 8`;
    db.query(todaySql, [req.workerId], (todayError, totals) => {
        if (todayError) {
            console.error("Worker dashboard database error:", todayError);
            return res.status(500).json({ message: "Could not load dashboard. Run the offline collection migration first." });
        }
        db.query(recentSql, [req.workerId, req.workerId], (recentError, recent) => {
            if (recentError) {
                console.error("Worker recent collections database error:", recentError);
                return res.status(500).json({ message: "Could not load recent collections." });
            }
            db.query(routeSql, [req.workerId], (routeError, routeTotals) => {
                if (routeError) {
                    console.error("Worker route total database error:", routeError);
                    return res.status(500).json({ message: "Could not load route total. Run the route migration first." });
                }
                const route = routeTotals[0] || {};
                res.json({ todayKg: Number(totals[0].todayKg), todayCount: Number(totals[0].todayCount), routeName: route.routeName || null, routeKg: Number(route.routeKg) || 0, routeCount: Number(route.routeCount) || 0, farmersCollected: Number(route.farmersCollected) || 0, farmersOnRoute: Number(route.farmersOnRoute) || 0, recent });
            });
        });
    });
});

// Farmer access is verified against the phone already held by the dairy office.
// The response stays the same whether an account exists, is inactive, lacks a
// phone number, or its SMS could not be delivered.
app.post("/farmers/otp/request", loginRateLimit, (req, res) => {
    const farmerNumber = String(req.body?.farmerNumber || "").trim();
    if (!farmerNumber || farmerNumber.length > 20) return res.status(202).json({ message: "If the active account has a verified phone number, a sign-in code will arrive shortly." });
    const now = Date.now();
    cleanExpiredFarmerAuth(now);
    const sentAt = farmerOtpSends.get(farmerNumber) || [];
    if (sentAt.length >= 5 || (sentAt.length && now - sentAt[sentAt.length - 1] < 60 * 1000)) {
        return res.status(202).json({ message: "If the active account has a verified phone number, a sign-in code will arrive shortly." });
    }
    // Reserve the resend slot before the asynchronous lookup so concurrent
    // requests cannot all pass the account-level SMS limit.
    farmerOtpSends.set(farmerNumber, [...sentAt, now]);
    db.query("SELECT farmer_number AS farmerNumber, first_name AS firstName, phone FROM farmers WHERE farmer_number = ? AND status = 'active' LIMIT 1", [farmerNumber], async (err, rows) => {
        if (!err && rows.length && rows[0].phone) {
            const code = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
            const expiresAt = Date.now() + 5 * 60 * 1000;
            farmerOtpSessions.set(farmerNumber, { digest: otpDigest(farmerNumber, code, expiresAt), phoneFingerprint: phoneFingerprint(rows[0].phone), expiresAt, attempts: 0 });
            const result = await sendFarmerLoginCode({ phone: rows[0].phone, code, brandName: process.env.DAIRY_COMPANY_NAME || requestBrandName(req) });
            if (result.status !== "accepted") console.warn(`Farmer login code was not accepted by SMS provider (${result.status}).`);
        } else if (err) {
            console.error("Farmer OTP lookup failed:", err.code || err.message);
        }
        res.status(202).json({ message: "If the active account has a verified phone number, a sign-in code will arrive shortly." });
    });
});

app.post("/farmers/otp/verify", loginRateLimit, (req, res) => {
    const farmerNumber = String(req.body?.farmerNumber || "").trim();
    const code = String(req.body?.code || "").trim();
    const pending = farmerOtpSessions.get(farmerNumber);
    if (!farmerNumber || farmerNumber.length > 20 || !/^\d{6}$/.test(code) || !pending || pending.expiresAt <= Date.now() || pending.attempts >= 5) {
        if (pending && pending.expiresAt <= Date.now()) farmerOtpSessions.delete(farmerNumber);
        return res.status(401).json({ message: "That code is incorrect or expired. Request a new code and try again." });
    }
    pending.attempts += 1;
    const supplied = otpDigest(farmerNumber, code, pending.expiresAt);
    if (!crypto.timingSafeEqual(pending.digest, supplied)) {
        if (pending.attempts >= 5) farmerOtpSessions.delete(farmerNumber);
        return res.status(401).json({ message: "That code is incorrect or expired. Request a new code and try again." });
    }
    farmerOtpSessions.delete(farmerNumber);
    db.query("SELECT farmer_number, phone FROM farmers WHERE farmer_number = ? AND status = 'active' LIMIT 1", [farmerNumber], (err, rows) => {
        if (err) return res.status(503).json({ message: "Could not verify your farmer account. Try again shortly." });
        if (!rows.length || !rows[0].phone || pending.phoneFingerprint !== phoneFingerprint(rows[0].phone)) return res.status(401).json({ message: "That code is incorrect or expired. Request a new code and try again." });
        res.json({ token: makeFarmerToken(rows[0].farmer_number, rows[0].phone), farmerNumber: rows[0].farmer_number });
    });
});

app.get("/farmers/me", requireFarmer, (req, res) => {
    const farmerQuery = `SELECT f.farmer_number AS farmerNumber, f.first_name AS firstName,
        COALESCE(SUM(mc.quantity_kg), 0) AS lifetimeKg,
        COALESCE(SUM(CASE WHEN mc.collection_date >= DATE_FORMAT(CURDATE(), '%Y-%m-01') THEN mc.quantity_kg ELSE 0 END), 0) AS monthKg,
        COALESCE(SUM(CASE WHEN mc.collection_date >= DATE_FORMAT(CURDATE(), '%Y-%m-01') THEN 1 ELSE 0 END), 0) AS monthCollections
        FROM farmers f LEFT JOIN milk_collections mc ON mc.farmer_number = f.farmer_number
        WHERE f.farmer_number = ? AND f.status = 'active' GROUP BY f.farmer_number, f.first_name`;
    db.query(farmerQuery, [req.farmerNumber], (farmerError, farmerRows) => {
        if (farmerError || !farmerRows.length) {
            if (farmerError) console.error("Farmer dashboard summary failed:", farmerError.code || farmerError.message);
            return res.status(farmerError ? 500 : 404).json({ message: "Could not load this farmer account." });
        }
        const collectionsQuery = `SELECT id, quantity_kg AS quantityKg,
            DATE_FORMAT(collection_date, '%Y-%m-%d') AS collectionDate
            FROM milk_collections WHERE farmer_number = ?
            ORDER BY collection_date DESC, id DESC LIMIT 30`;
        const monthsQuery = `SELECT DATE_FORMAT(collection_date, '%Y-%m') AS month,
            COALESCE(SUM(quantity_kg), 0) AS kg, COUNT(*) AS collections
            FROM milk_collections WHERE farmer_number = ?
            AND collection_date >= DATE_FORMAT(DATE_SUB(CURDATE(), INTERVAL 5 MONTH), '%Y-%m-01')
            GROUP BY DATE_FORMAT(collection_date, '%Y-%m') ORDER BY month`;
        db.query(collectionsQuery, [req.farmerNumber], (collectionError, collections) => {
            if (collectionError) return res.status(500).json({ message: "Could not load collection history." });
            db.query(monthsQuery, [req.farmerNumber], (monthError, months) => {
                if (monthError) return res.status(500).json({ message: "Could not load monthly totals." });
                const farmer = farmerRows[0];
                res.json({
                    farmerNumber: farmer.farmerNumber,
                    firstName: farmer.firstName,
                    lifetimeKg: Number(farmer.lifetimeKg) || 0,
                    monthKg: Number(farmer.monthKg) || 0,
                    monthCollections: Number(farmer.monthCollections) || 0,
                    months: months.map((entry) => ({ month: entry.month, kg: Number(entry.kg) || 0, collections: Number(entry.collections) || 0 })),
                    collections: collections.map((entry) => ({ id: entry.id, quantityKg: Number(entry.quantityKg), collectionDate: entry.collectionDate })),
                    finance: { available: false, message: "Milk prices, payout statements, savings, and loans are not connected to this dairy account yet." }
                });
            });
        });
    });
});

app.get("/farmers/:farmerNumber", requireWorker, requireAssignedRoute, (req, res) => {

    const farmerNumber = req.params.farmerNumber;

    const sql = `
        SELECT farmer_number, first_name
        FROM farmers
        WHERE farmer_number = ?
        AND status = 'active'
        AND route_id = ?
    `;

    db.query(sql, [farmerNumber, req.workerRouteId], (err, results) => {

        if (err) {
            console.error("Database error:", err);

            return res.status(500).json({
                message: "Database error"
            });
        }

        if (results.length === 0) {
            return res.status(404).json({
                message: "Farmer not found"
            });
        }

        res.json({
            farmerNumber: results[0].farmer_number,
            firstName: results[0].first_name
        });
    });
});

app.post("/milk", requireWorker, requireAssignedRoute, (req, res) => {
    const { farmerNumber, quantityKg, collectionDate, clientRecordId } = req.body || {};
    const selectedDate = collectionDate || new Date().toISOString().slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(selectedDate)) return res.status(400).json({ message: "Enter a valid collection date." });
    if (!farmerNumber || !Number.isFinite(Number(quantityKg)) || Number(quantityKg) <= 0) {
        return res.status(400).json({ message: "A farmer account and a quantity greater than zero are required." });
    }

    const saveForFarmer = () => {
        const insert = (farmer) => {
            const sql = `INSERT INTO milk_collections
                (farmer_number, quantity_kg, collection_date, collector_id, client_record_id)
                VALUES (?, ?, ?, ?, ?)`;
            db.query(sql, [farmer.farmer_number, Number(quantityKg), selectedDate, req.workerId, clientRecordId || null], (err, result) => {
                if (err?.code === "ER_DUP_ENTRY" && clientRecordId) {
                    return db.query("SELECT id, farmer_number, quantity_kg FROM milk_collections WHERE client_record_id = ? LIMIT 1", [clientRecordId], (lookupError, matches) => {
                        if (lookupError || !matches.length) return res.status(500).json({ message: "Could not confirm the saved delivery." });
                        return res.json({ message: "Delivery was already saved.", collectionId: matches[0].id, farmerNumber: matches[0].farmer_number, quantityKg: Number(matches[0].quantity_kg), duplicate: true });
                    });
                }
                if (err) {
                    console.error("Milk recording database error:", err);
                    return res.status(500).json({ message: clientRecordId ? "Run the offline collection migration before syncing saved deliveries." : "Failed to record milk." });
                }
                res.status(201).json({ message: "Milk recorded successfully", collectionId: result.insertId, farmerNumber: farmer.farmer_number, firstName: farmer.first_name, quantityKg: Number(quantityKg) });
                sendConfirmation({ phone: farmer.phone, firstName: farmer.first_name, farmerNumber: farmer.farmer_number, quantityKg, collectionDate: selectedDate, brandName: requestBrandName(req) })
                    .then((delivery) => {
                        console.info(`Collection SMS ${delivery.status} for collection ${result.insertId}.`);
                        if (!/^(1|true|yes)$/i.test(process.env.SMS_DELIVERY_LOG_ENABLED || "")) return;
                        db.query(`INSERT INTO sms_delivery_attempts
                            (collection_id, provider, status, provider_status_code)
                            VALUES (?, ?, ?, ?)`, [result.insertId, delivery.provider || "unknown", delivery.status, delivery.providerStatusCode || null], (logError) => {
                            if (logError) console.error("Could not save SMS delivery status:", logError.code || logError.message);
                        });
                    });
            });
        };
        db.query("SELECT farmer_number, first_name, phone FROM farmers WHERE farmer_number = ? AND status = 'active' AND route_id = ?", [farmerNumber, req.workerRouteId], (err, farmers) => {
            if (err) { console.error("Farmer check database error:", err); return res.status(500).json({ message: "Could not verify the farmer." }); }
            if (!farmers.length) return res.status(404).json({ message: "Farmer not found or inactive." });
            insert(farmers[0]);
        });
    };

    const validateDate = () => db.query("SELECT DATE_FORMAT(CURDATE(), '%Y-%m-%d') AS today", (err, rows) => {
        if (err) return res.status(500).json({ message: "Could not validate the collection date." });
        if (selectedDate < rows[0].today) return res.status(400).json({ message: "Milk cannot be recorded for a past date." });
        saveForFarmer();
    });

    if (clientRecordId) {
        db.query("SELECT id, farmer_number, quantity_kg FROM milk_collections WHERE client_record_id = ? LIMIT 1", [clientRecordId], (err, matches) => {
            if (err) { console.error("Offline sync key lookup error:", err); return res.status(500).json({ message: "Run the offline collection migration before syncing saved deliveries." }); }
            if (matches.length) return res.json({ message: "Delivery was already saved.", collectionId: matches[0].id, farmerNumber: matches[0].farmer_number, quantityKg: Number(matches[0].quantity_kg), duplicate: true });
            validateDate();
        });
    } else validateDate();
});
app.get("/milk/:farmerNumber", requireWorker, requireAssignedRoute, (req, res) => {
console.log("Milk history route reached:", req.params.farmerNumber);

    const farmerNumber = req.params.farmerNumber;
    const summaryOnly = req.query.summary === "1";

    const sql = `
        SELECT 
            collection_date,
            quantity_kg
        FROM milk_collections mc
        JOIN farmers f ON f.farmer_number = mc.farmer_number
        WHERE mc.farmer_number = ? AND f.route_id = ?
        ORDER BY collection_date DESC, id DESC
        ${summaryOnly ? "LIMIT 4" : ""}
    `;

    db.query(sql, [farmerNumber, req.workerRouteId], (err, results) => {

        if (err) {
            console.error("Database error:", err);

            return res.status(500).json({
                message: "Database error"
            });
        }

        if (summaryOnly) {
            return db.query("SELECT COALESCE(SUM(mc.quantity_kg), 0) AS totalKg, COUNT(*) AS totalCount FROM milk_collections mc JOIN farmers f ON f.farmer_number = mc.farmer_number WHERE mc.farmer_number = ? AND f.route_id = ?", [farmerNumber, req.workerRouteId], (summaryError, summaryRows) => {
                if (summaryError) {
                    console.error("Milk history summary database error:", summaryError);
                    return res.status(500).json({ message: "Could not load the farmer delivery summary." });
                }
                return res.json({ farmerNumber, totalKg: Number(summaryRows[0].totalKg), totalCount: Number(summaryRows[0].totalCount), collections: results });
            });
        }

        const totalKg = results.reduce(
            (total, record) => total + Number(record.quantity_kg),
            0
        );

        res.json({
            farmerNumber: farmerNumber,
            totalKg: totalKg,
            collections: results
        });
    });
});
console.log("Milk history route loaded");
const port = Number(process.env.PORT) || 3002;
app.listen(port, "0.0.0.0", () => {
    console.log(`Milk System server running on port ${port}`);
});
