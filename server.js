const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
require("dotenv").config();
const db = require("./db");
const app = express();
const { sendConfirmation, getSmsStatus } = require("./sms");
app.use(cors());
app.use(express.json());

const tokenSecret = process.env.WORKER_TOKEN_SECRET || "local-development-secret-change-me";
const webAuthnRpId = process.env.WEBAUTHN_RP_ID || "localhost";
const webAuthnOrigins = (process.env.WEBAUTHN_ORIGIN || "http://localhost:3003")
    .split(",").map((origin) => origin.trim()).filter(Boolean);
const pendingChallenges = new Map();
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
const makeToken = (workerId) => {
    const payload = Buffer.from(JSON.stringify({ workerId, expires: Date.now() + 12 * 60 * 60 * 1000 })).toString("base64url");
    const signature = crypto.createHmac("sha256", tokenSecret).update(payload).digest("base64url");
    return `${payload}.${signature}`;
};
const makeAdminToken = () => {
    const payload = Buffer.from(JSON.stringify({ admin: true, expires: Date.now() + 4 * 60 * 60 * 1000 })).toString("base64url");
    const signature = crypto.createHmac("sha256", tokenSecret).update(payload).digest("base64url");
    return `${payload}.${signature}`;
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
        next();
    } catch { return res.status(401).json({ message: "Invalid office admin session." }); }
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
        req.workerId = session.workerId;
        next();
    } catch { return res.status(401).json({ message: "Invalid sign-in. Please sign in again." }); }
};


const authenticateWorker = (req, res) => {
    const { workerId, password } = req.body || {};
    if (typeof workerId !== "string" || !workerId.trim() || typeof password !== "string" || !password) {
        return res.status(400).json({ message: "Worker ID and password are required." });
    }
    db.query("SELECT worker_id, password_hash, active FROM workers WHERE worker_id = ? LIMIT 1", [workerId.trim()], (err, rows) => {
        if (err) {
            console.error("Worker login database error:", err);
            return res.status(500).json({ message: "Could not sign in. Check that the workers table is set up." });
        }
        const worker = rows[0];
        if (!worker || !worker.active) return res.status(401).json({ message: "Worker ID or password is incorrect." });
        const savedPassword = worker.password_hash;
        const hashParts = savedPassword.split(":");
        const isScryptHash = hashParts.length === 2 && /^[a-f\d]{32}$/i.test(hashParts[0]) && /^[a-f\d]{128}$/i.test(hashParts[1]);
        const finishLogin = (validPassword) => {
            if (!validPassword) return res.status(401).json({ message: "Worker ID or password is incorrect." });
            if (isScryptHash) return res.json({ token: makeToken(worker.worker_id), workerId: worker.worker_id });

            // Older locally-added accounts may contain a plain-text password.
            // Upgrade it immediately after a successful login.
            const salt = crypto.randomBytes(16).toString("hex");
            crypto.scrypt(password, salt, 64, (hashError, derivedKey) => {
                if (hashError) return res.status(500).json({ message: "Could not secure the worker password." });
                db.query("UPDATE workers SET password_hash = ? WHERE worker_id = ?", [`${salt}:${derivedKey.toString("hex")}`, worker.worker_id], (updateError) => {
                    if (updateError) {
                        console.error("Could not upgrade worker password:", updateError);
                        return res.status(500).json({ message: "Could not secure the worker password." });
                    }
                    return res.json({ token: makeToken(worker.worker_id), workerId: worker.worker_id });
                });
            });
        };

        if (isScryptHash) {
            crypto.scrypt(password, hashParts[0], 64, (hashError, derivedKey) => {
                if (hashError) return res.status(500).json({ message: "Could not verify worker credentials." });
                const expectedHash = Buffer.from(hashParts[1], "hex");
                finishLogin(derivedKey.length === expectedHash.length && crypto.timingSafeEqual(derivedKey, expectedHash));
            });
        } else {
            const attemptedPassword = Buffer.from(password);
            const legacyPassword = Buffer.from(savedPassword);
            const matches = attemptedPassword.length === legacyPassword.length && crypto.timingSafeEqual(attemptedPassword, legacyPassword);
            finishLogin(matches);
        }
    });
};
app.post("/workers/login", authenticateWorker);
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
app.post("/login", (req, res) => {
    const { workerId, username, password } = req.body || {};
    const loginId = String(workerId || username || "").trim();
    verifyAdminLogin(loginId, password, (err, isAdmin) => {
        if (err) console.error("Admin login lookup error:", err.code || err.message);
        if (isAdmin) return res.json({ token: makeAdminToken(), role: "admin", adminId: loginId });
        req.body = { ...(req.body || {}), workerId: loginId };
        authenticateWorker(req, res);
    });
});

app.get("/workers/passkeys/register-options", requireWorker, (req, res) => {
    const challenge = storeChallenge(`register:${req.workerId}`);
    res.json({
        challenge, rp: { id: webAuthnRpId, name: "Kwikas Dairy Collection" },
        user: { id: Buffer.from(req.workerId).toString("base64url"), name: req.workerId, displayName: `Worker ${req.workerId}` },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: { authenticatorAttachment: "platform", residentKey: "preferred", userVerification: "required" },
        attestation: "none", timeout: 60000
    });
});

app.post("/workers/passkeys/register", requireWorker, (req, res) => {
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

app.post("/workers/passkeys/login-options", (req, res) => {
    const workerId = String(req.body?.workerId || "").trim();
    if (!workerId) return res.status(400).json({ message: "Enter your worker ID first." });
    db.query("SELECT credential_id FROM worker_passkeys WHERE worker_id = ?", [workerId], (err, rows) => {
        if (err) { console.error("Passkey lookup database error:", err); return res.status(500).json({ message: "Could not load device passkeys. Run the latest backend/schema.sql." }); }
        if (!rows.length) return res.status(404).json({ message: "No device passkey is set up for this worker yet." });
        const challenge = storeChallenge(`login:${workerId}`);
        res.json({ challenge, rpId: webAuthnRpId, userVerification: "required", timeout: 60000, allowCredentials: rows.map((row) => ({ type: "public-key", id: row.credential_id })) });
    });
});

app.post("/workers/passkeys/login", (req, res) => {
    const { workerId: rawWorkerId, credentialId, clientDataJSON, authenticatorData, signature } = req.body || {};
    const workerId = String(rawWorkerId || "").trim();
    if (!workerId || !credentialId || !clientDataJSON || !authenticatorData || !signature) return res.status(400).json({ message: "Passkey response is incomplete." });
    const clientData = readClientData(clientDataJSON, "webauthn.get", `login:${workerId}`, res);
    if (!clientData) return;
    db.query("SELECT p.public_key_jwk, p.signature_counter, w.active FROM worker_passkeys p JOIN workers w ON w.worker_id = p.worker_id WHERE p.worker_id = ? AND p.credential_id = ? LIMIT 1", [workerId, credentialId], (err, rows) => {
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
                res.json({ token: makeToken(workerId), workerId });
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
app.post("/admin/login", (req, res) => {
    const suppliedUser = String(req.body?.username || "").trim();
    const suppliedPassword = String(req.body?.password || "");
    verifyAdminLogin(suppliedUser, suppliedPassword, (err, ok) => {
        if (err) { console.error("Admin login database error:", err.code || err.message); return res.status(500).json({ message: "Could not check admin sign-in. Make sure the admin table exists." }); }
        if (!ok) return res.status(401).json({ message: "The worker or office ID and password do not match." });
        res.json({ token: makeAdminToken() });
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
app.post("/admin/workers", requireAdmin, (req, res) => {
    const workerId = String(req.body?.workerId || "").trim();
    const password = String(req.body?.password || "");
    const routeId = req.body?.routeId ? Number(req.body.routeId) : null;
    if (!workerId || workerId.length > 50 || password.length < 8 || (routeId !== null && (!Number.isInteger(routeId) || routeId <= 0))) return res.status(400).json({ message: "Enter a worker ID, a password of at least 8 characters, and a valid route." });
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
    if (routeId === null) return insert(null);
    db.query("SELECT id FROM collection_routes WHERE id = ? AND active = TRUE", [routeId], (err, rows) => {
        if (err) { console.error("Admin worker route validation error:", err); return res.status(500).json({ message: "Could not check that route." }); }
        if (!rows.length) return res.status(400).json({ message: "Choose an active collection route." });
        insert(routeId);
    });
});
app.post("/admin/farmers", requireAdmin, (req, res) => {
    const farmerNumber = String(req.body?.farmerNumber || "").trim();
    const firstName = String(req.body?.firstName || "").trim();
    const phone = String(req.body?.phone || "").trim();
    const routeId = req.body?.routeId ? Number(req.body.routeId) : null;
    if (!farmerNumber || farmerNumber.length > 20 || !firstName || firstName.length > 50 || !phone || phone.length > 20 || (routeId !== null && (!Number.isInteger(routeId) || routeId <= 0))) return res.status(400).json({ message: "Enter a farmer number, name, phone, and a valid optional route." });
    const cleanPhone = phone.replace(/[\s()-]/g, "");
    if (!/^(?:0[17]\d{8}|254[17]\d{8}|\+254[17]\d{8})$/.test(cleanPhone)) return res.status(400).json({ message: "Enter a valid Kenyan mobile number, such as 0712 345 678 or +254 712 345 678." });
    const insert = (route) => db.query("INSERT INTO farmers (farmer_number, first_name, phone, status, zone, route_id) VALUES (?, ?, ?, 'active', ?, ?)", [farmerNumber, firstName, phone, route?.routeName || null, route?.id || null], (err) => {
        if (err?.code === "ER_DUP_ENTRY") return res.status(409).json({ message: "That farmer number already exists." });
        if (err) { console.error("Admin farmer insert database error:", err); return res.status(500).json({ message: "Could not add farmer." }); }
        res.status(201).json({ message: "Farmer added.", farmerNumber });
    });
    if (routeId === null) return insert(null);
    db.query("SELECT id, route_name AS routeName FROM collection_routes WHERE id = ? AND active = TRUE", [routeId], (err, rows) => {
        if (err) { console.error("Admin farmer route validation error:", err); return res.status(500).json({ message: "Could not check that route." }); }
        if (!rows.length) return res.status(400).json({ message: "Choose an active collection route." });
        insert(rows[0]);
    });
});
app.get("/workers/dashboard", requireWorker, (req, res) => {
    const todaySql = `SELECT COALESCE(SUM(quantity_kg), 0) AS todayKg, COUNT(*) AS todayCount
        FROM milk_collections WHERE collector_id = ? AND collection_date = CURDATE()`;
    const routeSql = `SELECT r.route_name AS routeName,
        COALESCE(SUM(CASE WHEN w.route_id IS NULL OR collecting_worker.route_id = w.route_id THEN mc.quantity_kg ELSE 0 END), 0) AS routeKg,
        COUNT(CASE WHEN w.route_id IS NULL OR collecting_worker.route_id = w.route_id THEN mc.id END) AS routeCount,
        COUNT(DISTINCT CASE WHEN (w.route_id IS NULL OR collecting_worker.route_id = w.route_id) AND (w.route_id IS NULL OR collected_farmer.route_id = w.route_id) AND collected_farmer.status = 'active' THEN mc.farmer_number END) AS farmersCollected,
        (SELECT COUNT(*) FROM farmers f WHERE f.status = 'active' AND (w.route_id IS NULL OR f.route_id = w.route_id)) AS farmersOnRoute
        FROM workers w LEFT JOIN collection_routes r ON r.id = w.route_id
        LEFT JOIN milk_collections mc ON mc.collection_date = CURDATE()
        LEFT JOIN workers collecting_worker ON collecting_worker.worker_id = mc.collector_id
        LEFT JOIN farmers collected_farmer ON collected_farmer.farmer_number = mc.farmer_number
        WHERE w.worker_id = ? GROUP BY r.route_name`;
    const recentSql = `SELECT mc.farmer_number AS farmerNumber, f.first_name AS firstName,
        mc.quantity_kg AS quantityKg, DATE_FORMAT(mc.collection_date, '%Y-%m-%d') AS collectionDate,
        (mc.collector_id IS NULL) AS unassigned
        FROM milk_collections mc LEFT JOIN farmers f ON f.farmer_number = mc.farmer_number
        WHERE mc.collector_id = ? OR mc.collector_id IS NULL
        ORDER BY mc.collection_date DESC, mc.id DESC LIMIT 8`;
    db.query(todaySql, [req.workerId], (todayError, totals) => {
        if (todayError) {
            console.error("Worker dashboard database error:", todayError);
            return res.status(500).json({ message: "Could not load dashboard. Run the offline collection migration first." });
        }
        db.query(recentSql, [req.workerId], (recentError, recent) => {
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
app.get("/farmers/:farmerNumber", requireWorker, (req, res) => {

    const farmerNumber = req.params.farmerNumber;

    const sql = `
        SELECT farmer_number, first_name
        FROM farmers
        WHERE farmer_number = ?
        AND status = 'active'
    `;

    db.query(sql, [farmerNumber], (err, results) => {

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

app.post("/milk", requireWorker, (req, res) => {
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
                sendConfirmation({ phone: farmer.phone, firstName: farmer.first_name, farmerNumber: farmer.farmer_number, quantityKg, collectionDate: selectedDate })
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
        db.query("SELECT farmer_number, first_name, phone FROM farmers WHERE farmer_number = ? AND status = 'active'", [farmerNumber], (err, farmers) => {
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
app.get("/milk/:farmerNumber", requireWorker, (req, res) => {
console.log("Milk history route reached:", req.params.farmerNumber);

    const farmerNumber = req.params.farmerNumber;

    const sql = `
        SELECT 
            collection_date,
            quantity_kg
        FROM milk_collections
        WHERE farmer_number = ?
        ORDER BY collection_date DESC, id DESC
    `;

    db.query(sql, [farmerNumber], (err, results) => {

        if (err) {
            console.error("Database error:", err);

            return res.status(500).json({
                message: "Database error"
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
