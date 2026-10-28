const mysql = require("mysql2");
const fs = require("fs");
const path = require("path");
require("dotenv").config();

if (process.env.NODE_ENV === "production") {
    const required = ["DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME"];
    const missing = required.filter((key) => !process.env[key]);
    if (missing.length) throw new Error(`Missing production database settings: ${missing.join(", ")}`);
    if (!/^(1|true|yes)$/i.test(process.env.DB_SSL || "")) {
        throw new Error("DB_SSL must be enabled in production.");
    }
    if (/^(0|false|no)$/i.test(process.env.DB_SSL_REJECT_UNAUTHORIZED || "true")) {
        throw new Error("DB_SSL_REJECT_UNAUTHORIZED cannot be disabled in production.");
    }
}

const sslEnabled = /^(1|true|yes)$/i.test(process.env.DB_SSL || "");
const rejectUnauthorized = !/^(0|false|no)$/i.test(process.env.DB_SSL_REJECT_UNAUTHORIZED || "true");
let ssl;
if (sslEnabled) {
    const caPath = process.env.DB_SSL_CA;
    const ca = process.env.DB_SSL_CA_CERT || (caPath ? fs.readFileSync(path.resolve(caPath), "utf8") : undefined);
    ssl = { rejectUnauthorized, ...(ca ? { ca } : {}) };
}

const db = mysql.createPool({
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "",
    database: process.env.DB_NAME || "dairy_company",
    port: Number(process.env.DB_PORT) || 3306,
    ...(ssl ? { ssl } : {})
});

module.exports = db;
