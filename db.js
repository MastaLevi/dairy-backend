const mysql = require("mysql2");
const fs = require("fs");
const path = require("path");
require("dotenv").config();

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
