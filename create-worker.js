const crypto = require("crypto");
const readline = require("readline");
require("dotenv").config();
const db = require("./db");

const workerId = process.argv[2]?.trim();
if (!workerId) {
  console.error("Usage: npm run create-worker -- <worker-id>");
  process.exit(1);
}

const terminal = readline.createInterface({ input: process.stdin, output: process.stdout });
terminal.question("New password (minimum 8 characters): ", (password) => {
  terminal.close();
  if (password.length < 8) {
    console.error("Password must be at least 8 characters.");
    db.end();
    process.exitCode = 1;
    return;
  }
  const salt = crypto.randomBytes(16).toString("hex");
  crypto.scrypt(password, salt, 64, (err, key) => {
    if (err) {
      console.error("Could not hash password:", err.message);
      db.end();
      process.exitCode = 1;
      return;
    }
    db.query("INSERT INTO workers (worker_id, password_hash) VALUES (?, ?)", [workerId, `${salt}:${key.toString("hex")}`], (insertError) => {
      if (insertError) {
        console.error("Could not create worker:", insertError.message);
        process.exitCode = 1;
      } else console.log(`Worker ${workerId} created.`);
      db.end();
    });
  });
});
