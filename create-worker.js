const crypto = require("crypto");
const readline = require("readline");
require("dotenv").config();
const db = require("./db");

const workerId = process.argv[2]?.trim();
const routeId = Number(process.argv[3]);
if (!workerId || workerId.length > 50 || !Number.isInteger(routeId) || routeId <= 0) {
  console.error("Usage: npm run create-worker -- <worker-id> <active-route-id>");
  process.exit(1);
}

const terminal = readline.createInterface({ input: process.stdin, output: process.stdout });
terminal.question("New password (minimum 12 characters): ", (password) => {
  terminal.close();
  if (password.length < 12 || password.length > 256) {
    console.error("Password must be between 12 and 256 characters.");
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
    db.query("SELECT id FROM collection_routes WHERE id = ? AND active = TRUE", [routeId], (routeError, routes) => {
      if (routeError || !routes.length) {
        console.error(routeError ? "Could not validate the route." : "Choose an active route ID.");
        process.exitCode = 1;
        db.end();
        return;
      }
      db.query("INSERT INTO workers (worker_id, password_hash, route_id, session_version) VALUES (?, ?, ?, 1)", [workerId, `${salt}:${key.toString("hex")}`, routeId], (insertError) => {
        if (insertError) {
          console.error("Could not create worker:", insertError.code || insertError.message);
          process.exitCode = 1;
        } else console.log(`Worker ${workerId} created with an active route.`);
        db.end();
      });
    });
  });
});
