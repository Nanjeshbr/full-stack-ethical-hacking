const sqlite3 = require("sqlite3").verbose();

const db = new sqlite3.Database("./security_audit.db", (err) => {
  if (err) {
    console.error("Database connection failed:", err.message);
  } else {
    console.log("Connected to SQLite database");
  }
});

// Create vulnerabilities table with scanned_at timestamp
db.run(`
  CREATE TABLE IF NOT EXISTS vulnerabilities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    website     TEXT,
    name        TEXT,
    description TEXT,
    severity    TEXT,
    scanned_at  TEXT DEFAULT (datetime('now'))
  )
`);

// Create scans session table
db.run(`
  CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    website     TEXT,
    total       INTEGER,
    high        INTEGER,
    medium      INTEGER,
    low         INTEGER,
    score       REAL,
    scanned_at  TEXT DEFAULT (datetime('now'))
  )
`);

module.exports = db;