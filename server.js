import express from "express";
import http from "http";
import path from "path";
import { fileURLToPath } from "url";
import Database from "better-sqlite3";
import { Server } from "socket.io";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Datenbank
const db = new Database("clicks.db");

db.exec(`
  CREATE TABLE IF NOT EXISTS counter (
    id INTEGER PRIMARY KEY,
    clicks INTEGER NOT NULL
  )
`);

db.prepare(`
  INSERT OR IGNORE INTO counter (id, clicks)
  VALUES (1, 0)
`).run();

const getClicks = db.prepare(
  "SELECT clicks FROM counter WHERE id = 1"
);

const addClick = db.prepare(
  "UPDATE counter SET clicks = clicks + 1 WHERE id = 1"
);

// Website-Dateien
app.use(express.static(path.join(__dirname, "public")));

// Aktuellen Stand abfragen
app.get("/api/clicks", (req, res) => {
  res.json({
    clicks: getClicks.get().clicks
  });
});

// Besucher verbinden
io.on("connection", (socket) => {

  // aktuellen Stand an neuen Besucher senden
  socket.emit("clicks", getClicks.get().clicks);

  // Klick empfangen
  socket.on("click", () => {

    // Zähler erhöhen
    addClick.run();

    // neuen Stand an ALLE Besucher schicken
    io.emit("clicks", getClicks.get().clicks);
  });
});

// Render stellt PORT bereit
const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log(`Server läuft auf Port ${PORT}`);
});
