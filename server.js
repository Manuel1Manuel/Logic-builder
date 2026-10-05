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
const db = new Database("logic-builder.db");

db.exec(`
  CREATE TABLE IF NOT EXISTS app_state (
    id INTEGER PRIMARY KEY,
    data TEXT NOT NULL
  )
`);

db.prepare(`
  INSERT OR IGNORE INTO app_state (id, data)
  VALUES (1, '{}')
`).run();

const getState = db.prepare(`
  SELECT data FROM app_state WHERE id = 1
`);

const saveState = db.prepare(`
  UPDATE app_state
  SET data = ?
  WHERE id = 1
`);

// Website-Dateien
app.use(express.static(path.join(__dirname, "public")));

// Besucher verbinden
io.on("connection", (socket) => {

  // Aktuellen Logic-Builder-Zustand an neuen Besucher senden
  const row = getState.get();

  try {
    socket.emit("state", JSON.parse(row.data));
  } catch {
    socket.emit("state", {});
  }

  // Änderung von einem Besucher empfangen
  socket.on("stateChange", (state) => {

    try {
      const data = JSON.stringify(state);

      // Zustand speichern
      saveState.run(data);

      // Zustand sofort an ALLE Besucher senden
      io.emit("state", state);

    } catch (error) {
      console.error("Fehler beim Speichern des Zustands:", error);
    }
  });
});

// Render stellt PORT bereit
const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log(`Server läuft auf Port ${PORT}`);
});
