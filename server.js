import express from "express";
import http from "http";
import path from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";
import Database from "better-sqlite3";
import { Server } from "socket.io";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  // Große Blueprints können deutlich größer als das Socket.IO-Standardlimit
  // sein. Der Zustand wird trotzdem nur als ein kompakter JSON-Snapshot gesendet.
  maxHttpBufferSize: 16 * 1024 * 1024
});

const ACCESS_CODE = String(process.env.LOGIC_ACCESS_CODE || "").trim();
const ACCESS_SESSION_TTL = 7 * 24 * 60 * 60 * 1000;

function signAuth(ts){
  return crypto.createHmac("sha256", ACCESS_CODE).update(String(ts)).digest("hex");
}

function hasValidAuth(req){
  if(!ACCESS_CODE) return true;

  const raw = req.headers.cookie || "";
  const match = raw.match(/(?:^|;\s*)logic_auth=([^;]+)/);
  if(!match) return false;

  const value = decodeURIComponent(match[1]);
  const [ts, sig] = value.split(".");
  if(!ts || !sig || !/^\d+$/.test(ts)) return false;

  const age = Date.now() - Number(ts);
  if(age < 0 || age > ACCESS_SESSION_TTL) return false;

  const expected = signAuth(ts);
  return sig.length === expected.length &&
    crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
}

app.use(express.urlencoded({ extended: false }));

app.get("/login", (req, res) => {
  if(hasValidAuth(req)){
    res.redirect("/");
    return;
  }
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.post("/login", (req, res) => {
  if(!ACCESS_CODE){
    res.redirect("/");
    return;
  }

  const code = String(req.body.code || "");
  if(code !== ACCESS_CODE){
    res.redirect("/login?error=1");
    return;
  }

  const ts = Date.now();
  const token = encodeURIComponent(ts + "." + signAuth(ts));

  res.setHeader(
    "Set-Cookie",
    "logic_auth=" + token +
    "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=" +
    Math.floor(ACCESS_SESSION_TTL / 1000)
  );
  res.redirect("/");
});

app.use((req, res, next) => {
  if(!ACCESS_CODE){
    res.status(503).send("LOGIC_ACCESS_CODE ist in Render nicht gesetzt. Bitte die Environment Variable setzen und den Service neu deployen.");
    return;
  }
  if(req.path === "/login" || hasValidAuth(req)){
    next();
    return;
  }
  res.redirect("/login");
});

// Dauerhafte Datenbank.
// Auf Render wird dafür LOGIC_DB_PATH=/var/data/logic-builder.db gesetzt.
// /var/data liegt dann auf dem persistenten Render-Datenträger.
const DB_PATH = process.env.LOGIC_DB_PATH || path.join(__dirname, "logic-builder.db");
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("synchronous = FULL");

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

io.use((socket, next) => {
  if(!ACCESS_CODE){
    next(new Error("LOGIC_ACCESS_CODE fehlt"));
    return;
  }

  const cookie = socket.handshake.headers.cookie || "";
  const fakeReq = { headers: { cookie } };

  if(hasValidAuth(fakeReq)) next();
  else next(new Error("unauthorized"));
});

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
      // Der normale Realtime-Zustand enthält absichtlich keine komplette
      // Blueprint-Bibliothek mehr. Dadurch bleiben große Blueprints aus dem
      // schnellen Block-/Positionskanal heraus.
      const current = getState.get();
      let stored = {};
      try {
        stored = JSON.parse(current.data);
      } catch {}

      // Alte gespeicherte Blueprint-Daten bleiben erhalten.
      // Neue Block-/Wire-Daten werden nur darübergelegt.
      Object.assign(stored, state);
      if(current && Array.isArray(JSON.parse(current.data || "{}").blueprints)){
        stored.blueprints = JSON.parse(current.data).blueprints;
      }

      saveState.run(JSON.stringify(stored));

      // Die Änderung nur an die ANDEREN Besucher senden.
      socket.broadcast.emit("state", state);

    } catch (error) {
      console.error("Fehler beim Speichern des Zustands:", error);
    }
  });

  socket.on("blueprintLibraryChange", (library) => {
    try {
      if(!library || !Array.isArray(library.blueprints)) return;

      // Die große Bibliothek wird separat gespeichert und übertragen.
      // Dadurch blockiert ein großer Blueprint nicht mehr den normalen
      // Realtime-Kanal für Blockbewegungen und Verdrahtung.
      const current = getState.get();
      let stored = {};
      try {
        stored = JSON.parse(current.data);
      } catch {}

      stored.blueprints = library.blueprints;
      saveState.run(JSON.stringify(stored));

      socket.broadcast.emit("blueprintLibrary", library);
    } catch (error) {
      console.error("Fehler beim Speichern der Blueprint-Bibliothek:", error);
    }
  });
});

// Render stellt PORT bereit
const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log(`Server läuft auf Port ${PORT}`);
  console.log(`LOGIC_ACCESS_CODE gesetzt: ${ACCESS_CODE ? "JA" : "NEIN"}`);
});
