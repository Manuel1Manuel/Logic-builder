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
const io = new Server(server);

const ACCESS_CODE = process.env.LOGIC_ACCESS_CODE || "";
const ACCESS_SESSION_TTL = 7 * 24 * 60 * 60 * 1000;

function signAuth(ts){
  return crypto.createHmac("sha256", ACCESS_CODE).update(String(ts)).digest("hex");
}

function getAuthCookie(req){
  const raw = req.headers.cookie || "";
  const match = raw.match(/(?:^|;\\s*)logic_auth=([^;]+)/);
  if(!match) return false;
  const value = decodeURIComponent(match[1]);
  const [ts, sig] = value.split(".");
  if(!ts || !sig || !/^\\d+$/.test(ts)) return false;
  const age = Date.now() - Number(ts);
  if(age < 0 || age > ACCESS_SESSION_TTL) return false;
  const expected = signAuth(ts);
  return sig.length === expected.length &&
    crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
}

app.use(express.urlencoded({ extended: false }));

app.get("/login", (req, res) => {
  if(!ACCESS_CODE || getAuthCookie(req)){
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
  res.setHeader("Set-Cookie", "logic_auth=" + token + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=" + Math.floor(ACCESS_SESSION_TTL/1000));
  res.redirect("/");
});

app.use((req, res, next) => {
  if(!ACCESS_CODE || req.path === "/login" || getAuthCookie(req)){
    next();
    return;
  }
  res.redirect("/login");
});

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
io.use((socket, next) => {
  if(!ACCESS_CODE){
    next();
    return;
  }
  const cookie = socket.handshake.headers.cookie || "";
  const fakeReq = { headers: { cookie } };
  if(getAuthCookie(fakeReq)) next();
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
      const data = JSON.stringify(state);

      // Zustand speichern
      saveState.run(data);

      // Die Änderung nur an die ANDEREN Besucher senden.
      // Der Absender behält seine lokale Maus-/Drag-Bewegung und bekommt
      // nicht sofort seinen eigenen Stand vom Server zurück.
      socket.broadcast.emit("state", state);

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
