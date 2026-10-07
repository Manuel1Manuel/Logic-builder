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
  maxHttpBufferSize: 64 * 1024 * 1024
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

// AI-API bleibt ausschließlich serverseitig.
// Der API-Key kommt aus Render: GROQ_API_KEY.
app.use(express.json({ limit: "256kb" }));

app.post("/api/gemini", async (req, res) => {
  if(!process.env.GROQ_API_KEY){
    res.status(503).json({ error: "GROQ_API_KEY ist nicht gesetzt." });
    return;
  }

  const prompt = typeof req.body?.prompt === "string" ? req.body.prompt.trim() : "";
  const context = typeof req.body?.context === "string" ? req.body.context : "";
  if(!prompt){
    res.status(400).json({ error: "Kein Prompt angegeben." });
    return;
  }
  if(prompt.length > 20000){
    res.status(413).json({ error: "Der Prompt ist zu lang." });
    return;
  }

  const systemContext = `Du bist die integrierte KI des Logic Builder Ultra.
Du kennst die Logikgatter dieses Editors:
switch = Schalter/Eingang, lamp = Lampe, not = NOT, or3 = OR mit 3 Eingängen,
and = AND mit 2 Eingängen, or = OR mit 2 Eingängen, xor = XOR mit 2 Eingängen,
timer = Zeitglied, output = Ausgang, key = Tasteneingang, clock = Taktgeber,
memory = Speicherbaustein, led = LED.
Jeder Block hat eine Position x/y auf der Arbeitsfläche. wires verbinden from zu to; inputIndex ist der Eingang des Zielblocks.
Die aktuelle Schaltung und die Blueprint-Bibliothek werden dir als Kontext übergeben.
Wenn der Nutzer nur etwas wissen will, gib eine normale Antwort und keine Aktionen.
Wenn der Nutzer ausdrücklich darum bittet, darfst du die Arbeitsfläche direkt verändern.
Verwende dafür ausschließlich die bereitgestellten Aktionen:
- add_gate: neues Gatter mit type, x, y, optional name
- delete_gate: Gatter anhand seines aktuellen index löschen
- move_gate: Gatter anhand index nach x/y verschieben
- connect: Wire von from zu to mit inputIndex verbinden
- disconnect: passenden Wire von from zu to entfernen
- rename_gate: Gatter anhand index umbenennen
- set_switch: Schalterzustand setzen
- set_timer: Timer delay/stay setzen
- set_clock: Clock interval setzen
Die Indizes sind die aktuellen Node-Indizes aus dem Kontext. Neue Gatter erhalten fortlaufend die Indizes ab nodeCount; plane neue Gatter zuerst und verdrahte sie danach.
Führe niemals eine Aktion nur deshalb aus, weil du behauptest, etwas getan zu haben: Gib die Aktion als strukturierte Ausgabe zurück, damit der Editor sie tatsächlich ausführt.
Erfinde keine vorhandenen Blöcke und ändere nichts ohne ausdrücklichen Auftrag.
${context ? "\nAKTUELLER APP-KONTEXT:\n" + context : ""}

NUTZERANFRAGE:
${prompt}`;

  const response = await fetch(
    "https://api.groq.com/openai/v1/chat/completions",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + process.env.GROQ_API_KEY
      },
      body: JSON.stringify({
        model: "openai/gpt-oss-120b",
        messages: [{
          role: "system",
          content: systemContext + "\n\nWICHTIG: Antworte ausschließlich mit gültigem JSON im Format {\"answer\":\"...\",\"actions\":[...]}."
        }],
        response_format: { type: "json_object" }
      })
    }
  );
  const provider = "Groq";
  const data = await response.json();

  if(!response.ok){
    console.error("Groq API Fehler:", data);
    res.status(502).json({
      error: "Groq API Fehler.",
      details: data?.error?.message || "Unbekannter Fehler"
    });
    return;
  }

  const raw = data?.choices?.[0]?.message?.content || "{}";
  let result;
  try{
    result = JSON.parse(raw);
  }catch{
    result = { answer: raw, actions: [] };
  }
  res.json({
    text: result.answer || "",
    actions: Array.isArray(result.actions) ? result.actions : [],
    provider
  });
});

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

db.exec(`
  CREATE TABLE IF NOT EXISTS app_meta (
    id INTEGER PRIMARY KEY,
    revision INTEGER NOT NULL
  )
`);

db.prepare(`
  INSERT OR IGNORE INTO app_meta (id, revision)
  VALUES (1, 0)
`).run();
const getState = db.prepare(`
  SELECT data FROM app_state WHERE id = 1
`);

function getServerStorageBytes(){
  try{
    return Buffer.byteLength(String(getState.get()?.data || ""), "utf8");
  }catch{
    return 0;
  }
}

const saveState = db.prepare(`
  UPDATE app_state
  SET data = ?
  WHERE id = 1
`);

const getRevision = db.prepare(`
  SELECT revision FROM app_meta WHERE id = 1
`);

const saveRevision = db.prepare(`
  UPDATE app_meta
  SET revision = ?
  WHERE id = 1
`);
// Einmalige Bereinigung des alten gespeicherten Arbeitsflächenstands.
// Code/Blueprint-Definitionen bleiben im Repository unverändert; nur der
// bisher persistierte Zustand (Gatter/Wires/gespeicherte Bibliothek) wird
// einmalig geleert, damit alte Testdaten nicht wieder als Serverstand
// auftauchen können.
db.exec(`
  CREATE TABLE IF NOT EXISTS app_migrations (
    id TEXT PRIMARY KEY
  )
`);
const resetMigrationId = "clear_saved_logic_state_2026_10_06_v1";
const resetMigration = db.prepare(`
  INSERT OR IGNORE INTO app_migrations (id) VALUES (?)
`).run(resetMigrationId);
if(resetMigration.changes === 1){
  saveState.run(JSON.stringify({}));
  saveRevision.run(0);
  console.log("Gespeicherten Logic-Builder-Zustand einmalig geleert.");
}


let stateRevision = Number(getRevision.get()?.revision) || 0;

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
    const initialState = JSON.parse(row.data);
    initialState.serverRevision = stateRevision;
    initialState.serverStorageBytes = getServerStorageBytes();
    socket.emit("state", initialState);
  } catch {
    socket.emit("state", { serverRevision: stateRevision });
  }

  // Erst nach dem Empfang und Anwenden des initialen Server-Zustands darf
  // dieser Client wieder schreiben. Dadurch kann ein alter lokaler Stand
  // niemals den gerade geladenen Serverstand überschreiben.
  socket.lastAppliedRevision = stateRevision - 1;

  socket.on("stateApplied", (revision) => {
    if(Number.isInteger(revision) && revision === stateRevision){
      socket.lastAppliedRevision = revision;
    }
  });

  // Änderung von einem Besucher empfangen
  socket.on("stateChange", (state) => {

    try {
      const baseRevision = Number.isInteger(state?.baseRevision) ? state.baseRevision : null;

      // Alte/offene Browser-Tabs aus einer früheren Client-Version haben keine
      // baseRevision. Sie dürfen niemals einen aktuellen Serverstand überschreiben.
      if(baseRevision === null){
        const current = getState.get();
        const currentState = JSON.parse(current.data || "{}");
        currentState.serverRevision = stateRevision;
        currentState.serverStorageBytes = getServerStorageBytes();
        currentState.sourceSocketId = "server-rejected-legacy";
        socket.emit("state", currentState);
        socket.emit("stateRejected", { serverRevision: stateRevision, reason: "missing-base-revision" });
        return;
      }

      // Veraltete Vollzustände dürfen niemals einen neueren Zustand zurücksetzen.
      // Das verhindert, dass z.B. eine Löschung durch einen alten Poll-Zustand
      // von einem anderen Client wieder auftaucht.
      if(baseRevision !== stateRevision || socket.lastAppliedRevision !== stateRevision){
        const current = getState.get();
        const currentState = JSON.parse(current.data || "{}");
        currentState.serverRevision = stateRevision;
        currentState.serverStorageBytes = getServerStorageBytes();
        currentState.sourceSocketId = "server-rejected";
        socket.emit("state", currentState);
        socket.emit("stateRejected", { serverRevision: stateRevision });
        return;
      }
      // Der normale Realtime-Zustand enthält absichtlich keine komplette
      // Blueprint-Bibliothek mehr. Dadurch bleiben große Blueprints aus dem
      // schnellen Block-/Positionskanal heraus.
      const current = getState.get();
      let stored = {};
      try {
        stored = JSON.parse(current.data);
      } catch {}

      // Der Transportwert baseRevision gehört niemals in den gespeicherten
      // Zustand. Er dient nur dazu, veraltete Clients zu erkennen.
      const cleanState = { ...state };
      delete cleanState.baseRevision;
      delete cleanState.serverRevision;

      // Alte gespeicherte Blueprint-Daten bleiben erhalten.
      // Neue Block-/Wire-Daten werden nur darübergelegt.
      Object.assign(stored, cleanState);
      if(current && Array.isArray(JSON.parse(current.data || "{}").blueprints)){
        stored.blueprints = JSON.parse(current.data).blueprints;
      }

      // Erst speichern, dann die neue Revision dauerhaft sichern.
      // Dadurch geht die Versionsnummer bei einem Render-Neustart nicht zurück.
      const storedJson = JSON.stringify(stored);
      saveState.run(storedJson);
      const serverStorageBytes = Buffer.byteLength(storedJson, "utf8");
      stateRevision++;
      saveRevision.run(stateRevision);
      socket.lastAppliedRevision = stateRevision;

      // Wirklich den gespeicherten Serverstand zurückgeben, nicht nur das
      // eingegangene Paket. Der Absender bekommt ihn ebenfalls zurück.
      const broadcastState = {
        ...stored,
        serverRevision: stateRevision,
        serverStorageBytes,
        sourceSocketId: socket.id
      };

      const nodeCount = Array.isArray(stored.nodes) ? stored.nodes.length : 0;
      const wireCount = Array.isArray(stored.wires) ? stored.wires.length : 0;

      io.emit("state", broadcastState);
      socket.emit("stateAck", {
        serverRevision: stateRevision,
        confirmed: true,
        nodeCount,
        wireCount,
        serverStorageBytes
      });

    } catch (error) {
      console.error("Fehler beim Speichern des Zustands:", error);
    }
  });

  socket.on("blueprintLibraryChange", (library) => {
    try {
      if(!library || !Array.isArray(library.blueprints)) return;

      const baseRevision = Number.isInteger(library.baseRevision) ? library.baseRevision : null;
      if(baseRevision === null || baseRevision !== stateRevision || socket.lastAppliedRevision !== stateRevision){
        const current = getState.get();
        const currentState = JSON.parse(current.data || "{}");
        socket.emit("blueprintLibrary", {
          blueprints: Array.isArray(currentState.blueprints) ? currentState.blueprints : [],
          serverRevision: stateRevision,
          serverStorageBytes: getServerStorageBytes()
        });
        socket.emit("stateRejected", { serverRevision: stateRevision, reason: "blueprint-revision-conflict" });
        return;
      }

      // Die große Bibliothek wird separat gespeichert und übertragen.
      // Dadurch blockiert ein großer Blueprint nicht mehr den normalen
      // Realtime-Kanal für Blockbewegungen und Verdrahtung.
      const current = getState.get();
      let stored = {};
      try {
        stored = JSON.parse(current.data);
      } catch {}

      stored.blueprints = library.blueprints;
      const storedJson = JSON.stringify(stored);
      saveState.run(storedJson);

      stateRevision++;
      saveRevision.run(stateRevision);
      socket.lastAppliedRevision = stateRevision;

      const payload = {
        blueprints: library.blueprints,
        serverRevision: stateRevision,
        serverStorageBytes: Buffer.byteLength(storedJson, "utf8")
      };

      io.emit("blueprintLibrary", payload);
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
