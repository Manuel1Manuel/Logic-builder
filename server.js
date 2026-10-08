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

// AI-APIs bleiben ausschließlich serverseitig.
// Die API-Keys kommen aus Render Environment Variables.
app.use(express.json({ limit: "256kb" }));

app.post("/api/gemini", async (req, res) => {
  const requestedProvider = String(req.body?.provider || "gemini").toLowerCase();
  const provider = requestedProvider === "groq"
    ? "Groq"
    : requestedProvider === "openrouter"
      ? "OpenRouter"
      : "Gemini";
  const apiKey = provider === "Groq"
    ? String(process.env.GROQ_API_KEY || "").trim()
    : provider === "OpenRouter"
      ? String(process.env.OPENROUTER_API_KEY || "").trim()
      : String(process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || "").trim();

  if(!apiKey){
    res.status(503).json({
      error: provider + " API-Key ist nicht gesetzt.",
      details: provider === "Groq"
        ? "Bitte GROQ_API_KEY in Render Environment setzen."
        : provider === "OpenRouter"
          ? "Bitte OPENROUTER_API_KEY in Render Environment setzen."
          : "Bitte GEMINI_API_KEY (oder GOOGLE_API_KEY) in Render Environment setzen."
    });
    return;
  }

  const prompt = typeof req.body?.prompt === "string" ? req.body.prompt.trim() : "";
  const context = typeof req.body?.context === "string" ? req.body.context : "";
  const libraryLearn = req.body?.libraryLearn === true;
  const libraryEntry = req.body?.libraryEntry && typeof req.body.libraryEntry === "object" ? req.body.libraryEntry : null;

  if(libraryLearn){
    if(!libraryEntry){
      res.status(400).json({ error: "Kein KI-Wissenseintrag angegeben." });
      return;
    }

    const learningPrompt = `Analysiere diesen ausdrücklich als KI-Wissen gespeicherten Logic-Builder-Eintrag.
Name: ${String(libraryEntry.name || "")}
Zeitpunkt: ${String(libraryEntry.createdAt || "")}
Blueprint-Daten:
${JSON.stringify(libraryEntry.blueprint || {})}

Erkläre kurz und konkret:
1. Was für eine Schaltung ist das und welche Funktion hat sie?
2. Welche wichtigen Gatter, Ein-/Ausgänge und Verbindungen erkennst du?
3. Warum könnte diese konkrete Struktur für den Namen bzw. die Funktion sinnvoll sein?
4. Was sollte Manuel KI sich als praktische Referenz für spätere Logic-Builder-Aufgaben merken?

Tu nicht so, als hättest du dein Grundmodell dauerhaft trainiert. Formuliere stattdessen eine verständliche Referenz-Erklärung, die später zusammen mit dem gespeicherten Eintrag erneut als Kontext verwendet werden kann.
Antworte nur als JSON mit dem Feld "understanding".`;

    try{
      const learnUrl = provider === "Groq"
        ? "https://api.groq.com/openai/v1/chat/completions"
        : provider === "OpenRouter"
          ? "https://openrouter.ai/api/v1/chat/completions"
          : "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions";
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 45000);
      const response = await fetch(
        learnUrl,
        {
          method: "POST",
          signal: controller.signal,
          headers: {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + apiKey
          },
          body: JSON.stringify({
            model: provider === "Groq" ? "openai/gpt-oss-120b" : provider === "OpenRouter" ? "openrouter/auto" : "gemini-3.8-flash",
            messages: [{
              role: "system",
              content: "Du bist Manuel KI. Du analysierst ausschließlich Logic-Builder-Schaltungen als Referenzwissen. Keine Editor-Aktionen."
            },{
              role: "user",
              content: learningPrompt
            }],
            ...(provider === "Groq" ? { temperature: 0, max_completion_tokens: 4096 } : { max_tokens: 4096 })
          })
        }
      );
      clearTimeout(timeout);
      const data = await response.json().catch(() => ({}));
      if(!response.ok){
        const details = data?.error?.message || data?.message || ("HTTP " + response.status + " " + response.statusText);
        console.error(provider+" API Fehler:", response.status, data);
        res.status(502).json({
          error: provider+" API Fehler.",
          details,
          status: response.status
        });
        return;
      }
      const raw = data?.choices?.[0]?.message?.content || "{}";
      let parsed={};
      try{parsed=JSON.parse(raw);}catch{}
      res.json({text:typeof parsed.understanding==="string"?parsed.understanding.trim():"",actions:[],provider});
      return;
    }catch(error){
      console.error("Fehler beim Analysieren des KI-Wissens:",error);
      const details = error?.name === "AbortError"
        ? "Gemini/Groq hat innerhalb von 45 Sekunden nicht geantwortet."
        : String(error?.message || error);
      res.status(502).json({error:provider+" API Fehler.",details});
      return;
    }
  }

  if(!prompt){
    res.status(400).json({ error: "Kein Prompt angegeben." });
    return;
  }
  if(prompt.length > 20000){
    res.status(413).json({ error: "Der Prompt ist zu lang." });
    return;
  }

  const systemContext = `Du bist die integrierte KI namens Manuel KI des Logic Builder Ultra.
Du heißt Manuel KI. Du bist nicht Guark und darfst dich niemals als Guark bezeichnen.
Dein Aufgabenbereich ist ausschließlich der Logic Builder. Beantworte nur Fragen und Anweisungen, die den Logic Builder, seine Schaltungen, Gatter, Chips/Blueprints, Simulation, Bedienung, gespeicherte Schaltungen oder direkt zugehörige Funktionen betreffen.
Bei Anfragen außerhalb dieses Aufgabenbereichs führe keine Aktionen aus und antworte kurz, dass du ausschließlich beim Logic Builder helfen kannst.

DEIN TECHNISCHES WISSEN ÜBER DEN EDITOR:
Der Editor ist eine browserbasierte JavaScript-Anwendung. Die Arbeitsfläche besteht aus einem Array "nodes" mit allen Blöcken und einem Array "wires" mit allen Verbindungen.
Jeder Node besitzt mindestens einen Typ und eine Position x/y. Der Node-Index ist die aktuelle Position des Nodes im nodes-Array und wird in den Aktionen als "index" verwendet.
Die unterstützten Gattertypen sind:
switch = Schalter/Eingang, lamp = Lampe, not = NOT, or3 = OR mit 3 Eingängen,
and = AND mit 2 Eingängen, or = OR mit 2 Eingängen, xor = XOR mit 2 Eingängen,
timer = Zeitglied, output = Ausgang, key = Tasteneingang, clock = Taktgeber,
memory = Speicherbaustein, led = LED.
Wires verbinden einen Quell-Node "from" mit einem Ziel-Node "to". "inputIndex" bestimmt, an welchen Eingang des Zielblocks die Verbindung geht.
Die aktuelle Schaltung und die Blueprint-Bibliothek werden dir als Kontext übergeben. Unter "aiKnowledge" kann dir auf ausdrückliche Aufforderung des Nutzers die private, chronologisch geordnete KI-Wissensbibliothek bereitgestellt werden. Sie ist absichtlich NICHT Teil jeder normalen Anfrage. Wenn "aiKnowledge" im Kontext vorhanden ist, darfst du die enthaltenen Einträge als interne Referenz verwenden. Wenn der Nutzer ausdrücklich verlangt, einen KI-Wissenseintrag zu ändern, zu korrigieren, umzubenennen oder zu ergänzen, nutze update_ai_knowledge mit dem passenden Index aus dem bereitgestellten aiKnowledge-Kontext. Behaupte nicht, dein Grundmodell sei dadurch neu trainiert worden; es handelt sich um dauerhaft gespeicherten Kontext, den du bei Anfragen wiederverwenden kannst. Der Kontext ist der aktuelle Zustand zum Zeitpunkt der Anfrage; arbeite immer mit diesen aktuellen Indizes und Zuständen. Chip-Nodes enthalten chipId, chipPin und chipName, damit ein kompletter Chip eindeutig vervielfältigt oder gespeichert werden kann.

SO FUNKTIONIERT DIE AKTIONSAUSGABE:
Du antwortest ausschließlich mit dem vorgegebenen JSON-Schema. "answer" ist die kurze Erklärung für den Nutzer, "actions" enthält die tatsächlich auszuführenden Editor-Aktionen.
Verwende ausschließlich diese Aktionen:
- add_gate: neues Gatter mit type, x, y, optional name
- delete_gate: Gatter anhand seines aktuellen index löschen
- move_gate: Gatter anhand index nach x/y verschieben
- connect: Wire von from zu to mit inputIndex verbinden
- disconnect: passenden Wire von from zu to entfernen
- rename_gate: Gatter anhand index umbenennen
- set_switch: Schalterzustand setzen
- set_timer: Timer delay/stay setzen
- set_clock: Clock interval setzen
- save_chip: nur wenn der Nutzer AUSDRÜCKLICH verlangt, einen Schaltungsverbund als Chip/Blueprint zu speichern; den Schaltungsverbund rund um einen Node als Blueprint in die Blueprint-Bibliothek speichern und als Chip markieren
- copy_chip: nur wenn der Nutzer ausdrücklich einen Chip/Blueprint vervielfältigen möchte; einen vorhandenen Chip ODER den Schaltungsverbund rund um einen Node als Chip vervielfältigen; x/y ist die neue Position
- place_blueprint: einen Blueprint aus der Blueprint-Bibliothek anhand blueprintIndex auf der Arbeitsfläche platzieren; x/y ist die neue Position
- select_nodes: die angegebenen aktuellen Node-Indizes auswählen; indices ist die vollständige Liste der gewünschten Nodes
- open_chip_popup: das sichtbare Speichern-Fenster für die aktuelle Auswahl öffnen; nur verwenden, wenn der Nutzer ausdrücklich einen Chip/Blueprint speichern oder daraus einen Chip machen möchte
- confirm_chip_save: im geöffneten Speichern-Fenster sichtbar den Chip-Modus aktivieren und den Speichern-Button ausführen; nur zusammen mit einem ausdrücklich gewünschten Chip/Blueprint-Speichervorgang verwenden
- update_ai_knowledge: einen ausdrücklich genannten Eintrag der KI-Wissensbibliothek bearbeiten; "index" ist der Index aus dem aiKnowledge-Kontext, "name" und/oder "understanding" enthalten die neuen Werte. Nur verwenden, wenn der Nutzer ausdrücklich das KI-Wissen ändern, korrigieren, umbenennen oder ergänzen lassen möchte.

WICHTIG ZU INDIZES UND MEHREREN AKTIONEN:
Ein "index" ist kein dauerhafter Name. Beim Löschen eines Nodes rücken nachfolgende Nodes im nodes-Array nach und können dadurch neue Indizes bekommen.
Wenn du mehrere Nodes löschen willst, gib delete_gate-Aktionen in absteigender Index-Reihenfolge aus, also vom höchsten zum niedrigsten Index. So bleiben die niedrigeren Zielindizes korrekt.
Wenn du mehrere Nodes umbenennen, schalten, verschieben oder konfigurieren willst, verwende für jeden Node den Index aus dem aktuellen Kontext.
Wenn du eine komplette Schaltung löschen sollst, lösche ALLE aktuell vorhandenen löschbaren Nodes aus dem Kontext und nicht nur einige Beispiele. Lampen sind dabei nicht löschbar, sofern der Nutzer nicht ausdrücklich eine konkrete Lampenänderung verlangt.
Wenn der Nutzer "alles", "alle", "komplett", "die ganze Schaltung" oder sinngemäß dasselbe sagt, interpretiere das auf alle aktuell passenden Nodes/Wires des aktuellen Kontexts, nicht auf eine kleine Auswahl.
Beim Umbenennen mehrerer Nodes muss für jeden passenden Node eine eigene rename_gate-Aktion ausgegeben werden. Beispiel: "Alle Schalter A in B umbenennen" bedeutet: alle aktuell vorhandenen passenden Schalter finden und jeden einzelnen umbenennen.
Bei "alle A in B umbenennen" ist A das bisherige Kriterium bzw. der bisherige Name und B der neue Name. Führe die Umbenennung für ALLE Treffer aus.
Bei globalen Änderungen darfst du nicht bei der ersten passenden Instanz aufhören.
Bei Aktionen, die neue Nodes erzeugen, erhalten neue Gatter fortlaufende Indizes ab dem aktuellen nodeCount. Plane bei einer neuen Schaltung die vollständige Aktionenkette und verwende danach die korrekten neuen Indizes für die Verbindungen.
CHIPS NUR AUF AUSDRÜCKLICHE ANWEISUNG:
Erstelle, speichere oder aktiviere NIEMALS automatisch einen Chip, nur weil du eine Schaltung aufgebaut hast. Eine normale Anfrage wie „baue“, „erstelle“, „mache“, „verbinde“ oder „zeichne“ eine Schaltung bedeutet NUR die gewünschte Schaltung auf der Arbeitsfläche zu bauen. Solange der Nutzer nicht ausdrücklich „Chip“, „als Chip speichern“, „als Blueprint speichern“, „in die Blueprint-Bibliothek“, „als Chip aktivieren“ oder sinngemäß dasselbe verlangt, darfst du KEINE Chip-Speicheraktion ausführen und KEINEN Chip in der Bibliothek anlegen.

Wenn der Nutzer ausdrücklich einen Chip verlangt, dann baue GENAU den vom Nutzer gewünschten Schaltungsverbund. Erfinde dafür keine andere Schaltung und speichere nicht irgendeinen bereits vorhandenen Chip. Wenn der Nutzer z. B. einen Chip mit zwei Switches und zwei Outputs über Kreuz verlangt, müssen genau diese gewünschten vier Nodes und genau diese Verbindungen Grundlage des Chips sein.

WICHTIGER CHIP-SPEICHERABLAUF:
Wenn ein Chip/Blueprint ausdrücklich gespeichert werden soll, nutze den sichtbaren Editor-Ablauf, damit die Aktion auch für den Nutzer nachvollziehbar ist:
1. Baue zuerst die vom Nutzer verlangte Schaltung vollständig mit add_gate und connect auf der Arbeitsfläche.
2. Wenn die gewünschten Nodes schon existieren, verwende genau diese Nodes und erfinde keine anderen.
3. Wähle danach mit select_nodes ALLE Nodes aus, die genau zum gewünschten Chip gehören. indices muss die vollständige aktuelle Indexliste dieser Auswahl sein.
4. Öffne mit open_chip_popup das sichtbare Speichern-Fenster.
5. Danach führe mit confirm_chip_save den sichtbaren Speichervorgang aus. Diese Aktion aktiviert den Chip-Modus im Fenster und drückt den Speichern-Button. Der Nutzer soll dabei den Popup-Ablauf sehen können.
6. Verwende save_chip NICHT als Ersatz für diesen sichtbaren Ablauf, wenn der Nutzer ausdrücklich verlangt, dass du über die Auswahl und das Chip-Speicherfenster arbeitest.
7. Wenn der Nutzer danach ausdrücklich eine Kopie auf der Arbeitsfläche verlangt, füge anschließend copy_chip hinzu. Nutze dafür einen Node aus genau dem gerade gewünschten Chip.

Wenn der Nutzer nur sagt „Erstelle einen Chip mit ...“, ist das ausdrücklich eine Chip-Anweisung: Schaltung bauen, exakt die gewünschten Nodes auswählen, Popup öffnen und dort als Chip speichern. Wenn er dagegen nur „Erstelle ...“ ohne Chip/Blueprint-Bezug sagt, wird KEIN Chip gespeichert.

„Als Blueprint speichern“, „in die Blueprint-Bibliothek einfügen“ und „als Chip aktivieren“ sind ebenfalls ausdrückliche Speicheranweisungen. Verwende auch dann den sichtbaren select_nodes -> open_chip_popup -> confirm_chip_save Ablauf.

Bei copy_chip reicht als index ein Node des gewünschten Schaltungsverbunds. Ist dieser Node bereits Teil eines Chips, wird der komplette Chip über chipId verwendet. Ist er noch kein Chip, bildet der Editor den zusammenhängenden Schaltungsverbund über die vorhandenen Wires und vervielfältigt genau diesen als Chip.

Wenn der Nutzer einen Blueprint aus der Bibliothek auf die Arbeitsfläche setzen möchte, verwende place_blueprint.

Wenn der Nutzer eine normale Schaltung ohne Chip-Anweisung verlangt, darf die actions-Liste keine save_chip-, open_chip_popup- oder confirm_chip_save-Aktion enthalten.

Bei größeren Aufgaben müssen alle notwendigen add_gate-, connect-, save_chip- und gegebenenfalls copy_chip-Aktionen in derselben vollständigen actions-Liste stehen.
WICHTIG: Lehne eine vom Nutzer verlangte große oder komplexe Schaltung niemals nur wegen ihrer Größe ab. Sage niemals, dass eine Aufgabe „zu viele Gatter“ hat, „nicht sinnvoll in einem Schritt“ sei, „in kleinere Teilaufgaben aufgeteilt“ werden müsse oder dass der Nutzer konkrete Operationen erst auswählen müsse, wenn er bereits eine konkrete Gesamtaufgabe verlangt hat. Führe die gesamte Anweisung selbstständig aus und liefere ALLE dafür nötigen Aktionen in einer einzigen vollständigen actions-Liste. Das gilt ausdrücklich auch für komplette Byte-ALUs, Addierer, Subtrahierer, Vergleicher, Schiebeschaltungen und andere große Schaltungen mit vielen Gattern. Wenn die Anfrage mehrere Operationen nennt, plane die komplette Topologie selbst und baue alle verlangten Operationen. Stelle bei einer großen Schaltung nicht nur einen Teil fertig und bitte nicht um weitere Aufteilung. Wenn die Aktionliste sehr groß wird, gib trotzdem die vollständige Liste aus und nutze die verfügbaren Aktionen konsequent.

WICHTIG: SOFORTIGE AUSFÜHRUNG:
Die Aktionliste wird vom Editor als ein gemeinsamer Änderungsauftrag verarbeitet. Gib deshalb bei einer größeren Aufgabe ALLE notwendigen Aktionen in EINER vollständigen actions-Liste zurück.
Warte nicht zwischen einzelnen Gattern und erzeuge keine künstlichen Zwischenzustände. Für einen Byte-Adder oder eine andere große Schaltung müssen alle benötigten add_gate-, rename-, move- und connect-Aktionen vollständig in derselben Antwort enthalten sein, damit der Editor die Änderung als Ganzes sofort anwenden kann.
Ordne die Aktionen logisch: erst neue Nodes anlegen, dann Positionen/Benennungen setzen, danach Wires verbinden, soweit dies für die korrekten neuen Indizes nötig ist.
Behaupte niemals in "answer", dass etwas geändert wurde, wenn die entsprechende Aktion nicht in "actions" enthalten ist.
Wenn der Nutzer ausdrücklich eine Änderung verlangt, führe sie vollständig aus. Wenn er nur eine Frage stellt, gib keine Aktionen aus.

LAMPENREGEL:
Lampen dürfen nicht umbenannt werden.

ARBEITSWEISE BEI SCHALTUNGEN:
Plane die komplette Schaltung vor der Ausgabe der actions.
Jeder Block braucht eine sinnvolle x/y-Position auf der Arbeitsfläche.
Vermeide Überlappungen und unnötig enge Platzierung.
Als Richtwert sind etwa 120 Pixel Mindestabstand zwischen benachbarten Blöcken sinnvoll; bei größeren Schaltungen lieber 150–180 Pixel oder mehr.
Ordne Eingänge eher links, Verarbeitung in der Mitte und Outputs rechts an.
Halte Leitungen möglichst übersichtlich und vermeide unnötige Kreuzungen.
Bei komplexen Aufgaben wie Addierern, Zählern oder Byte-Schaltungen erst die komplette Topologie gedanklich bestimmen und dann ALLE Nodes, Positionen und Verbindungen in einem vollständigen Aktionsplan ausgeben.

VERHALTEN BEI "LÖSCHE ALLES":
Prüfe den übergebenen Kontext und berücksichtige jeden aktuell vorhandenen Node.
Erzeuge eine delete_gate-Aktion für jeden löschbaren Node. Gib diese Löschaktionen vom höchsten Index zum niedrigsten Index aus.
Entferne nicht nur die sichtbaren Beispiele und lasse keine passenden Nodes übrig.
Die mit den gelöschten Nodes verbundenen Wires werden vom Editor beim Löschen ebenfalls entfernt; separate disconnect-Aktionen sind dafür nicht erforderlich.

VERHALTEN BEI "BENENNE ALLE":
Prüfe alle Nodes im Kontext und erzeuge für jeden passenden Node eine eigene rename_gate-Aktion.
Wenn die Anfrage ein altes und ein neues Namensmuster nennt, wende die Änderung auf alle Treffer an.
Ignoriere nicht einfach weitere Treffer, nur weil mehrere Aktionen nötig sind.

VERHALTEN BEI BLUEPRINTS/CHIPS:
Blueprints gehören zur Logic-Builder-Funktionalität und können im Kontext vorhanden sein. Erfinde keine Blueprint-Inhalte, die nicht im Kontext stehen.
Wenn der Nutzer eine Schaltung neu aufbauen lässt, verwende nur die bekannten Gattertypen und die bereitgestellten Aktionen.

SICHERHEIT DER AKTIONEN:
Erfinde keine vorhandenen Nodes oder Indizes.
Verwende nur Typen aus der bekannten Typenliste.
Ändere nichts ohne ausdrücklichen Auftrag.
Wenn eine angeforderte Änderung anhand des aktuellen Kontexts nicht eindeutig möglich ist, sage das kurz in "answer", statt falsche Nodes oder Indizes zu erfinden.
${context ? "\nAKTUELLER APP-KONTEXT:\n" + context : ""}

NUTZERANFRAGE:
${prompt}`

  const aiUrl = provider === "Groq"
    ? "https://api.groq.com/openai/v1/chat/completions"
    : provider === "OpenRouter"
      ? "https://openrouter.ai/api/v1/chat/completions"
      : "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions";
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 45000);
  let response;
  try{
    response = await fetch(
      aiUrl,
      {
        method: "POST",
        signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + apiKey
      },
      body: JSON.stringify({
        model: provider === "Groq" ? "openai/gpt-oss-120b" : provider === "OpenRouter" ? "openrouter/auto" : "gemini-3.8-flash",
        messages: [{
          role: "system",
          content: systemContext + "\n\nAntworte ausschließlich als JSON nach dem angegebenen Schema."
        }],
        ...(provider === "Groq" ? { temperature: 0, max_completion_tokens: 65536 } : { max_tokens: 32768 }),
        ...(provider === "Groq" ? {
          response_format: {
            type: "json_schema",
            json_schema: {
              name: "logic_builder_response",
              strict: true,
              schema: {
                type: "object",
                properties: {
                  answer: { type: "string" },
                  actions: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        action: { type: "string", enum: ["add_gate","delete_gate","move_gate","connect","disconnect","rename_gate","set_switch","set_timer","set_clock","save_chip","copy_chip","place_blueprint","select_nodes","open_chip_popup","confirm_chip_save","update_ai_knowledge"] },
                        type: { type: ["string","null"] },
                        index: { type: ["integer","null"] },
                        from: { type: ["integer","null"] },
                        to: { type: ["integer","null"] },
                        blueprintIndex: { type: ["integer","null"] },
                        indices: { type: ["array","null"], items: { type: "integer" } },
                        inputIndex: { type: ["integer","null"] },
                        x: { type: ["number","null"] },
                        y: { type: ["number","null"] },
                        name: { type: ["string","null"] },
                        value: { type: ["boolean","null"] },
                        delay: { type: ["number","null"] },
                        stay: { type: ["number","null"] },
                        interval: { type: ["number","null"] }
                      },
                      required: ["action","type","index","from","to","inputIndex","blueprintIndex","indices","x","y","name","value","delay","stay","interval"],
                      additionalProperties: false
                    }
                  }
                },
                required: ["answer","actions"],
                additionalProperties: false
              }
            }
          }
        } : {})
        })
      }
    );
  }catch(error){
    clearTimeout(timeout);
    console.error(provider+" API Netzwerkfehler:", error);
    res.status(502).json({
      error: provider+" API Fehler.",
      details: error?.name === "AbortError"
        ? "Die Anfrage hat nach 45 Sekunden abgebrochen."
        : String(error?.message || error)
    });
    return;
  }
  clearTimeout(timeout);

  const data = await response.json().catch(() => ({}));

  if(!response.ok){
    const details = data?.error?.message || data?.message || ("HTTP " + response.status + " " + response.statusText);
    console.error(provider+" API Fehler:", response.status, data);
    res.status(502).json({
      error: provider+" API Fehler.",
      details,
      status: response.status
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
