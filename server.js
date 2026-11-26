import express from "express";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { deflateSync } from "node:zlib";
import pg from "pg";

const { Pool } = pg;

const app = express();
const PORT = process.env.PORT || 3000;
const __dirname = path.dirname(fileURLToPath(import.meta.url));

app.set("trust proxy", 1);
app.use(express.json({ limit: "2mb" }));

const pool = process.env.DATABASE_URL ? new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "true"
    ? { rejectUnauthorized: false }
    : undefined,
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
}) : null;

let databaseReady = false;

function getOwnerId() {
  if (!securityConfigured()) {
    throw new Error("Configuration de sécurité incomplète.");
  }
  return crypto.createHmac("sha256", process.env.SESSION_SECRET)
    .update("demon-city-owner:")
    .update(process.env.SITE_PASSWORD)
    .digest("hex");
}

async function initializeDatabase() {
  if (!pool) {
    console.warn("DATABASE_URL absent : conversations persistantes désactivées.");
    return false;
  }

  await pool.query(`CREATE TABLE IF NOT EXISTS conversations (
    id UUID PRIMARY KEY,
    owner_id TEXT NOT NULL,
    title VARCHAR(120) NOT NULL DEFAULT 'Nouvelle discussion',
    pinned BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);

  await pool.query(`CREATE INDEX IF NOT EXISTS conversations_owner_updated_idx
    ON conversations (owner_id, updated_at DESC)`);

  await pool.query(`CREATE TABLE IF NOT EXISTS conversation_messages (
    id UUID PRIMARY KEY,
    conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    role VARCHAR(20) NOT NULL CHECK (role IN ('user','assistant')),
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);

  await pool.query(`CREATE INDEX IF NOT EXISTS conversation_messages_conversation_created_idx
    ON conversation_messages (conversation_id, created_at ASC)`);

  databaseReady = true;
  console.log("PostgreSQL connecté : conversations persistantes activées.");
  return true;
}

function requireDatabase(res) {
  if (!pool || !databaseReady) {
    res.status(503).json({
      success: false,
      error: "La base PostgreSQL n'est pas disponible. Vérifie DATABASE_URL."
    });
    return false;
  }
  return true;
}

function isValidConversationId(id) {
  return typeof id === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id);
}

async function createConversation(ownerId) {
  const count = await pool.query(
    "SELECT COUNT(*)::int AS count FROM conversations WHERE owner_id=$1",
    [ownerId]
  );

  if (count.rows[0].count >= 100) {
    throw new Error("Limite de 100 conversations atteinte. Supprime une ancienne conversation.");
  }

  const id = crypto.randomUUID();
  const result = await pool.query(
    "INSERT INTO conversations (id,owner_id,title) VALUES ($1,$2,'Nouvelle discussion') RETURNING id,title,pinned,created_at,updated_at",
    [id, ownerId]
  );
  return result.rows[0];
}

async function getOwnedConversation(ownerId, id) {
  if (!isValidConversationId(id)) return null;
  const result = await pool.query(
    "SELECT id,title,pinned,created_at,updated_at FROM conversations WHERE id=$1 AND owner_id=$2",
    [id, ownerId]
  );
  return result.rows[0] || null;
}

async function getConversationHistory(id) {
  const result = await pool.query(
    "SELECT role,content FROM conversation_messages WHERE conversation_id=$1 ORDER BY created_at DESC LIMIT 20",
    [id]
  );
  return result.rows.reverse();
}

async function saveConversationExchange(ownerId, id, userMessage, assistantMessage) {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const owned = await client.query(
      "SELECT id,title FROM conversations WHERE id=$1 AND owner_id=$2 FOR UPDATE",
      [id, ownerId]
    );

    if (!owned.rows.length) throw new Error("Conversation introuvable.");

    await client.query(
      "INSERT INTO conversation_messages (id,conversation_id,role,content) VALUES ($1,$2,'user',$3),($4,$2,'assistant',$5)",
      [crypto.randomUUID(), id, userMessage, crypto.randomUUID(), assistantMessage]
    );

    if (owned.rows[0].title === "Nouvelle discussion") {
      const title = userMessage.replace(/\s+/g, " ").trim().slice(0, 55) || "Nouvelle discussion";
      await client.query(
        "UPDATE conversations SET title=$1,updated_at=NOW() WHERE id=$2",
        [title, id]
      );
    } else {
      await client.query(
        "UPDATE conversations SET updated_at=NOW() WHERE id=$1",
        [id]
      );
    }

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

// Stockage temporaire des sessions et actions
const sessions = new Map();
const loginAttempts = new Map();
const pendingActions = new Map();

const SESSION_DURATION = 24 * 60 * 60 * 1000;
const ACTION_DURATION = 2 * 60 * 1000;
const COOKIE_NAME = "dcia_session";

// Configuration DemonCode
const DEMONCODE_MAX_WIDTH = 256;
const DEMONCODE_MAX_HEIGHT = 256;
const DEMONCODE_MAX_LENGTH = 1800000;

// Sécurité
function securityConfigured() {
  return Boolean(
    process.env.SITE_PASSWORD &&
    process.env.SESSION_SECRET &&
    process.env.SESSION_SECRET.length >= 32
  );
}

function signSession(id) {
  return crypto
    .createHmac("sha256", process.env.SESSION_SECRET)
    .update(id)
    .digest("base64url");
}

function getSession(req) {
  if (!securityConfigured()) return null;

  const cookies = req.headers.cookie || "";
  const cookie = cookies
    .split(";")
    .map(item => item.trim())
    .find(item => item.startsWith(COOKIE_NAME + "="));

  if (!cookie) return null;

  const value = cookie.substring(COOKIE_NAME.length + 1);
  const [id, signature] = value.split(".");

  if (!id || !signature) return null;

  const expected = signSession(id);
  const received = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);

  if (
    received.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(received, expectedBuffer)
  ) {
    return null;
  }

  const session = sessions.get(id);

  if (!session || session.expiresAt < Date.now()) {
    sessions.delete(id);

    for (const [actionId, action] of pendingActions) {
      if (action.sessionId === id) pendingActions.delete(actionId);
    }

    return null;
  }

  return { id, session };
}
// Page de connexion
const loginPage = `<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#171116">
<title>Connexion - Demon City IA</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#171316;color:#f5eef3;font:15px system-ui,sans-serif;padding:20px}
.card{width:100%;max-width:390px;background:#211a20;border:1px solid #392a35;border-radius:20px;padding:28px;box-shadow:0 20px 60px #0005}
.mark{width:54px;height:54px;display:grid;place-items:center;border-radius:16px;background:linear-gradient(145deg,#c13a65,#65152f);font-weight:900;font-size:20px}
h1{font-size:23px;margin:20px 0 5px}
p{color:#aa9ca7;font-size:13px;margin:0 0 22px}
label{display:block;font-size:12px;margin-bottom:8px;color:#d8cbd4}
input{width:100%;padding:13px;border:1px solid #51404b;border-radius:10px;background:#171316;color:white;outline:none}
input:focus{border-color:#c33562}
button{width:100%;margin-top:14px;padding:13px;border:0;border-radius:10px;background:#a92750;color:white;font-weight:700;cursor:pointer}
#error{color:#ff829c;font-size:12px;margin-top:12px;min-height:18px}
</style>
</head>
<body>
<div class="card">
<div class="mark">DC</div>
<h1>Demon City IA</h1>
<p>Connecte-toi pour accéder à ton espace de travail.</p>
<form id="loginForm">
<label for="password">Mot de passe</label>
<input id="password" type="password" autocomplete="current-password" placeholder="Ton mot de passe" required>
<button id="submit" type="submit">Se connecter</button>
<div id="error" role="alert"></div>
</form>
</div>
<script>
const form=document.getElementById("loginForm");
const input=document.getElementById("password");
const error=document.getElementById("error");
const button=document.getElementById("submit");
form.addEventListener("submit",async event=>{
  event.preventDefault();
  button.disabled=true;
  error.textContent="";
  try{
    const response=await fetch("/auth/login",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({password:input.value})
    });
    const data=await response.json();
    if(!response.ok)throw new Error(data.error||"Connexion refusée.");
    location.href="/";
  }catch(err){
    error.textContent=err.message;
  }finally{
    button.disabled=false;
  }
});
</script>
</body>
</html>`;

// Routes de connexion
app.get("/login", (req, res) => {
  if (getSession(req)) return res.redirect("/");
  res.type("html").send(loginPage);
});

app.get("/auth/status", (req, res) => {
  res.json({
    authenticated: Boolean(getSession(req)),
    securityConfigured: securityConfigured()
  });
});

app.post("/auth/login", (req, res) => {
  const password = process.env.SITE_PASSWORD;
  const submitted = req.body?.password;

  if (!securityConfigured()) {
    return res.status(503).json({
      error: "Configuration de sécurité incomplète."
    });
  }

  if (typeof submitted !== "string" || submitted.length > 200) {
    return res.status(400).json({ error: "Mot de passe invalide." });
  }

  const ip = req.ip || "unknown";
  const attempts = loginAttempts.get(ip) || {
    count: 0,
    startedAt: Date.now()
  };

  if (Date.now() - attempts.startedAt > 15 * 60 * 1000) {
    attempts.count = 0;
    attempts.startedAt = Date.now();
  }

  if (attempts.count >= 5) {
    return res.status(429).json({
      error: "Trop de tentatives. Réessaie dans 15 minutes."
    });
  }

  const expected = crypto.createHash("sha256").update(password).digest();
  const received = crypto.createHash("sha256").update(submitted).digest();

  if (!crypto.timingSafeEqual(expected, received)) {
    attempts.count++;
    loginAttempts.set(ip, attempts);
    return res.status(401).json({ error: "Mot de passe incorrect." });
  }

  loginAttempts.delete(ip);

  const id = crypto.randomBytes(32).toString("base64url");

  sessions.set(id, {
    expiresAt: Date.now() + SESSION_DURATION
  });

  const signature = signSession(id);

  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=${id}.${signature}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400`
  );

  res.json({ success: true });
});

app.post("/auth/logout", (req, res) => {
  const current = getSession(req);

  if (current) {
    sessions.delete(current.id);

    for (const [actionId, action] of pendingActions) {
      if (action.sessionId === current.id) {
        pendingActions.delete(actionId);
      }
    }
  }

  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`
  );

  res.json({ success: true });
});

// Protéger les routes privées
app.use((req, res, next) => {
  const current = getSession(req);

  if (current) {
    req.sessionId = current.id;
    try {
      req.ownerId = getOwnerId();
    } catch {
      return res.status(503).json({
        success: false,
        error: "Configuration de sécurité incomplète."
      });
    }
    return next();
  }

  if (req.accepts("html")) return res.redirect("/login");

  return res.status(401).json({
    success: false,
    error: "Connexion nécessaire."
  });
});

// Site privé
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.use(express.static(path.join(__dirname, "public")));

// Instructions du cerveau Demon City IA

const SYSTEM_PROMPT = `
Tu es Demon City IA, l'assistant officiel du serveur Minecraft Demon City.

Tu parles français naturellement, clairement et de manière conviviale.
Tu connais Minecraft Bedrock et le projet Demon City.
Tu ne prétends jamais avoir effectué une action non réalisée.

LANGAGES INTERNES :

DemonScript sert exclusivement à demander des actions sur le serveur.
Ses symboles sont :
- ¥ : démarrer le serveur Falix.
- £ : arrêter le serveur Falix.
- ₩ : redémarrer le serveur Falix.
- 《{/commande} : préparer une commande Minecraft.

RÈGLES DEMONSCRIPT :
Quand l'utilisateur demande clairement une action de contrôle du serveur,
réponds uniquement avec le symbole correspondant.
Pour une commande Minecraft, réponds uniquement avec :
《{/commande Minecraft}

N'ajoute aucun texte autour du symbole.
N'émets jamais ces symboles dans une conversation ordinaire,
une explication, un exemple ou une simple question.
Ne transforme jamais une question sur une commande en exécution.
En cas de doute sur l'intention, pose une question normale.
Le serveur demandera toujours une confirmation avant l'exécution.

DEMONCODE :

DemonCode est un langage propriétaire exclusivement destiné
à la création et à la conversion d'images en pixels.
Il ne sert pas à créer des programmes ou des interfaces.

FORMAT OBLIGATOIRE :

Chaque image doit commencer par :

{image-size LARGEURxHAUTEURpx}
{format RGB}

Ou :

{image-size LARGEURxHAUTEURpx}
{format RGBA}

Ensuite viennent les lignes de pixels.

RÈGLES STRICTES DE COMPTAGE :

1. Le nombre de lignes de pixels doit être exactement égal à la hauteur.
2. Chaque ligne doit contenir exactement autant de pixels que la largeur.
3. Chaque pixel doit être séparé du suivant par un point-virgule.
4. En RGB, chaque pixel contient exactement trois nombres :
   ROUGE-VERT-BLEU
5. En RGBA, chaque pixel contient exactement quatre nombres :
   ROUGE-VERT-BLEU-ALPHA
6. Chaque nombre doit être un entier compris entre 0 et 255.
7. Ne place jamais plusieurs lignes de pixels sur une seule ligne.
8. Ne coupe jamais une ligne de pixels en plusieurs lignes.
9. N'ajoute aucun commentaire dans le code.
10. Ne remplace jamais des pixels par des points de suspension.
11. Ne raccourcis jamais le code avec des expressions comme
    "les autres pixels sont identiques".
12. Vérifie mentalement le nombre de pixels de chaque ligne
    et le nombre total de lignes avant de répondre.

TAILLE DES IMAGES :

Pour les petits dessins, utilise de préférence 8x8 ou 16x16.
Pour les dessins plus détaillés, tu peux utiliser une résolution supérieure.
Ne dépasse jamais 256x256 pixels.

CRÉATION D'IMAGES :

Quand l'utilisateur demande de créer, dessiner ou générer une image :
- Génère directement du DemonCode valide.
- Choisis une résolution adaptée à la complexité du dessin.
- Produis une image complète, sans pixels manquants.
- Utilise les couleurs RGB ou RGBA.
- Place le code dans un bloc de code identifié demoncode.
- N'ajoute pas d'explications à l'intérieur du bloc.

IMPORTANT :
Avant de produire le code, calcule le nombre de pixels nécessaire.
Pour une image de 8x8, il faut exactement 64 pixels :
8 lignes de 8 pixels.
Pour une image de 16x16, il faut exactement 256 pixels :
16 lignes de 16 pixels.

Ne prétends jamais qu'une image est valide si les dimensions
et le nombre de pixels ne correspondent pas.

Ne confonds jamais DemonCode et DemonScript.

OUTILS :
- get_server_status : consulter le statut réel du serveur Falix.
- get_console_log : lire les dernières lignes de la console Falix en direct.
- prepare_server_command : préparer une commande Minecraft.
- prepare_server_power : préparer start, stop ou restart.
- list_server_files : explorer les dossiers Falix.
- read_server_file : lire un fichier Falix.
- prepare_file_write : préparer la modification d'un fichier.

RECHERCHE :
Tu disposes de browser_search.
Utilise-le pour les recherches Internet et les informations récentes.
Ne prétends jamais avoir recherché si aucune recherche n'a été effectuée.

CONTRÔLE FALIX :
Pour démarrer, arrêter ou redémarrer, utilise DemonScript.
Ne remplace jamais ces actions par une commande Minecraft.

FICHIERS :
Utilise les outils de lecture et d'exploration.
Les modifications doivent toujours attendre la validation de l'utilisateur.
Ne supprime jamais un fichier sans autorisation explicite.

CONFIRMATIONS :
Les actions qui modifient le serveur nécessitent une confirmation.
Ne prétends jamais qu'une action est exécutée avant sa validation
et la réponse positive de Falix.

SÉCURITÉ :
Ne révèle jamais les clés API, mots de passe ou secrets.
Ne prétends jamais avoir accès à des fonctions non disponibles.
`;
// Configuration Falix
function getFalixConfig() {
  const apiKey = process.env.FALIX_API_KEY;
  const serverId = process.env.FALIX_SERVER_ID || "3574991";

  if (!apiKey || !serverId) {
    throw new Error("Configuration Falix incomplète.");
  }

  return { apiKey, serverId };
}

// Extraire un lien de vérification officiel Falix
function getFalixActionUrl(result) {
  const candidates = [
    result?.error?.action_url,
    result?.action_url,
    result?.data?.action_url
  ];

  for (const candidate of candidates) {
    if (typeof candidate !== "string") continue;

    try {
      const url = new URL(candidate);
      const officialHost =
        url.hostname === "falixnodes.net" ||
        url.hostname.endsWith(".falixnodes.net");

      if (url.protocol === "https:" && officialHost) return url.href;
    } catch {}
  }

  return null;
}

// Fonction commune pour appeler Falix
async function falixRequest(endpoint, options = {}) {
  const { apiKey } = getFalixConfig();

  const response = await fetch(
    `https://client.falixnodes.net/api/v2${endpoint}`,
    {
      ...options,
      headers: {
        Authorization: `Bearer ${apiKey}`,
        ...(options.body ? { "Content-Type": "application/json" } : {}),
        ...options.headers
      },
      signal: AbortSignal.timeout(20000)
    }
  );

  const result = await response.json().catch(() => ({}));

  if (!response.ok) {
    const message =
      result.error?.message ||
      result.message ||
      `Erreur Falix (${response.status})`;

    const error = new Error(message);
    error.status = response.status;
    error.actionUrl = getFalixActionUrl(result);
    throw error;
  }

  return result.data;
}

function serverEndpoint(pathname) {
  const { serverId } = getFalixConfig();
  return `/servers/${encodeURIComponent(serverId)}${pathname}`;
}

// Statut réel
async function getFalixStatus() {
  const server = await falixRequest(
    serverEndpoint("/console/status")
  );

  return {
    id: server.server_id,
    name: server.server_name,
    status: server.status,
    message: server.message,
    nodeReady: server.node_ready,
    resources: server.resources || null
  };
}

// Lire la console Falix en direct
async function getFalixLogs() {
  if (typeof globalThis.WebSocket !== "function") {
    throw new Error(
      "WebSocket indisponible. Demon City IA nécessite Node.js 22 ou supérieur."
    );
  }

  const session = await falixRequest(
    serverEndpoint("/console/token"),
    { method: "POST" }
  );

  if (
    !session ||
    typeof session.socket !== "string" ||
    typeof session.token !== "string"
  ) {
    throw new Error("Falix n'a pas fourni de session WebSocket valide.");
  }

  const socketUrl = new URL(session.socket);

  if (socketUrl.protocol !== "wss:") {
    throw new Error("Adresse WebSocket Falix non sécurisée.");
  }

  const ws = new globalThis.WebSocket(socketUrl.href);
  const lines = [];

  return await new Promise((resolve, reject) => {
    let authenticated = false;
    let finished = false;
    let collectionTimer = null;

    function finish(error = null) {
      if (finished) return;
      finished = true;

      clearTimeout(connectionTimer);
      if (collectionTimer) clearTimeout(collectionTimer);

      try {
        ws.close();
      } catch {}

      if (error) reject(error);
      else {
        resolve({
          source: "websocket",
          live: true,
          truncated: false,
          lines: lines.slice(-200)
        });
      }
    }

    const connectionTimer = setTimeout(() => {
      finish(new Error("Délai dépassé lors de la connexion à la console Falix."));
    }, 12000);

    ws.addEventListener("open", () => {
      ws.send(JSON.stringify({
        event: "auth",
        args: [session.token]
      }));
    });

    ws.addEventListener("message", event => {
      let packet;

      try {
        packet = JSON.parse(String(event.data));
      } catch {
        return;
      }

      const eventName = packet?.event;
      const args = Array.isArray(packet?.args) ? packet.args : [];

      if (eventName === "auth success" && !authenticated) {
        authenticated = true;

        ws.send(JSON.stringify({
          event: "send logs",
          args: []
        }));

        collectionTimer = setTimeout(() => finish(), 1800);
        return;
      }

      if (eventName === "jwt error") {
        finish(new Error("Falix a refusé le token WebSocket."));
        return;
      }

      if (
        eventName === "console output" &&
        typeof args[0] === "string"
      ) {
        lines.push(args[0]);
        if (lines.length > 500) lines.shift();
      }
    });

    ws.addEventListener("error", () => {
      finish(new Error("Impossible de communiquer avec le WebSocket Falix."));
    });

    ws.addEventListener("close", () => {
      if (authenticated) finish();
      else finish(new Error("Falix a fermé la connexion avant l'authentification."));
    });
  });
}

// Envoyer une commande Minecraft
async function sendFalixCommand(command) {
  const data = await falixRequest(
    serverEndpoint("/commands"),
    {
      method: "POST",
      headers: { "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify({ command })
    }
  );

  return {
    accepted: data?.accepted === true,
    serverId: data?.server_id
  };
}

// Contrôle du serveur
async function powerFalixServer(signal) {
  if (!["start", "stop", "restart"].includes(signal)) {
    throw new Error("Action serveur non autorisée.");
  }

  const data = await falixRequest(
    serverEndpoint("/power"),
    {
      method: "POST",
      headers: { "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify({ signal })
    }
  );

  return { accepted: true, signal, result: data };
}

// Explorer un dossier
async function listFalixFiles(directory = "/") {
  if (
    typeof directory !== "string" ||
    directory.length > 500 ||
    directory.includes("..")
  ) {
    throw new Error("Chemin de dossier invalide.");
  }

  const params = new URLSearchParams({
    directory,
    limit: "100",
    offset: "0"
  });

  return await falixRequest(serverEndpoint(`/files?${params}`));
}

// Lire un fichier texte
async function readFalixFile(filePath) {
  if (
    typeof filePath !== "string" ||
    !filePath.startsWith("/") ||
    filePath.length > 500 ||
    filePath.includes("..")
  ) {
    throw new Error("Chemin de fichier invalide.");
  }

  const params = new URLSearchParams({
    path: filePath,
    length: "65536"
  });

  return await falixRequest(
    serverEndpoint(`/files/content?${params}`)
  );
}

// Écrire un fichier
async function writeFalixFile(filePath, content) {
  if (
    typeof filePath !== "string" ||
    !filePath.startsWith("/") ||
    filePath.length > 500 ||
    filePath.includes("..")
  ) {
    throw new Error("Chemin de fichier invalide.");
  }

  if (
    typeof content !== "string" ||
    Buffer.byteLength(content, "utf8") > 60000
  ) {
    throw new Error("Le contenu du fichier est invalide ou trop volumineux.");
  }

  return await falixRequest(
    serverEndpoint("/files/content"),
    {
      method: "PUT",
      headers: { "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify({ path: filePath, content })
    }
  );
}

// Préparer une action avec expiration
function createPendingAction(sessionId, action) {
  const actionId = crypto.randomBytes(24).toString("base64url");
  const expiresAt = Date.now() + ACTION_DURATION;

  pendingActions.set(actionId, {
    ...action,
    sessionId,
    expiresAt
  });

  return {
    actionId,
    command: action.label,
    expiresAt
  };
}

// Préparer une commande Minecraft
function prepareCommand(sessionId, command) {
  if (typeof command !== "string") {
    throw new Error("Commande invalide.");
  }

  const cleaned = command.trim().replace(/^\/+/, "");

  if (!cleaned || cleaned.length > 300) {
    throw new Error("La commande doit contenir entre 1 et 300 caractères.");
  }

  if (/[\r\n\u0000-\u001f]/.test(cleaned)) {
    throw new Error("Les commandes sur plusieurs lignes sont interdites.");
  }

  const forbidden = ["stop", "restart", "kill", "op", "deop"];
  const firstWord = cleaned.split(/\s+/)[0].toLowerCase();

  if (forbidden.includes(firstWord)) {
    throw new Error("Utilise l'outil de contrôle du serveur pour cette action.");
  }

  return createPendingAction(sessionId, {
    type: "command",
    command: cleaned,
    label: `Commande Minecraft : ${cleaned}`
  });
}

// Préparer le contrôle Falix
function preparePower(sessionId, signal) {
  if (!["start", "stop", "restart"].includes(signal)) {
    throw new Error("Action serveur invalide.");
  }

  const labels = {
    start: "Démarrer le serveur",
    stop: "Arrêter le serveur",
    restart: "Redémarrer le serveur"
  };

  return createPendingAction(sessionId, {
    type: "power",
    signal,
    label: labels[signal]
  });
}

// Préparer une modification de fichier
function prepareFileWrite(sessionId, filePath, content) {
  if (
    typeof content !== "string" ||
    Buffer.byteLength(content, "utf8") > 60000
  ) {
    throw new Error("Contenu de fichier invalide ou trop volumineux.");
  }

  if (
    typeof filePath !== "string" ||
    !filePath.startsWith("/") ||
    filePath.length > 500 ||
    filePath.includes("..")
  ) {
    throw new Error("Chemin de fichier invalide.");
  }

  return createPendingAction(sessionId, {
    type: "write_file",
    filePath,
    content,
    label: `Modifier le fichier : ${filePath}`
  });
}
// Interpréter les marqueurs DemonScript
// Seul un message constitué exactement d'un marqueur est interprété.
function parseDemonScript(content) {
  if (typeof content !== "string") return null;

  const value = content.trim();

  const powers = {
    "¥": "start",
    "£": "stop",
    "₩": "restart"
  };

  if (Object.hasOwn(powers, value)) {
    return {
      type: "power",
      signal: powers[value]
    };
  }

  const commandMatch = value.match(/^《\{\/([^{}\r\n]+)\}$/);

  if (commandMatch) {
    return {
      type: "command",
      command: commandMatch[1].trim()
    };
  }

  return null;
}

// Créer l'action DemonScript en attente
function prepareDemonScript(sessionId, script) {
  if (script.type === "power") {
    return preparePower(sessionId, script.signal);
  }

  if (script.type === "command") {
    return prepareCommand(sessionId, script.command);
  }

  throw new Error("Instruction DemonScript inconnue.");
}

// Confirmation d'une action
app.post("/actions/confirm", async (req, res) => {
  const actionId = req.body?.actionId;

  if (typeof actionId !== "string" || actionId.length > 100) {
    return res.status(400).json({
      success: false,
      reply: "Demande de validation invalide."
    });
  }

  const pending = pendingActions.get(actionId);

  if (!pending || pending.sessionId !== req.sessionId) {
    return res.status(404).json({
      success: false,
      reply: "Cette action n'existe plus ou a déjà été traitée."
    });
  }

  if (Date.now() > pending.expiresAt) {
    pendingActions.delete(actionId);

    return res.status(410).json({
      success: false,
      reply: "Le délai de validation est dépassé. Prépare à nouveau l'action."
    });
  }

  pendingActions.delete(actionId);

  try {
    let reply = "";

    if (pending.type === "command") {
      const result = await sendFalixCommand(pending.command);

      if (!result.accepted) {
        throw new Error("Falix n'a pas confirmé l'acceptation de la commande.");
      }

      reply = `Commande acceptée par Falix : ${pending.command}`;
    } else if (pending.type === "power") {
      await powerFalixServer(pending.signal);

      const labels = {
        start: "démarrage",
        stop: "arrêt",
        restart: "redémarrage"
      };

      reply = `Falix a accepté la demande de ${labels[pending.signal]}. Le changement d'état peut prendre quelques instants.`;
    } else if (pending.type === "write_file") {
      await writeFalixFile(pending.filePath, pending.content);
      reply = `Le fichier ${pending.filePath} a été envoyé à Falix pour modification.`;
    } else {
      throw new Error("Type d'action inconnu.");
    }

    return res.json({ success: true, reply });
  } catch (error) {
    console.error("Erreur action Falix :", error.message);

    return res.status(error.status || 502).json({
      success: false,
      reply: error.message,
      actionUrl: error.actionUrl || null
    });
  }
});

// Refuser une action
app.post("/actions/cancel", (req, res) => {
  const actionId = req.body?.actionId;

  if (typeof actionId !== "string" || actionId.length > 100) {
    return res.status(400).json({
      success: false,
      reply: "Demande d'annulation invalide."
    });
  }

  const pending = pendingActions.get(actionId);

  if (!pending || pending.sessionId !== req.sessionId) {
    return res.status(404).json({
      success: false,
      reply: "Cette action n'existe plus ou a déjà été traitée."
    });
  }

  pendingActions.delete(actionId);

  return res.json({
    success: true,
    reply: "Action annulée. Rien n'a été envoyé à Falix."
  });
});

// ================================
// MOTEUR DEMONCODE : TEXTE VERS PNG
// ================================

// Lire et valider un document DemonCode
function parseDemonCode(source) {
  if (typeof source !== "string" || source.length > DEMONCODE_MAX_LENGTH) {
    throw new Error("Code DemonCode invalide ou trop volumineux.");
  }

  const lines = source.trim().split(/\r?\n/);

  const sizeMatch = lines[0]?.trim().match(
    /^\{image-size\s+(\d+)x(\d+)px\}$/
  );

  if (!sizeMatch) {
    throw new Error("Dimensions invalides. Exemple : {image-size 64x64px}");
  }

  const width = Number(sizeMatch[1]);
  const height = Number(sizeMatch[2]);

  if (
    !Number.isSafeInteger(width) ||
    !Number.isSafeInteger(height) ||
    width < 1 ||
    height < 1 ||
    width > DEMONCODE_MAX_WIDTH ||
    height > DEMONCODE_MAX_HEIGHT
  ) {
    throw new Error(
      `Les dimensions maximales sont ${DEMONCODE_MAX_WIDTH} × ${DEMONCODE_MAX_HEIGHT} pixels.`
    );
  }

  const formatMatch = lines[1]?.trim().match(
    /^\{format\s+(RGB|RGBA)\}$/
  );

  if (!formatMatch) {
    throw new Error("Format manquant. Utilise {format RGB} ou {format RGBA}.");
  }

  const format = formatMatch[1];
  const channels = format === "RGB" ? 3 : 4;
  const pixelLines = lines.slice(2).filter(line => line.trim() !== "");

  if (pixelLines.length !== height) {
    throw new Error(
      `Hauteur incorrecte : ${height} lignes attendues, ${pixelLines.length} trouvées.`
    );
  }

  const pixels = [];

  for (let y = 0; y < height; y++) {
    const row = pixelLines[y].split(";").map(value => value.trim());

    if (row.length !== width) {
      throw new Error(
        `Ligne ${y + 1} : ${width} pixels attendus, ${row.length} trouvés.`
      );
    }

    for (let x = 0; x < width; x++) {
      const values = row[x].split("-").map(value => {
        if (!/^\d+$/.test(value)) return NaN;
        return Number(value);
      });

      if (
        values.length !== channels ||
        values.some(value =>
          !Number.isInteger(value) || value < 0 || value > 255
        )
      ) {
        throw new Error(
          `Couleur invalide à la ligne ${y + 1}, pixel ${x + 1}.`
        );
      }

      pixels.push(values);
    }
  }

  return { width, height, format, channels, pixels };
}

// Calculer le CRC32 nécessaire au format PNG
const crcTable = new Uint32Array(256);

for (let n = 0; n < 256; n++) {
  let c = n;

  for (let k = 0; k < 8; k++) {
    c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
  }

  crcTable[n] = c >>> 0;
}

function crc32(buffer) {
  let crc = 0xffffffff;

  for (const byte of buffer) {
    crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  }

  return (crc ^ 0xffffffff) >>> 0;
}

// Créer un bloc PNG
function pngChunk(type, data) {
  const typeBuffer = Buffer.from(type, "ascii");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);

  const crcInput = Buffer.concat([typeBuffer, data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(crcInput), 0);

  return Buffer.concat([length, typeBuffer, data, crc]);
}

// Encoder les pixels en véritable fichier PNG
function encodeDemonCodePng(image) {
  const { width, height, format, channels, pixels } = image;
  const colorType = format === "RGB" ? 2 : 6;

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = colorType;
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  const rowLength = 1 + width * channels;
  const raw = Buffer.alloc(rowLength * height);

  let pixelIndex = 0;

  for (let y = 0; y < height; y++) {
    const rowStart = y * rowLength;
    raw[rowStart] = 0;

    for (let x = 0; x < width; x++) {
      const pixel = pixels[pixelIndex++];
      const offset = rowStart + 1 + x * channels;

      for (let c = 0; c < channels; c++) {
        raw[offset + c] = pixel[c];
      }
    }
  }

  const signature = Buffer.from([
    137, 80, 78, 71, 13, 10, 26, 10
  ]);

  const ihdrChunk = pngChunk("IHDR", ihdr);
  const idatChunk = pngChunk("IDAT", deflateSync(raw));
  const iendChunk = pngChunk("IEND", Buffer.alloc(0));

  return Buffer.concat([
    signature,
    ihdrChunk,
    idatChunk,
    iendChunk
  ]);
}

// Route DemonCode protégée par la connexion
app.post("/demoncode/render", (req, res) => {
  try {
    const code = req.body?.code;

    const image = parseDemonCode(code);
    const png = encodeDemonCodePng(image);

    res.setHeader("Content-Type", "image/png");
    res.setHeader(
      "Content-Disposition",
      'inline; filename="demoncode-image.png"'
    );
    res.setHeader("Cache-Control", "no-store");

    return res.status(200).send(png);
  } catch (error) {
    return res.status(400).json({
      success: false,
      error: error.message
    });
  }
});

// Statut de Demon City IA
app.get("/status", (req, res) => {
  res.json({
    success: true,
    name: "Demon City IA",
    status: "online",
    aiConfigured: Boolean(process.env.GROQ_API_KEY),
    falixConfigured: Boolean(process.env.FALIX_API_KEY),
    webSearchEnabled: true,
    demonScriptEnabled: true,
    demonCodeEnabled: true
  });
});

// Test Falix
app.get("/falix-test", async (req, res) => {
  try {
    const data = await falixRequest("/me");

    res.json({
      success: true,
      message: "Demon City IA est connecté à Falix !",
      account: data.account?.username || "Connecté"
    });
  } catch (error) {
    console.error("Erreur Falix :", error.message);

    res.status(500).json({
      success: false,
      error: "Impossible de contacter Falix."
    });
  }
});

// Statut Falix
app.get("/falix-status", async (req, res) => {
  try {
    const server = await getFalixStatus();
    res.json({ success: true, server });
  } catch (error) {
    console.error("Erreur statut Falix :", error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Console Falix en direct
app.get("/falix-console", async (req, res) => {
  try {
    const logs = await getFalixLogs();
    res.json({ success: true, console: logs });
  } catch (error) {
    console.error("Erreur console Falix :", error.message);

    res.status(error.status || 500).json({
      success: false,
      error: error.message
    });
  }
});

// Fonctions accessibles à Groq
const availableTools = [
  {
    type: "function",
    function: {
      name: "get_server_status",
      description: "Consulter le statut réel du serveur Falix.",
      parameters: {
        type: "object",
        properties: {},
        required: [],
        additionalProperties: false
      }
    }
  },
  {
    type: "function",
    function: {
      name: "get_console_log",
      description: "Lire les dernières lignes de la console Falix en direct via WebSocket.",
      parameters: {
        type: "object",
        properties: {},
        required: [],
        additionalProperties: false
      }
    }
  },
  {
    type: "function",
    function: {
      name: "prepare_server_command",
      description: "Préparer une commande Minecraft à envoyer après validation.",
      parameters: {
        type: "object",
        properties: {
          command: { type: "string" }
        },
        required: ["command"],
        additionalProperties: false
      }
    }
  },
  {
    type: "function",
    function: {
      name: "prepare_server_power",
      description: "Préparer un démarrage, arrêt ou redémarrage du serveur Falix. Demande toujours une confirmation.",
      parameters: {
        type: "object",
        properties: {
          signal: {
            type: "string",
            enum: ["start", "stop", "restart"]
          }
        },
        required: ["signal"],
        additionalProperties: false
      }
    }
  },
  {
    type: "function",
    function: {
      name: "list_server_files",
      description: "Lister les fichiers et dossiers d'un répertoire du serveur Falix.",
      parameters: {
        type: "object",
        properties: {
          directory: { type: "string" }
        },
        required: ["directory"],
        additionalProperties: false
      }
    }
  },
  {
    type: "function",
    function: {
      name: "read_server_file",
      description: "Lire le contenu texte d'un fichier du serveur Falix.",
      parameters: {
        type: "object",
        properties: {
          path: { type: "string" }
        },
        required: ["path"],
        additionalProperties: false
      }
    }
  },
  {
    type: "function",
    function: {
      name: "prepare_file_write",
      description: "Préparer la création ou modification d'un fichier Falix. L'écriture attendra la confirmation de l'utilisateur.",
      parameters: {
        type: "object",
        properties: {
          path: { type: "string" },
          content: { type: "string" }
        },
        required: ["path", "content"],
        additionalProperties: false
      }
    }
  }
];

// ================================
// CONVERSATIONS POSTGRESQL
// ================================

// Récupérer les conversations
app.get("/api/conversations", async (req, res) => {
  if (!requireDatabase(res)) return;

  try {
    const result = await pool.query(
      `SELECT id, title, pinned, created_at, updated_at
       FROM conversations
       WHERE owner_id = $1
       ORDER BY pinned DESC, updated_at DESC`,
      [req.ownerId]
    );

    return res.json({
      success: true,
      conversations: result.rows
    });
  } catch (error) {
    console.error("Erreur récupération conversations :", error.message);
    return res.status(500).json({
      success: false,
      error: "Impossible de récupérer les conversations."
    });
  }
});

// Créer une conversation
app.post("/api/conversations", async (req, res) => {
  if (!requireDatabase(res)) return;

  try {
    const conversation = await createConversation(req.ownerId);

    return res.status(201).json({
      success: true,
      conversation
    });
  } catch (error) {
    console.error("Erreur création conversation :", error.message);

    return res.status(500).json({
      success: false,
      error: error.message.includes("100")
        ? error.message
        : "Impossible de créer la conversation."
    });
  }
});

// Récupérer les messages d'une conversation
app.get("/api/conversations/:id/messages", async (req, res) => {
  if (!requireDatabase(res)) return;

  try {
    const conversation = await getOwnedConversation(
      req.ownerId,
      req.params.id
    );

    if (!conversation) {
      return res.status(404).json({
        success: false,
        error: "Conversation introuvable."
      });
    }

    const result = await pool.query(
      `SELECT id, role, content, created_at
       FROM conversation_messages
       WHERE conversation_id = $1
       ORDER BY created_at ASC`,
      [conversation.id]
    );

    return res.json({
      success: true,
      conversation,
      messages: result.rows
    });
  } catch (error) {
    console.error("Erreur récupération messages :", error.message);

    return res.status(500).json({
      success: false,
      error: "Impossible de récupérer les messages."
    });
  }
});

// Modifier le titre ou épingler une conversation
app.patch("/api/conversations/:id", async (req, res) => {
  if (!requireDatabase(res)) return;

  const title = req.body?.title;
  const pinned = req.body?.pinned;

  if (
    title === undefined &&
    pinned === undefined
  ) {
    return res.status(400).json({
      success: false,
      error: "Aucune modification demandée."
    });
  }

  if (
    title !== undefined &&
    (typeof title !== "string" || !title.trim() || title.trim().length > 120)
  ) {
    return res.status(400).json({
      success: false,
      error: "Titre invalide. Maximum : 120 caractères."
    });
  }

  if (pinned !== undefined && typeof pinned !== "boolean") {
    return res.status(400).json({
      success: false,
      error: "La valeur pinned doit être booléenne."
    });
  }

  try {
    const values = [];
    const updates = [];

    if (title !== undefined) {
      values.push(title.trim());
      updates.push(`title = $${values.length}`);
    }

    if (pinned !== undefined) {
      values.push(pinned);
      updates.push(`pinned = $${values.length}`);
    }

    values.push(req.params.id);
    const idIndex = values.length;

    values.push(req.ownerId);
    const ownerIndex = values.length;

    const result = await pool.query(
      `UPDATE conversations
       SET ${updates.join(", ")}, updated_at = NOW()
       WHERE id = $${idIndex} AND owner_id = $${ownerIndex}
       RETURNING id, title, pinned, created_at, updated_at`,
      values
    );

    if (!result.rowCount) {
      return res.status(404).json({
        success: false,
        error: "Conversation introuvable."
      });
    }

    return res.json({
      success: true,
      conversation: result.rows[0]
    });
  } catch (error) {
    console.error("Erreur modification conversation :", error.message);

    return res.status(500).json({
      success: false,
      error: "Impossible de modifier la conversation."
    });
  }
});

// Supprimer une conversation et ses messages
app.delete("/api/conversations/:id", async (req, res) => {
  if (!requireDatabase(res)) return;

  try {
    const result = await pool.query(
      `DELETE FROM conversations
       WHERE id = $1 AND owner_id = $2
       RETURNING id`,
      [req.params.id, req.ownerId]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        success: false,
        error: "Conversation introuvable."
      });
    }

    return res.json({
      success: true,
      message: "Conversation supprimée."
    });
  } catch (error) {
    console.error("Erreur suppression conversation :", error.message);

    return res.status(500).json({
      success: false,
      error: "Impossible de supprimer la conversation."
    });
  }
});

// ================================
// APPEL GROQ
// ================================

async function callGroq(apiKey, messages, includeTools = true) {
  const tools = includeTools
    ? [...availableTools, { type: "browser_search" }]
    : [{ type: "browser_search" }];

  const response = await fetch(
    "https://api.groq.com/openai/v1/chat/completions",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model: process.env.GROQ_MODEL || "openai/gpt-oss-120b",
        messages,
        tools,
        tool_choice: "auto",
        temperature: 0.7,
        max_tokens: 2000
      }),
      signal: AbortSignal.timeout(60000)
    }
  );

  const result = await response.json();

  if (!response.ok) {
    console.error("Erreur Groq :", response.status, result.error);
    throw new Error("Erreur du moteur Groq.");
  }

  return result.choices?.[0]?.message;
}

// ================================
// CHAT PRINCIPAL AVEC HISTORIQUE
// ================================

app.post("/chat", async (req, res) => {
  const apiKey = process.env.GROQ_API_KEY;
  const userMessage = req.body?.message;
  let conversationId = req.body?.conversationId || null;

  if (!apiKey) {
    return res.status(500).json({
      success: false,
      error: "Clé API Groq manquante."
    });
  }

  if (
    typeof userMessage !== "string" ||
    !userMessage.trim()
  ) {
    return res.status(400).json({
      success: false,
      error: "Message vide ou invalide."
    });
  }

  if (userMessage.length > 8000) {
    return res.status(400).json({
      success: false,
      error: "Message trop long."
    });
  }

  if (!requireDatabase(res)) return;

  try {
    let conversation;

    if (conversationId) {
      conversation = await getOwnedConversation(
        req.ownerId,
        conversationId
      );

      if (!conversation) {
        return res.status(404).json({
          success: false,
          error: "Conversation introuvable."
        });
      }
    } else {
      conversation = await createConversation(req.ownerId);
      conversationId = conversation.id;
    }

    const history = await getConversationHistory(conversation.id);

    const messages = [
      { role: "system", content: SYSTEM_PROMPT },
      ...history,
      { role: "user", content: userMessage.trim() }
    ];

    const assistantMessage = await callGroq(apiKey, messages);

    if (!assistantMessage) {
      throw new Error("Groq n'a pas renvoyé de réponse.");
    }

    // DemonScript
    const demonScript = parseDemonScript(assistantMessage.content);

    if (demonScript) {
      const pendingAction = prepareDemonScript(
        req.sessionId,
        demonScript
      );

      const replies = {
        start: "Je te propose de démarrer le serveur Falix.",
        stop: "Je te propose d'arrêter le serveur Falix.",
        restart: "Je te propose de redémarrer le serveur Falix."
      };

      const reply = demonScript.type === "command"
        ? `Je te propose d'envoyer cette commande Minecraft : ${demonScript.command}`
        : replies[demonScript.signal];

      await saveConversationExchange(
        req.ownerId,
        conversation.id,
        userMessage.trim(),
        reply
      );

      return res.json({
        success: true,
        reply,
        pendingAction,
        conversationId: conversation.id
      });
    }

    let pendingAction = null;
    let finalAnswer = assistantMessage.content;

    // Traiter les fonctions demandées par Groq
    if (assistantMessage.tool_calls?.length) {
      messages.push(assistantMessage);

      for (const toolCall of assistantMessage.tool_calls) {
        let toolResult;

        try {
          const functionName = toolCall.function?.name;
          const args = JSON.parse(
            toolCall.function?.arguments || "{}"
          );

          if (functionName === "get_server_status") {
            toolResult = JSON.stringify({
              success: true,
              server: await getFalixStatus()
            });
          } else if (functionName === "get_console_log") {
            toolResult = JSON.stringify({
              success: true,
              console: await getFalixLogs()
            });
          } else if (functionName === "prepare_server_command") {
            const prepared = prepareCommand(
              req.sessionId,
              args.command
            );

            pendingAction = prepared;

            toolResult = JSON.stringify({
              success: true,
              confirmationRequired: true,
              command: prepared.command
            });
          } else if (functionName === "prepare_server_power") {
            const prepared = preparePower(
              req.sessionId,
              args.signal
            );

            pendingAction = prepared;

            toolResult = JSON.stringify({
              success: true,
              confirmationRequired: true,
              action: args.signal
            });
          } else if (functionName === "list_server_files") {
            const files = await listFalixFiles(
              args.directory || "/"
            );

            toolResult = JSON.stringify({
              success: true,
              files
            });
          } else if (functionName === "read_server_file") {
            const file = await readFalixFile(args.path);

            toolResult = JSON.stringify({
              success: true,
              file
            });
          } else if (functionName === "prepare_file_write") {
            const prepared = prepareFileWrite(
              req.sessionId,
              args.path,
              args.content
            );

            pendingAction = prepared;

            toolResult = JSON.stringify({
              success: true,
              confirmationRequired: true,
              path: args.path
            });
          } else {
            toolResult = JSON.stringify({
              success: false,
              error: "Fonction non autorisée."
            });
          }
        } catch (error) {
          toolResult = JSON.stringify({
            success: false,
            error: error.message
          });
        }

        messages.push({
          role: "tool",
          tool_call_id: toolCall.id,
          content: toolResult
        });
      }

      const finalMessage = await callGroq(
        apiKey,
        messages,
        false
      );

      finalAnswer = finalMessage?.content;

      if (!finalAnswer) {
        throw new Error("Réponse finale vide.");
      }
    }

    if (!finalAnswer) {
      throw new Error("Groq n'a pas renvoyé de réponse.");
    }

    await saveConversationExchange(
      req.ownerId,
      conversation.id,
      userMessage.trim(),
      finalAnswer
    );

    return res.json({
      success: true,
      reply: finalAnswer,
      pendingAction,
      conversationId: conversation.id
    });
  } catch (error) {
    console.error("Erreur chat :", error.message);

    return res.status(500).json({
      success: false,
      error: error.message.includes("100")
        ? error.message
        : "Impossible de traiter la demande. Réessaie dans un instant."
    });
  }
});

// ================================
// NETTOYAGE PERIODIQUE
// ================================

setInterval(() => {
  const now = Date.now();

  for (const [actionId, action] of pendingActions) {
    if (action.expiresAt < now) {
      pendingActions.delete(actionId);
    }
  }

  for (const [id, session] of sessions) {
    if (session.expiresAt < now) {
      sessions.delete(id);
    }
  }
}, 60 * 1000).unref();

// ================================
// DEMARRAGE DU SERVEUR
// ================================

async function startServer() {
  try {
    await initializeDatabase();
  } catch (error) {
    databaseReady = false;
    console.error(
      "Connexion PostgreSQL impossible :",
      error.message
    );
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log("Diagnostic sécurité :", {
      sitePasswordPresent: Boolean(process.env.SITE_PASSWORD),
      sessionSecretPresent: Boolean(process.env.SESSION_SECRET),
      sessionSecretLength: process.env.SESSION_SECRET?.length || 0
    });

    console.log("Demon City IA démarré sur le port", PORT);
    console.log("DemonScript activé.");
    console.log("DemonCode activé.");
    console.log(
      "Conversations PostgreSQL :",
      databaseReady ? "activées" : "indisponibles"
    );
  });
}

startServer();
