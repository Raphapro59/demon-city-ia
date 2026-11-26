
import express from "express";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const app = express();
const PORT = process.env.PORT || 3000;
const __dirname = path.dirname(fileURLToPath(import.meta.url));

app.use(express.json({ limit: "20kb" }));

// Configuration des sessions
const sessions = new Map();
const loginAttempts = new Map();
const SESSION_DURATION = 24 * 60 * 60 * 1000;
const COOKIE_NAME = "dcia_session";

// Générer une signature sécurisée pour les sessions
function signSession(id) {
  return crypto
    .createHmac("sha256", process.env.SESSION_SECRET)
    .update(id)
    .digest("base64url");
}

// Vérifier le cookie de session
function getSession(req) {
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
  const receivedBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);

  if (
    receivedBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(receivedBuffer, expectedBuffer)
  ) {
    return null;
  }

  const session = sessions.get(id);

  if (!session || session.expiresAt < Date.now()) {
    sessions.delete(id);
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
body{margin:0;min-height:100vh;display:grid;place-items:center;
background:#171316;color:#f5eef3;font:15px system-ui,sans-serif;padding:20px}
.card{width:100%;max-width:390px;background:#211a20;border:1px solid #392a35;
border-radius:20px;padding:28px;box-shadow:0 20px 60px #0005}
.mark{width:54px;height:54px;display:grid;place-items:center;border-radius:16px;
background:linear-gradient(145deg,#c13a65,#65152f);font-weight:900;font-size:20px}
h1{font-size:23px;margin:20px 0 5px}
p{color:#aa9ca7;font-size:13px;margin:0 0 22px}
label{display:block;font-size:12px;margin-bottom:8px;color:#d8cbd4}
input{width:100%;padding:13px;border:1px solid #51404b;border-radius:10px;
background:#171316;color:white;outline:none}
input:focus{border-color:#c33562}
button{width:100%;margin-top:14px;padding:13px;border:0;border-radius:10px;
background:#a92750;color:white;font-weight:700;cursor:pointer}
button:disabled{opacity:.5}
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
<input id="password" type="password" autocomplete="current-password"
placeholder="Ton mot de passe" required>
<button id="submit" type="submit">Se connecter</button>
<div id="error" role="alert"></div>
</form>
</div>
<script>
const form = document.getElementById("loginForm");
const input = document.getElementById("password");
const error = document.getElementById("error");
const button = document.getElementById("submit");

form.addEventListener("submit", async event => {
  event.preventDefault();
  button.disabled = true;
  error.textContent = "";

  try {
    const response = await fetch("/auth/login", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({password: input.value})
    });

    const data = await response.json();

    if (!response.ok) throw new Error(data.error || "Connexion refusée.");

    location.href = "/";
  } catch (err) {
    error.textContent = err.message;
  } finally {
    button.disabled = false;
  }
});
</script>
</body>
</html>`;

// Afficher l'écran de connexion
app.get("/login", (req, res) => {
  res.type("html").send(loginPage);
});

// Vérifier si une session est déjà active
app.get("/auth/status", (req, res) => {
  res.json({ authenticated: Boolean(getSession(req)) });
});

// Connexion avec le mot de passe défini dans Render
app.post("/auth/login", (req, res) => {
  const password = process.env.SITE_PASSWORD;
  const secret = process.env.SESSION_SECRET;
  const submitted = req.body?.password;

  if (!password || !secret || secret.length < 32) {
    return res.status(503).json({
      error: "Configuration de sécurité incomplète."
    });
  }

  if (typeof submitted !== "string" || submitted.length > 200) {
    return res.status(400).json({ error: "Mot de passe invalide." });
  }

  // Limiter les tentatives de connexion
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

  // Comparer les empreintes sans comparaison directe des mots de passe
  const expected = crypto.createHash("sha256").update(password).digest();
  const received = crypto.createHash("sha256").update(submitted).digest();

  if (!crypto.timingSafeEqual(expected, received)) {
    attempts.count++;
    loginAttempts.set(ip, attempts);

    return res.status(401).json({
      error: "Mot de passe incorrect."
    });
  }

  loginAttempts.delete(ip);

  // Créer une session aléatoire
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

// Déconnexion
app.post("/auth/logout", (req, res) => {
  const current = getSession(req);

  if (current) sessions.delete(current.id);

  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`
  );

  res.json({ success: true });
});

// Protéger toutes les autres pages et routes
app.use((req, res, next) => {
  if (getSession(req)) return next();

  if (req.accepts("html") && !req.path.startsWith("/auth/")) {
    return res.redirect("/login");
  }

  return res.status(401).json({
    success: false,
    error: "Connexion nécessaire."
  });
});

// Servir le véritable site après connexion
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.use(express.static(path.join(__dirname, "public")));

// Instructions de Demon City IA
const SYSTEM_PROMPT = `
Tu es Demon City IA, l'assistant officiel du serveur Minecraft Demon City.
Tu parles français, naturellement et clairement.
Tu aides à gérer le serveur Minecraft Bedrock et les projets Demon City.
Tu ne prétends jamais avoir effectué une action qui n'a pas été exécutée.
Ne te présente pas spontanément à chaque conversation.
`;

// Statut général
app.get("/status", (req, res) => {
  res.json({
    success: true,
    name: "Demon City IA",
    status: "online",
    aiConfigured: Boolean(process.env.GROQ_API_KEY),
    falixConfigured: Boolean(process.env.FALIX_API_KEY)
  });
});

// Vérifier la connexion Falix
app.get("/falix-test", async (req, res) => {
  const apiKey = process.env.FALIX_API_KEY;

  if (!apiKey) {
    return res.status(500).json({
      success: false,
      error: "Clé API Falix manquante"
    });
  }

  try {
    const response = await fetch(
      "https://client.falixnodes.net/api/v2/me",
      {
        headers: { Authorization: `Bearer ${apiKey}` },
        signal: AbortSignal.timeout(15000)
      }
    );

    const result = await response.json();

    if (!response.ok) {
      return res.status(response.status).json({
        success: false,
        error: result.error?.message || "Erreur Falix"
      });
    }

    res.json({
      success: true,
      message: "Demon City IA est connecté à Falix !",
      account: result.data?.account?.username || "Connecté"
    });
  } catch (error) {
    console.error("Erreur Falix :", error.message);
    res.status(500).json({
      success: false,
      error: "Impossible de contacter Falix"
    });
  }
});

// Lire le statut du serveur Minecraft
app.get("/falix-status", async (req, res) => {
  const apiKey = process.env.FALIX_API_KEY;
  const serverId = process.env.FALIX_SERVER_ID;

  if (!apiKey || !serverId) {
    return res.status(500).json({
      success: false,
      error: "Configuration Falix incomplète"
    });
  }

  try {
    const response = await fetch(
      `https://client.falixnodes.net/api/v2/servers/${encodeURIComponent(serverId)}/console/status`,
      {
        headers: { Authorization: `Bearer ${apiKey}` },
        signal: AbortSignal.timeout(15000)
      }
    );

    const result = await response.json();

    if (!response.ok) {
      return res.status(response.status).json({
        success: false,
        error: result.error?.message || "Falix a refusé la demande"
      });
    }

    const server = result.data;

    res.json({
      success: true,
      server: {
        id: server.server_id,
        name: server.server_name,
        status: server.status,
        message: server.message,
        nodeReady: server.node_ready,
        resources: server.resources || null
      }
    });
  } catch (error) {
    console.error("Erreur statut :", error.message);
    res.status(500).json({
      success: false,
      error: "Impossible de récupérer le statut du serveur"
    });
  }
});

// Envoyer un message à Groq
app.post("/chat", async (req, res) => {
  const apiKey = process.env.GROQ_API_KEY;
  const message = req.body?.message;

  if (!apiKey) {
    return res.status(500).json({
      success: false,
      error: "Clé API Groq manquante"
    });
  }

  if (typeof message !== "string" || !message.trim()) {
    return res.status(400).json({
      success: false,
      error: "Message vide ou invalide"
    });
  }

  if (message.length > 8000) {
    return res.status(400).json({
      success: false,
      error: "Message trop long"
    });
  }

  try {
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
          messages: [
            { role: "system", content: SYSTEM_PROMPT },
            { role: "user", content: message.trim() }
          ],
          temperature: 0.7,
          max_tokens: 1000
        }),
        signal: AbortSignal.timeout(30000)
      }
    );

    const result = await response.json();

    if (!response.ok) {
      return res.status(502).json({
        success: false,
        error: result.error?.message || "Erreur du moteur Groq"
      });
    }

    const answer = result.choices?.[0]?.message?.content;

    if (!answer) {
      return res.status(502).json({
        success: false,
        error: "Groq n'a pas renvoyé de réponse"
      });
    }

    res.json({ success: true, reply: answer });
  } catch (error) {
    console.error("Erreur serveur :", error.message);
    res.status(500).json({
      success: false,
      error: "Impossible de contacter le moteur IA"
    });
  }
});

// Démarrer Demon City IA
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Demon City IA démarré sur le port ${PORT}`);
});
