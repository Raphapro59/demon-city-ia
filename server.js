
import express from "express";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const app = express();
const PORT = process.env.PORT || 3000;
const __dirname = path.dirname(fileURLToPath(import.meta.url));

app.set("trust proxy", 1);
app.use(express.json({ limit: "20kb" }));

// Sessions et protections
const sessions = new Map();
const loginAttempts = new Map();

// Actions en attente de validation, identifiées par un jeton unique
const pendingCommands = new Map();

const SESSION_DURATION = 24 * 60 * 60 * 1000;
const COMMAND_CONFIRMATION_DURATION = 2 * 60 * 1000;
const COOKIE_NAME = "dcia_session";

// Vérifier la configuration de sécurité
function securityConfigured() {
  return Boolean(
    process.env.SITE_PASSWORD &&
    process.env.SESSION_SECRET &&
    process.env.SESSION_SECRET.length >= 32
  );
}

// Signer les identifiants de session
function signSession(id) {
  return crypto
    .createHmac("sha256", process.env.SESSION_SECRET)
    .update(id)
    .digest("base64url");
}

// Récupérer la session du visiteur
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

    // Supprimer aussi les commandes de cette session
    for (const [actionId, action] of pendingCommands) {
      if (action.sessionId === id) {
        pendingCommands.delete(actionId);
      }
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

    for (const [actionId, action] of pendingCommands) {
      if (action.sessionId === current.id) {
        pendingCommands.delete(actionId);
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

// Instructions de Demon City IA
const SYSTEM_PROMPT = `
Tu es Demon City IA, l'assistant officiel du serveur Minecraft Demon City.

Tu parles français naturellement, clairement et de manière conviviale.
Ne te présente jamais spontanément.
Réponds directement aux demandes.

Fonctions disponibles :
- get_server_status : consulter le statut réel du serveur Falix.
- get_console_log : consulter les dernières lignes de la console.
- prepare_server_command : préparer une commande Minecraft.

Si l'utilisateur demande le statut, utilise get_server_status.
S'il demande ce qui se passe dans la console, utilise get_console_log.
S'il demande d'exécuter une commande Minecraft, utilise prepare_server_command.

IMPORTANT :
prepare_server_command prépare une commande, mais ne l'exécute jamais.
L'interface affichera automatiquement des boutons Valider et Refuser.
Ne demande jamais à l'utilisateur de taper un code de confirmation.
Ne prétends jamais qu'une commande a été exécutée avant que Falix
ait répondu positivement après un clic sur Valider.

Ne révèle jamais les clés API, mots de passe ou secrets.
Ne prétends jamais avoir accès à des fonctions non disponibles.
`;

// Configuration Falix
function getFalixConfig() {
  const apiKey = process.env.FALIX_API_KEY;
  const serverId = process.env.FALIX_SERVER_ID;

  if (!apiKey || !serverId) {
    throw new Error("Configuration Falix incomplète.");
  }

  return { apiKey, serverId };
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
      signal: AbortSignal.timeout(15000)
    }
  );

  const result = await response.json().catch(() => ({}));

  if (!response.ok) {
    const message =
      result.error?.message ||
      result.message ||
      `Erreur Falix (${response.status})`;

    throw new Error(message);
  }

  return result.data;
}

// Lire le statut réel du serveur
async function getFalixStatus() {
  const { serverId } = getFalixConfig();

  const server = await falixRequest(
    `/servers/${encodeURIComponent(serverId)}/console/status`
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

// Lire les dernières lignes de la console
async function getFalixLogs() {
  const { serverId } = getFalixConfig();

  const data = await falixRequest(
    `/servers/${encodeURIComponent(serverId)}/console/log?lines=40`
  );

  return {
    source: data.source || null,
    truncated: Boolean(data.truncated),
    lines: Array.isArray(data.lines) ? data.lines : []
  };
}

// Envoyer une commande à Falix
async function sendFalixCommand(command) {
  const { serverId } = getFalixConfig();

  const data = await falixRequest(
    `/servers/${encodeURIComponent(serverId)}/commands`,
    {
      method: "POST",
      headers: {
        "Idempotency-Key": crypto.randomUUID()
      },
      body: JSON.stringify({ command })
    }
  );

  return {
    accepted: data?.accepted === true,
    serverId: data?.server_id
  };
}

// Préparer une commande sans l'exécuter
function prepareCommand(sessionId, command) {
  if (typeof command !== "string") {
    throw new Error("Commande invalide.");
  }

  const cleaned = command.trim().replace(/^\/+/, "");

  if (!cleaned || cleaned.length > 300) {
    throw new Error("La commande doit contenir entre 1 et 300 caractères.");
  }

  // Une seule ligne est autorisée
  if (/[\r\n\u0000-\u001f]/.test(cleaned)) {
    throw new Error("Les commandes sur plusieurs lignes sont interdites.");
  }

  // Bloquer les commandes à fort impact
  const forbidden = ["stop", "restart", "kill", "op", "deop"];
  const firstWord = cleaned.split(/\s+/)[0].toLowerCase();

  if (forbidden.includes(firstWord)) {
    throw new Error("Cette commande est bloquée dans cette première version.");
  }

  // Créer un identifiant secret et unique pour le bouton
  const actionId = crypto.randomBytes(24).toString("base64url");
  const expiresAt = Date.now() + COMMAND_CONFIRMATION_DURATION;

  pendingCommands.set(actionId, {
    sessionId,
    command: cleaned,
    expiresAt
  });

  return {
    success: true,
    confirmationRequired: true,
    actionId,
    command: cleaned,
    expiresAt
  };
}

// Valider une commande depuis le bouton de l'interface
app.post("/actions/confirm", async (req, res) => {
  const actionId = req.body?.actionId;

  if (typeof actionId !== "string" || actionId.length > 100) {
    return res.status(400).json({
      success: false,
      reply: "La demande de validation est invalide."
    });
  }

  const pending = pendingCommands.get(actionId);

  if (!pending || pending.sessionId !== req.sessionId) {
    return res.status(404).json({
      success: false,
      reply: "Cette commande n'existe plus ou a déjà été traitée."
    });
  }

  if (Date.now() > pending.expiresAt) {
    pendingCommands.delete(actionId);

    return res.status(410).json({
      success: false,
      reply: "Le délai de validation est dépassé. Prépare à nouveau ta commande."
    });
  }

  // Supprimer l'action avant l'appel pour empêcher les doubles clics
  pendingCommands.delete(actionId);

  try {
    const result = await sendFalixCommand(pending.command);

    if (!result.accepted) {
      return res.status(502).json({
        success: false,
        reply: "Falix n'a pas confirmé l'acceptation de la commande. Vérifie la console du serveur."
      });
    }

    return res.json({
      success: true,
      reply: `C'est fait ! La commande \`${pending.command}\` a bien été acceptée par Falix.`
    });
  } catch (error) {
    console.error("Erreur commande Falix :", error.message);

    return res.status(502).json({
      success: false,
      reply: `Je n'ai pas réussi à envoyer la commande à Falix : ${error.message}`
    });
  }
});

// Refuser une commande depuis le bouton de l'interface
app.post("/actions/cancel", (req, res) => {
  const actionId = req.body?.actionId;

  if (typeof actionId !== "string" || actionId.length > 100) {
    return res.status(400).json({
      success: false,
      reply: "La demande d'annulation est invalide."
    });
  }

  const pending = pendingCommands.get(actionId);

  if (!pending || pending.sessionId !== req.sessionId) {
    return res.status(404).json({
      success: false,
      reply: "Cette commande n'existe plus ou a déjà été traitée."
    });
  }

  pendingCommands.delete(actionId);

  return res.json({
    success: true,
    reply: "C'est noté ! J'ai annulé la commande. Rien n'a été envoyé à Falix."
  });
});

// Statut général de Demon City IA
app.get("/status", (req, res) => {
  res.json({
    success: true,
    name: "Demon City IA",
    status: "online",
    aiConfigured: Boolean(process.env.GROQ_API_KEY),
    falixConfigured: Boolean(
      process.env.FALIX_API_KEY && process.env.FALIX_SERVER_ID
    )
  });
});

// Vérifier la connexion Falix
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

    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Lecture de la console
app.get("/falix-console", async (req, res) => {
  try {
    const logs = await getFalixLogs();

    res.json({
      success: true,
      console: logs
    });
  } catch (error) {
    console.error("Erreur lecture console :", error.message);

    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Fonctions accessibles à l'IA
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
      description: "Lire les dernières lignes de la console Minecraft.",
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
      description: "Préparer une commande Minecraft. Elle ne sera exécutée qu'après le clic de l'utilisateur sur Valider.",
      parameters: {
        type: "object",
        properties: {
          command: {
            type: "string",
            description: "Commande Minecraft sans slash initial."
          }
        },
        required: ["command"],
        additionalProperties: false
      }
    }
  }
];

// Chat principal avec Groq et Falix
app.post("/chat", async (req, res) => {
  const apiKey = process.env.GROQ_API_KEY;
  const message = req.body?.message;

  if (!apiKey) {
    return res.status(500).json({
      success: false,
      error: "Clé API Groq manquante."
    });
  }

  if (typeof message !== "string" || !message.trim()) {
    return res.status(400).json({
      success: false,
      error: "Message vide ou invalide."
    });
  }

  if (message.length > 8000) {
    return res.status(400).json({
      success: false,
      error: "Message trop long."
    });
  }

  try {
    const messages = [
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: message.trim() }
    ];

    // Première demande à Groq
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
          tools: availableTools,
          tool_choice: "auto",
          temperature: 0.7,
          max_tokens: 1000
        }),
        signal: AbortSignal.timeout(30000)
      }
    );

    const result = await response.json();

    if (!response.ok) {
      console.error("Erreur Groq :", response.status, result.error);

      return res.status(502).json({
        success: false,
        error: result.error?.message || "Erreur du moteur Groq."
      });
    }

    const assistantMessage = result.choices?.[0]?.message;

    if (!assistantMessage) {
      return res.status(502).json({
        success: false,
        error: "Groq n'a pas renvoyé de réponse."
      });
    }

    let pendingAction = null;

    // Exécuter uniquement les fonctions prévues
    if (assistantMessage.tool_calls?.length) {
      messages.push(assistantMessage);

      for (const toolCall of assistantMessage.tool_calls) {
        let toolResult;

        try {
          const functionName = toolCall.function?.name;
          const args = JSON.parse(toolCall.function?.arguments || "{}");

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
            // Préparer la commande et transmettre l'action à l'interface
            const prepared = prepareCommand(req.sessionId, args.command);

            pendingAction = {
              actionId: prepared.actionId,
              command: prepared.command,
              expiresAt: prepared.expiresAt
            };

            toolResult = JSON.stringify({
              success: true,
              confirmationRequired: true,
              command: prepared.command,
              message: "La commande est prête. L'utilisateur doit choisir Valider ou Refuser dans l'interface."
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

      // Faire formuler la réponse finale par Groq
      const finalResponse = await fetch(
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
            temperature: 0.7,
            max_tokens: 1000
          }),
          signal: AbortSignal.timeout(30000)
        }
      );

      const finalResult = await finalResponse.json();

      if (!finalResponse.ok) {
        console.error("Erreur réponse finale Groq :", finalResult.error);

        return res.status(502).json({
          success: false,
          error: "Erreur lors de la réponse finale de Groq."
        });
      }

      const finalAnswer = finalResult.choices?.[0]?.message?.content;

      if (!finalAnswer) {
        return res.status(502).json({
          success: false,
          error: "Réponse finale vide."
        });
      }

      return res.json({
        success: true,
        reply: finalAnswer,
        pendingAction
      });
    }

    const answer = assistantMessage.content;

    if (!answer) {
      return res.status(502).json({
        success: false,
        error: "Groq n'a pas renvoyé de réponse."
      });
    }

    return res.json({
      success: true,
      reply: answer,
      pendingAction: null
    });

  } catch (error) {
    console.error("Erreur serveur :", error.message);

    return res.status(500).json({
      success: false,
      error: "Impossible de contacter le moteur IA."
    });
  }
});

// Démarrer Demon City IA
app.listen(PORT, "0.0.0.0", () => {
  console.log("Diagnostic sécurité :", {
    sitePasswordPresent: Boolean(process.env.SITE_PASSWORD),
    sessionSecretPresent: Boolean(process.env.SESSION_SECRET),
    sessionSecretLength: process.env.SESSION_SECRET?.length || 0
  });

  console.log(`Demon City IA démarré sur le port ${PORT}`);
});
