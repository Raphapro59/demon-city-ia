
import express from "express";

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "20kb" }));
app.use(express.static("public"));

// Instructions de Demon City IA
const SYSTEM_PROMPT = `
Tu es Demon City IA, l'assistant officiel du serveur Minecraft Demon City.
Tu parles français, naturellement et clairement.
Tu aides à gérer le serveur Minecraft Bedrock et les projets Demon City.
Tu ne prétends jamais avoir effectué une action qui n'a pas été exécutée.
`;

// Statut général de Demon City IA
app.get("/status", (req, res) => {
  res.json({
    success: true,
    name: "Demon City IA",
    status: "online",
    aiConfigured: Boolean(process.env.GROQ_API_KEY),
    falixConfigured: Boolean(process.env.FALIX_API_KEY)
  });
});

// Vérifier la connexion au compte Falix
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
        headers: {
          Authorization: `Bearer ${apiKey}`
        }
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

// Lire le véritable statut du serveur Minecraft
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
        headers: {
          Authorization: `Bearer ${apiKey}`
        },
        signal: AbortSignal.timeout(15000)
      }
    );

    const result = await response.json();

    if (!response.ok) {
      console.error("Erreur statut Falix :", response.status);

      return res.status(response.status).json({
        success: false,
        error: result.error?.message || "Falix a refusé la demande"
      });
    }

    // Falix renvoie les informations dans result.data
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

// Envoyer un message au moteur Groq
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
      console.error("Erreur Groq :", response.status);

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

    res.json({
      success: true,
      reply: answer
    });

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
