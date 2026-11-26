
import express from "express";

const app = express();
const PORT = process.env.PORT || 3000;

// Autoriser les requêtes JSON
app.use(express.json({ limit: "20kb" }));

// Afficher l'interface Demon City IA
app.use(express.static("public"));

// Configuration de l'assistant
const SYSTEM_PROMPT = `
Tu es Demon City IA, l'assistant officiel du serveur Minecraft Demon City.
Tu parles français, avec un ton naturel et sympathique.
Tu aides les joueurs et les administrateurs pour Minecraft Bedrock,
la gestion du serveur et les projets Demon City.

Tu ne prétends jamais avoir effectué une action si elle n'a pas réellement été exécutée.
La connexion Falix existe, mais les commandes de gestion ne sont pas encore toutes implémentées.
`;

// Vérifier la configuration
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
      error: "Clé API Falix manquante dans Render"
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
        error: "Falix a refusé la connexion"
      });
    }

    res.json({
      success: true,
      message: "Demon City IA est connecté à Falix !",
      account: result.username || result.name || "Connecté"
    });

  } catch (error) {
    console.error("Erreur Falix :", error.message);

    res.status(500).json({
      success: false,
      error: "Impossible de contacter Falix"
    });
  }
});

// Envoyer un message à Groq
app.post("/chat", async (req, res) => {
  const apiKey = process.env.GROQ_API_KEY;

  if (!apiKey) {
    return res.status(500).json({
      success: false,
      error: "Clé API Groq manquante dans Render"
    });
  }

  const message = req.body?.message;

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
            {
              role: "system",
              content: SYSTEM_PROMPT
            },
            {
              role: "user",
              content: message.trim()
            }
          ],
          temperature: 0.7,
          max_tokens: 1000
        })
      }
    );

    const result = await response.json();

    if (!response.ok) {
      console.error(
        "Erreur Groq :",
        response.status,
        result.error?.message || "Erreur inconnue"
      );

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

// Démarrer le serveur
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Demon City IA démarré sur le port ${PORT}`);
});
