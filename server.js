
import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Configuration de Demon City IA
const app = express();
const PORT = process.env.PORT || 3000;
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Modèle IA utilisé
const AI_MODEL = process.env.OPENAI_MODEL || "gpt-6.2-sol";

// Configuration Express
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

// Instructions principales de Demon City IA
const AI_INSTRUCTIONS = `
Tu es Demon City IA, l'assistant intelligent du projet Demon City.

Tu parles français naturellement.
Tu es sympathique, précis et utile.
Tu connais Minecraft Bedrock et le serveur Demon City RP.
Tu aides à gérer le serveur Falix.

IMPORTANT :
- Ne prétends jamais avoir effectué une action qui n'a pas été exécutée.
- Pour le moment, tu peux discuter et expliquer les choses.
- Tu ne peux pas encore exécuter directement les commandes Falix.
- Ne demande jamais à l'utilisateur de révéler ses clés API.
`;

// État du serveur web
app.get("/status", (req, res) => {
  res.json({
    success: true,
    name: "Demon City IA",
    status: "online",
    aiConfigured: Boolean(process.env.OPENAI_API_KEY),
    falixConfigured: Boolean(process.env.FALIX_API_KEY)
  });
});

// Discussion avec le moteur IA OpenAI
app.post("/chat", async (req, res) => {
  const apiKey = process.env.OPENAI_API_KEY;
  const message = req.body?.message;

  // Vérifier la clé OpenAI
  if (!apiKey) {
    return res.status(500).json({
      success: false,
      error: "Moteur IA non configuré."
    });
  }

  // Vérifier le message
  if (typeof message !== "string" || !message.trim()) {
    return res.status(400).json({
      success: false,
      error: "Message vide ou invalide."
    });
  }

  if (message.length > 3000) {
    return res.status(400).json({
      success: false,
      error: "Message trop long (3000 caractères maximum)."
    });
  }

  try {
    // Envoyer le message à OpenAI
    const response = await fetch(
      "https://api.openai.com/v1/responses",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${apiKey}`
        },
        body: JSON.stringify({
          model: AI_MODEL,
          instructions: AI_INSTRUCTIONS,
          input: message,
          max_output_tokens: 1000
        })
      }
    );

    const result = await response.json();

    // Gérer les erreurs OpenAI
    if (!response.ok) {
      console.error("Erreur OpenAI :", result.error?.message);

      return res.status(response.status).json({
        success: false,
        error: "Le moteur IA a rencontré une erreur.",
        code: result.error?.code || "openai_error"
      });
    }

    // Récupérer le texte de la réponse
    const reply = (result.output || [])
      .flatMap(item => item.content || [])
      .filter(item => item.type === "output_text")
      .map(item => item.text)
      .join("\n");

    if (!reply) {
      return res.status(502).json({
        success: false,
        error: "L'IA n'a pas renvoyé de réponse."
      });
    }

    res.json({
      success: true,
      reply
    });

  } catch (error) {
    console.error("Erreur moteur IA :", error.message);

    res.status(502).json({
      success: false,
      error: "Impossible de contacter le moteur IA."
    });
  }
});

// Tester la connexion Falix
app.get("/falix-test", async (req, res) => {
  const apiKey = process.env.FALIX_API_KEY;

  if (!apiKey) {
    return res.status(500).json({
      success: false,
      error: "Clé API Falix manquante."
    });
  }

  try {
    const response = await fetch(
      "https://client.falixnodes.net/api/v2/me",
      {
        headers: {
          Authorization: `Bearer ${apiKey}`,
          Accept: "application/json"
        }
      }
    );

    const result = await response.json();

    if (!response.ok) {
      return res.status(response.status).json({
        success: false,
        error: "Erreur de connexion Falix."
      });
    }

    res.json({
      success: true,
      message: "Demon City IA est connecté à Falix !",
      account: result.data?.account?.username || "Connecté"
    });

  } catch (error) {
    console.error("Erreur Falix :", error.message);

    res.status(502).json({
      success: false,
      error: "Impossible de joindre Falix."
    });
  }
});

// Démarrer Demon City IA
app.listen(PORT, "0.0.0.0", () => {
  console.log("Demon City IA est lancé !");
  console.log(`Port : ${PORT}`);
  console.log(`Modèle IA : ${AI_MODEL}`);
});
