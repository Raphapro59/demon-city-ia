
import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Configuration du serveur Demon City IA
const app = express();
const PORT = process.env.PORT || 3000;
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Autoriser les requêtes JSON
app.use(express.json({ limit: "1mb" }));

// Afficher l'interface web située dans /public
app.use(express.static(path.join(__dirname, "public")));

// Vérifier que Demon City IA fonctionne
app.get("/status", (req, res) => {
  res.json({
    success: true,
    name: "Demon City IA",
    status: "online"
  });
});

// Tester la connexion à l'API Falix
app.get("/falix-test", async (req, res) => {
  // Vérifier que la clé API existe dans Render
  const apiKey = process.env.FALIX_API_KEY;

  if (!apiKey) {
    return res.status(500).json({
      success: false,
      error: "Clé API Falix manquante dans Render"
    });
  }

  try {
    // Interroger Falix pour vérifier la clé
    const response = await fetch(
      "https://client.falixnodes.net/api/v2/me",
      {
        method: "GET",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          Accept: "application/json"
        }
      }
    );

    const result = await response.json();

    // Gérer les erreurs renvoyées par Falix
    if (!response.ok) {
      return res.status(response.status).json({
        success: false,
        error: result.error?.message || "Erreur de connexion Falix",
        code: result.error?.code || "unknown"
      });
    }

    // Confirmer la connexion sans exposer la clé
    res.json({
      success: true,
      message: "Demon City IA est connecté à Falix !",
      account: result.data?.account?.username || "Connecté",
      permissions: result.data?.key?.scopes || []
    });

  } catch (error) {
    console.error("Erreur Falix :", error.message);

    res.status(502).json({
      success: false,
      error: "Impossible de joindre l'API Falix"
    });
  }
});

// Démarrer le serveur web
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Demon City IA lancé sur le port ${PORT}`);
});
