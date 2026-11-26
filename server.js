
import express from "express";

// Création de l'application Demon City IA
const app = express();

// Autoriser les requêtes JSON
app.use(express.json());

// Afficher l'interface Demon City IA
app.use(express.static("public"));

// Vérifier l'état de l'application
app.get("/status", (req, res) => {
  res.json({
    name: "Demon City IA",
    status: "online",
    falix: "not_connected"
  });
});

// Démarrer le serveur
const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Demon City IA démarré sur le port ${PORT}`);
});
