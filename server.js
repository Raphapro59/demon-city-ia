
import express from "express";

// Création de l'application Demon City IA
const app = express();

// Autoriser les requêtes JSON
app.use(express.json());

// Page d'accueil
app.get("/", (req, res) => {
  res.send(`
    <h1>Demon City IA</h1>
    <p>Le serveur fonctionne !</p>
    <p>Assistant en cours de développement.</p>
  `);
});

// Vérifier l'état de l'application
app.get("/status", (req, res) => {
  res.json({
    name: "Demon City IA",
    status: "online",
    falix: "not_connected"
  });
});

// Démarrer le serveur sur le port fourni par l'hébergeur
const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Demon City IA démarré sur le port ${PORT}`);
});
