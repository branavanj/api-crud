require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const nodemailer = require('nodemailer');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY;
const saltRounds = 10;

// Servir le front-end statique (par exemple, dans le dossier "public")
app.use(express.static('public'));

app.use(bodyParser.json());

const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

// Configuration de Nodemailer (ici avec Gmail)
const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  }
});

// Template HTML complet pour l'email de validation
const emailTemplate = `
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <title>Validation de votre email</title>
  </head>
  <body style="margin: 0; padding: 0; background-color: #f4f4f4;">
    <table border="0" cellpadding="0" cellspacing="0" width="100%">
      <tr>
        <td style="padding: 20px 0 30px 0;">
          <table align="center" border="0" cellpadding="0" cellspacing="0" width="600"
            style="border-collapse: collapse; border: 1px solid #cccccc; background-color: #ffffff;">
            <tr>
              <td align="center" bgcolor="#70bbd9"
                style="padding: 40px 0 30px 0; font-family: Arial, sans-serif;">
                <h1 style="color: #ffffff; margin: 0;">Votre Compagnie</h1>
              </td>
            </tr>
            <tr>
              <td style="padding: 40px 30px 40px 30px; font-family: Arial, sans-serif;">
                <table border="0" cellpadding="0" cellspacing="0" width="100%">
                  <tr>
                    <td style="color: #153643; font-size: 24px;">
                      <b>Validation de votre email</b>
                    </td>
                  </tr>
                  <tr>
                    <td style="padding: 20px 0 30px 0; color: #153643; font-size: 16px; line-height: 20px;">
                      Bonjour,<br /><br />
                      Merci de vous être inscrit sur notre plateforme. Pour activer votre compte, veuillez cliquer sur le bouton ci-dessous afin de valider votre adresse email.
                    </td>
                  </tr>
                  <tr>
                    <td align="center">
                      <a href="{{url}}"
                        style="background-color: #28a745; color: #ffffff; padding: 15px 25px; text-decoration: none; font-size: 16px; border-radius: 5px;">
                        Valider mon email
                      </a>
                    </td>
                  </tr>
                  <tr>
                    <td style="padding: 20px 0 30px 0; color: #153643; font-size: 14px; line-height: 18px;">
                      Si vous n'arrivez pas à cliquer sur le bouton, copiez et collez le lien suivant dans votre navigateur :<br />
                      <a href="{{url}}" style="color: #28a745;">{{url}}</a>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
            <tr>
              <td bgcolor="#ee4c50" style="padding: 30px 30px;">
                <table border="0" cellpadding="0" cellspacing="0" width="100%">
                  <tr>
                    <td style="color: #ffffff; font-family: Arial, sans-serif; font-size: 14px;">
                      &reg; Votre Compagnie, 2025<br />
                      Pour toute question, contactez-nous.
                    </td>
                    <td align="right">
                      <table border="0" cellpadding="0" cellspacing="0">
                        <tr>
                          <td>
                            <a href="http://www.twitter.com/">
                              <img src="https://via.placeholder.com/38" alt="Twitter" width="38" height="38"
                                style="display: block;" border="0" />
                            </a>
                          </td>
                          <td style="font-size: 0; line-height: 0;" width="20">&nbsp;</td>
                          <td>
                            <a href="http://www.facebook.com/">
                              <img src="https://via.placeholder.com/38" alt="Facebook" width="38" height="38"
                                style="display: block;" border="0" />
                            </a>
                          </td>
                        </tr>
                      </table>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>
`;

// Swagger configuration
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'API Documentation',
      version: '1.0.0',
      description: 'Documentation de l\'API'
    },
    servers: [{ url: `http://localhost:${port}` }],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT'
        }
      }
    }
  },
  apis: ['./index.js'] // Les annotations Swagger se trouvent dans ce fichier
};
const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Middleware pour vérifier le token JWT (endpoints protégés)
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token manquant' });
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token invalide ou expiré' });
    req.user = user;
    next();
  });
}



/**
 * @swagger
 * /health:
 *   get:
 *     summary: Vérifie l'état de santé des services 
 *     description: Retourne le statut de la connexion à la base de données et au service SMTP, ainsi qu'un timestamp.
 *     responses:
 *       200:
 *         description: Etat de santé retourné avec succès.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 database:
 *                   type: string
 *                   example: OK
 *                 smtp:
 *                   type: string
 *                   example: OK
 *                 timestamp:
 *                   type: string
 *                   example: "2025-03-05T12:34:56.789Z"
 */
app.get('/health', (req, res) => {
  // Vérification de la base de données via une requête simple
  db.query('SELECT 1 AS result', (dbErr, dbResults) => {
    const dbStatus = !dbErr;
    if (dbErr) {
      console.error('[Health Check] - Erreur BDD:', dbErr);
    }
    // Vérification du service SMTP via transporter.verify de Nodemailer
    transporter.verify((smtpErr, success) => {
      const smtpStatus = !smtpErr;
      if (smtpErr) {
        console.error('[Health Check] - Erreur SMTP:', smtpErr);
      }
      // Log des résultats avec un horodatage
      console.log(`[Health Check] - BDD: ${dbStatus ? 'OK' : 'ERREUR'}, SMTP: ${smtpStatus ? 'OK' : 'ERREUR'} - ${new Date().toISOString()}`);
      // Réponse JSON indiquant l'état de chaque service
      res.json({
        database: dbStatus ? 'OK' : 'ERREUR',
        smtp: smtpStatus ? 'OK' : 'ERREUR',
        timestamp: new Date().toISOString()
      });
    });
  });
});





/**
 * @swagger
 * /register:
 *   post:
 *     summary: Enregistrer un nouvel utilisateur
 *     description: Crée un nouvel utilisateur, hash le mot de passe et envoie un email de validation.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Inscription réussie, email de validation envoyé.
 *       400:
 *         description: Email ou mot de passe manquant.
 *       500:
 *         description: Erreur serveur.
 */
app.post('/register', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email et password requis' });

  // Hashage du mot de passe
  bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Erreur lors du hash du mot de passe' });
    }
    const query = 'INSERT INTO users (username, password, role, verified) VALUES (?, ?, ?, ?)';
    db.query(query, [email, hashedPassword, 'user', false], (error, results) => {
      if (error) {
        console.error(error);
        return res.status(500).json({ error: 'Erreur lors de la création de l\'utilisateur' });
      }
      const userId = results.insertId;
      // Génération d'un token pour la validation de l'email (valable 1 jour)
      const emailToken = jwt.sign({ id: userId, email: email }, SECRET_KEY, { expiresIn: '1d' });
      const verificationUrl = `http://localhost:${port}/verify-email?token=${emailToken}`;
      const emailHtml = emailTemplate.replace(/{{url}}/g, verificationUrl);
      transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Validation de votre email',
        html: emailHtml
      }, (err, info) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: 'Erreur lors de l\'envoi de l\'email de validation' });
        }
        res.json({ message: 'Inscription réussie ! Veuillez vérifier votre email pour activer votre compte.' });
      });
    });
  });
});

/**
 * @swagger
 * /verify-email:
 *   get:
 *     summary: Valider l'email d'un utilisateur
 *     description: Valide l'email à l'aide du token reçu par email.
 *     parameters:
 *       - in: query
 *         name: token
 *         schema:
 *           type: string
 *         required: true
 *         description: Token de validation.
 *     responses:
 *       200:
 *         description: Email validé avec succès.
 *       400:
 *         description: Token manquant ou invalide.
 *       500:
 *         description: Erreur serveur.
 */
app.get('/verify-email', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: 'Token manquant' });
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(400).json({ error: 'Token invalide ou expiré' });
    const { id } = decoded;
    const query = 'UPDATE users SET verified = ? WHERE id = ?';
    db.query(query, [true, id], (error, results) => {
      if (error) {
        console.error(error);
        return res.status(500).json({ error: 'Erreur lors de la vérification de l\'email' });
      }
      res.json({ message: 'Email vérifié avec succès. Vous pouvez maintenant vous connecter.' });
    });
  });
});

/**
 * @swagger
 * /authenticate:
 *   post:
 *     summary: Authentifier un utilisateur
 *     description: Authentifie l'utilisateur et retourne un token JWT si l'email est validé.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Authentification réussie, retourne un token JWT.
 *       400:
 *         description: Email ou mot de passe manquant.
 *       401:
 *         description: Identifiants incorrects.
 *       403:
 *         description: Email non vérifié.
 *       500:
 *         description: Erreur serveur.
 */
app.post('/authenticate', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email et password requis' });
  const query = 'SELECT * FROM users WHERE username = ?';
  db.query(query, [email], (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: 'Erreur serveur' });
    }
    if (results.length === 0)
      return res.status(401).json({ error: 'Identifiants incorrects' });
    const user = results[0];
    // Comparaison du mot de passe avec bcrypt
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Erreur lors de la vérification du mot de passe' });
      }
      if (!isMatch)
        return res.status(401).json({ error: 'Identifiants incorrects' });
      if (!user.verified)
        return res.status(403).json({ error: 'Email non vérifié. Veuillez vérifier votre email.' });
      const authToken = jwt.sign({ id: user.id, email: user.username, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
      res.json({ token: authToken });
    });
  });
});

/**
 * @swagger
 * /orders:
 *   post:
 *     summary: Créer une commande
 *     description: Crée une commande pour l'utilisateur authentifié.
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               item:
 *                 type: string
 *               quantity:
 *                 type: integer
 *     responses:
 *       200:
 *         description: Commande créée avec succès.
 *       400:
 *         description: Champs manquants.
 *       401:
 *         description: Non authentifié.
 *       500:
 *         description: Erreur serveur.
 */
app.post('/orders', authenticateToken, (req, res) => {
  const { item, quantity } = req.body;
  if (!item || !quantity)
    return res.status(400).json({ error: 'Item et quantity requis' });
  const query = 'INSERT INTO orders (item, quantity, user_id) VALUES (?, ?, ?)';
  db.query(query, [item, quantity, req.user.id], (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: 'Erreur lors de la création de la commande' });
    }
    res.json({ message: 'Commande créée avec succès', orderId: results.insertId });
  });
});

/**
 * @swagger
 * /orders:
 *   get:
 *     summary: Récupérer les commandes
 *     description: Récupère la liste des commandes pour l'utilisateur authentifié.
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Liste des commandes.
 *       401:
 *         description: Non authentifié.
 *       500:
 *         description: Erreur serveur.
 */
app.get('/orders', authenticateToken, (req, res) => {
  const query = 'SELECT * FROM orders WHERE user_id = ?';
  db.query(query, [req.user.id], (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: 'Erreur lors de la récupération des commandes' });
    }
    res.json(results);
  });
});

/**
 * @swagger
 * /orders/{id}:
 *   put:
 *     summary: Mettre à jour une commande
 *     description: Met à jour l'item et la quantité d'une commande pour l'utilisateur authentifié.
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: L'identifiant de la commande à mettre à jour.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               item:
 *                 type: string
 *               quantity:
 *                 type: integer
 *     responses:
 *       200:
 *         description: Commande mise à jour avec succès.
 *       400:
 *         description: Champs manquants.
 *       404:
 *         description: Commande non trouvée ou non autorisée.
 *       500:
 *         description: Erreur serveur.
 */
app.put('/orders/:id', authenticateToken, (req, res) => {
  const orderId = req.params.id;
  const { item, quantity } = req.body;
  if (!item || !quantity)
    return res.status(400).json({ error: 'Item et quantity requis' });
  const query = 'UPDATE orders SET item = ?, quantity = ? WHERE id = ? AND user_id = ?';
  db.query(query, [item, quantity, orderId, req.user.id], (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: 'Erreur lors de la mise à jour de la commande' });
    }
    if (results.affectedRows === 0)
      return res.status(404).json({ error: 'Commande non trouvée ou non autorisée' });
    res.json({ message: 'Commande mise à jour avec succès' });
  });
});

/**
 * @swagger
 * /orders/{id}:
 *   delete:
 *     summary: Supprimer une commande
 *     description: Supprime une commande appartenant à l'utilisateur authentifié.
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: L'identifiant de la commande à supprimer.
 *     responses:
 *       200:
 *         description: Commande supprimée avec succès.
 *       404:
 *         description: Commande non trouvée ou non autorisée.
 *       500:
 *         description: Erreur serveur.
 */
app.delete('/orders/:id', authenticateToken, (req, res) => {
  const orderId = req.params.id;
  const query = 'DELETE FROM orders WHERE id = ? AND user_id = ?';
  db.query(query, [orderId, req.user.id], (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: 'Erreur lors de la suppression de la commande' });
    }
    if (results.affectedRows === 0)
      return res.status(404).json({ error: 'Commande non trouvée ou non autorisée' });
    res.json({ message: 'Commande supprimée avec succès' });
  });
});

app.listen(port, () => {
  console.log(`Serveur démarré sur le port ${port}`);
});
