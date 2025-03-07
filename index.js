require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const nodemailer = require('nodemailer');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const winston = require('winston');
const morgan = require('morgan');

const app = express();
const port = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY;
const saltRounds = 10;
const cors = require('cors');

app.use(cors({
  origin: '*', // Autorise toutes les origines (tu peux restreindre à ton frontend)
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Authorization', 'Content-Type']
}));


// --- Configuration du système de log avec Winston et Morgan ---
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(info => `${info.timestamp} ${info.level.toUpperCase()}: ${info.message}`)
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/app.log' })
  ]
});

app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));

// --- Middleware & configuration Express ---
app.use(express.static('public'));
app.use(bodyParser.json());

const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

// --- Configuration de Nodemailer ---
const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  }
});

// --- Chargement du template d'email depuis un fichier externe ---
const templatePath = path.join(__dirname, 'templates', 'verificationEmail.html');
let emailTemplate;
try {
  emailTemplate = fs.readFileSync(templatePath, 'utf8');
  logger.info('Template email chargé avec succès.');
} catch (error) {
  logger.error('Erreur lors du chargement du template email: ' + error.message);
  process.exit(1);
}

// --- Configuration Swagger ---
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'API Documentation',
      version: '1.0.0',
      description: 'Documentation de l\'API'
    },
    servers: [{ url: `https://api.esgi.local` }],
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
  apis: ['./index.js']
};
const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// --- Middleware de vérification du token JWT ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    logger.error('Token manquant dans la requête.');
    return res.status(401).json({ error: 'Token manquant' });
  }
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      logger.error('Token invalide ou expiré: ' + err.message);
      return res.status(403).json({ error: 'Token invalide ou expiré' });
    }
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
 */
app.get('/health', (req, res) => {
  db.query('SELECT 1 AS result', (dbErr, dbResults) => {
    const dbStatus = !dbErr;
    if (dbErr) {
      logger.error('[Health Check] - Erreur BDD: ' + dbErr.message);
    }
    transporter.verify((smtpErr, success) => {
      const smtpStatus = !smtpErr;
      if (smtpErr) {
        logger.error('[Health Check] - Erreur SMTP: ' + smtpErr.message);
      }
      logger.info(`[Health Check] - BDD: ${dbStatus ? 'OK' : 'ERREUR'}, SMTP: ${smtpStatus ? 'OK' : 'ERREUR'} - ${new Date().toISOString()}`);
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
 */
app.post('/register', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    logger.error('Email et password requis pour l’inscription.');
    return res.status(400).json({ error: 'Email et password requis' });
  }
  bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
    if (err) {
      logger.error('Erreur lors du hash du mot de passe: ' + err.message);
      return res.status(500).json({ error: 'Erreur lors du hash du mot de passe' });
    }
    const query = 'INSERT INTO users (username, password, role, verified) VALUES (?, ?, ?, ?)';
    db.query(query, [email, hashedPassword, 'user', false], (error, results) => {
      if (error) {
        logger.error('Erreur lors de la création de l’utilisateur: ' + error.message);
        return res.status(500).json({ error: 'Erreur lors de la création de l\'utilisateur' });
      }
      const userId = results.insertId;
      // Génération d'un token pour la validation de l'email valable 10 minutes
      const emailToken = jwt.sign({ id: userId, email: email }, SECRET_KEY, { expiresIn: '10m' });
      const verificationUrl = `https://api.esgi.local/verify-email?token=${emailToken}`;
      const emailHtml = emailTemplate.replace(/{{url}}/g, verificationUrl);
      transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Validation de votre email',
        html: emailHtml
      }, (err, info) => {
        if (err) {
          logger.error('Erreur lors de l’envoi de l’email de validation: ' + err.message);
          return res.status(500).json({ error: 'Erreur lors de l\'envoi de l\'email de validation' });
        }
        logger.info(`Email de validation envoyé à ${email}`);
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
 */
app.get('/verify-email', (req, res) => {
  const { token } = req.query;
  if (!token) {
    logger.error('Token de vérification manquant.');
    return res.status(400).json({ error: 'Token manquant' });
  }
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      logger.error('Token invalide ou expiré: ' + err.message);
      return res.status(400).json({ error: 'Token invalide ou expiré' });
    }
    const { id } = decoded;
    const query = 'UPDATE users SET verified = ? WHERE id = ?';
    db.query(query, [true, id], (error, results) => {
      if (error) {
        logger.error('Erreur lors de la vérification de l’email: ' + error.message);
        return res.status(500).json({ error: 'Erreur lors de la vérification de l\'email' });
      }
      logger.info(`Email vérifié pour l’utilisateur id ${id}`);
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
 */
app.post('/authenticate', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    logger.error('Email et password requis pour l’authentification.');
    return res.status(400).json({ error: 'Email et password requis' });
  }
  const query = 'SELECT * FROM users WHERE username = ?';
  db.query(query, [email], (error, results) => {
    if (error) {
      logger.error('Erreur serveur lors de l’authentification: ' + error.message);
      return res.status(500).json({ error: 'Erreur serveur' });
    }
    if (results.length === 0) {
      logger.error(`Identifiants incorrects pour l’email: ${email}`);
      return res.status(401).json({ error: 'Identifiants incorrects' });
    }
    const user = results[0];
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        logger.error('Erreur lors de la comparaison des mots de passe: ' + err.message);
        return res.status(500).json({ error: 'Erreur lors de la vérification du mot de passe' });
      }
      if (!isMatch) {
        logger.error(`Mot de passe incorrect pour l’email: ${email}`);
        return res.status(401).json({ error: 'Identifiants incorrects' });
      }
      if (!user.verified) {
        logger.error(`Email non vérifié pour l’email: ${email}`);
        return res.status(403).json({ error: 'Email non vérifié. Veuillez vérifier votre email.' });
      }
      const authToken = jwt.sign({ id: user.id, email: user.username, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
      logger.info(`Utilisateur authentifié: ${email}`);
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
  logger.info(`Serveur démarré sur le port ${port}`);
});
