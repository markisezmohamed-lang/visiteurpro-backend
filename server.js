require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const helmet = require('helmet');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const XLSX = require('xlsx');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = process.env.UPLOAD_DIR || 'uploads';

// ─── Dossier uploads ────────────────────────────────────────────────
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ─── Base de données ─────────────────────────────────────────────────
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// ─── Middlewares globaux ─────────────────────────────────────────────
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PATCH', 'DELETE'] }));
app.use(express.json({ limit: '10mb' }));
app.use('/uploads', express.static(UPLOAD_DIR));

// ─── Rate limiting (sécurité anti-brute-force) ───────────────────────
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: 'Trop de tentatives, réessayez dans 15 minutes.' } });
const apiLimiter  = rateLimit({ windowMs: 60 * 1000, max: 120 });
app.use('/api/', apiLimiter);
app.use('/api/auth/login', authLimiter);

// ─── Upload photos (multer) ──────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique + path.extname(file.originalname));
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB max
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|webp/;
    cb(null, allowed.test(file.mimetype));
  }
});

// ─── Middleware d'authentification JWT ──────────────────────────────
function auth(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ error: 'Token manquant' });
  const token = header.split(' ')[1];
  try {
    req.agent = jwt.verify(token, process.env.JWT_SECRET || 'secret_dev');
    next();
  } catch {
    res.status(401).json({ error: 'Token invalide ou expiré' });
  }
}

// ═══════════════════════════════════════════════════════════════════
// ROUTES AUTHENTIFICATION
// ═══════════════════════════════════════════════════════════════════

// POST /api/auth/login — connexion agent
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Champs manquants' });
  try {
    const result = await pool.query('SELECT * FROM agents WHERE username = $1', [username]);
    if (!result.rows.length) return res.status(401).json({ error: 'Identifiants incorrects' });
    const agent = result.rows[0];
    const valid = await bcrypt.compare(password, agent.password);
    if (!valid) return res.status(401).json({ error: 'Identifiants incorrects' });
    const token = jwt.sign(
      { id: agent.id, username: agent.username, role: agent.role },
      process.env.JWT_SECRET || 'secret_dev',
      { expiresIn: '8h' }
    );
    res.json({ token, agent: { id: agent.id, username: agent.username, nom: agent.nom, role: agent.role } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════
// ROUTES VISITEURS
// ═══════════════════════════════════════════════════════════════════

// POST /api/visitors — enregistrer un nouveau visiteur
app.post('/api/visitors', async (req, res) => {
  const { id_number, nom, prenom, dob, lieu, telephone, email, notes } = req.body;
  if (!id_number || !nom || !prenom) return res.status(400).json({ error: 'id_number, nom et prenom sont obligatoires' });
  try {
    const result = await pool.query(
      `INSERT INTO visitors (id_number, nom, prenom, dob, lieu, telephone, email, notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [id_number, nom, prenom, dob || null, lieu, telephone, email, notes]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/visitors/:id/photo — uploader la photo d'identité
app.post('/api/visitors/:id/photo', auth, upload.single('photo'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Fichier image requis (jpeg/png/webp, max 5MB)' });
  const photoUrl = `/uploads/${req.file.filename}`;
  try {
    const result = await pool.query(
      'UPDATE visitors SET photo_url = $1 WHERE id = $2 RETURNING *',
      [photoUrl, req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Visiteur introuvable' });
    res.json({ photo_url: photoUrl, visitor: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/visitors/:id/photo-base64 — photo depuis webcam (base64)
app.post('/api/visitors/:id/photo-base64', auth, async (req, res) => {
  const { image } = req.body; // "data:image/jpeg;base64,..."
  if (!image) return res.status(400).json({ error: 'Image base64 manquante' });
  try {
    const base64Data = image.replace(/^data:image\/\w+;base64,/, '');
    const filename = `${Date.now()}-webcam.jpg`;
    fs.writeFileSync(path.join(UPLOAD_DIR, filename), Buffer.from(base64Data, 'base64'));
    const photoUrl = `/uploads/${filename}`;
    const result = await pool.query(
      'UPDATE visitors SET photo_url = $1 WHERE id = $2 RETURNING *',
      [photoUrl, req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Visiteur introuvable' });
    res.json({ photo_url: photoUrl, visitor: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/visitors — liste des visiteurs (agent authentifié)
app.get('/api/visitors', auth, async (req, res) => {
  const { date, statut, search } = req.query;
  let query = 'SELECT * FROM visitors WHERE 1=1';
  const params = [];
  if (date) {
    params.push(date);
    query += ` AND DATE(heure_entree) = $${params.length}`;
  }
  if (statut) {
    params.push(statut);
    query += ` AND statut = $${params.length}`;
  }
  if (search) {
    params.push(`%${search}%`);
    query += ` AND (nom ILIKE $${params.length} OR prenom ILIKE $${params.length} OR id_number ILIKE $${params.length})`;
  }
  query += ' ORDER BY heure_entree DESC';
  try {
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/visitors/:id/statut — marquer entrée/sortie
app.patch('/api/visitors/:id/statut', auth, async (req, res) => {
  const { statut } = req.body;
  if (!['in', 'out'].includes(statut)) return res.status(400).json({ error: 'statut doit être "in" ou "out"' });
  try {
    const result = await pool.query(
      `UPDATE visitors SET statut = $1, heure_sortie = $2 WHERE id = $3 RETURNING *`,
      [statut, statut === 'out' ? new Date() : null, req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Visiteur introuvable' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/visitors/export — export Excel
app.get('/api/visitors/export', auth, async (req, res) => {
  const { date } = req.query;
  let query = 'SELECT id_number, nom, prenom, dob, lieu, telephone, email, heure_entree, heure_sortie, statut, notes FROM visitors';
  const params = [];
  if (date) { params.push(date); query += ` WHERE DATE(heure_entree) = $1`; }
  query += ' ORDER BY heure_entree DESC';
  try {
    const result = await pool.query(query, params);
    const data = result.rows.map(v => ({
      'N° ID':           v.id_number,
      'Nom':             v.nom,
      'Prénom':          v.prenom,
      'Date naissance':  v.dob ? new Date(v.dob).toLocaleDateString('fr-FR') : '',
      'Lieu naissance':  v.lieu || '',
      'Téléphone':       v.telephone || '',
      'Email':           v.email || '',
      'Heure entrée':    v.heure_entree ? new Date(v.heure_entree).toLocaleString('fr-FR') : '',
      'Heure sortie':    v.heure_sortie ? new Date(v.heure_sortie).toLocaleString('fr-FR') : '',
      'Statut':          v.statut === 'in' ? 'Présent' : 'Sorti',
      'Notes':           v.notes || ''
    }));
    const ws = XLSX.utils.json_to_sheet(data);
    ws['!cols'] = [12,15,15,14,14,14,24,16,16,10,20].map(w => ({ wch: w }));
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Visiteurs');
    const buffer = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
    const filename = `visiteurs_${date || new Date().toISOString().slice(0,10)}.xlsx`;
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.send(buffer);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/visitors/:id — supprimer un visiteur (admin seulement)
app.delete('/api/visitors/:id', auth, async (req, res) => {
  if (req.agent.role !== 'admin') return res.status(403).json({ error: 'Réservé à l\'administrateur' });
  try {
    await pool.query('DELETE FROM visitors WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Santé du serveur ────────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ status: 'ok', time: new Date() }));

// ─── Démarrage ───────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`✅ VisiteurPro API démarré sur http://localhost:${PORT}`));
