import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import { initDatabase } from './src/database.js';
import { router } from './src/routes.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Initialize SQLite schema and seed users
initDatabase();

// Mount API routes
app.use('/api', router);

// Serve frontend static UI
app.use(express.static(path.join(__dirname, 'public')));

// Fallback to SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(` TrustVault Security Platform running on port ${PORT}`);
  console.log(` Access Dashboard at: http://localhost:${PORT}`);
  console.log(`====================================================`);
});