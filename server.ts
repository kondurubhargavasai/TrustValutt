import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { initDatabase } from './src/database.ts';
import { router } from './src/routes.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const isProd = process.env.NODE_ENV === 'production';

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Initialize SQLite/Zero-Trust database schemas & pre-seeded audit blocks
initDatabase();

// Mount TrustVault API router
app.use('/api', router);

async function startServer() {
  if (!isProd) {
    // In development mode, mount Vite middleware to serve hot module frontend
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    // In production, serve the compiled Vite static assets from dist
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`====================================================`);
    console.log(` TrustVault Zero-Trust Security Platform active`);
    console.log(` Server listening on: http://0.0.0.0:${PORT}`);
    console.log(` API Endpoint: http://0.0.0.0:${PORT}/api/stats`);
    console.log(`====================================================`);
  });
}

startServer().catch((err) => {
  console.error('[TrustVault] Failed to start server:', err);
  process.exit(1);
});
