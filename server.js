import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

try {
  const { initDatabase } = await import('./src/database.ts');
  const { router } = await import('./src/routes.ts');

  const app = express();
  const PORT = Number(process.env.PORT) || 3000;

  app.use(cors());
  app.use(express.json({ limit: '50mb' }));
  app.use(express.urlencoded({ extended: true, limit: '50mb' }));

  initDatabase();
  app.use('/api', router);

  const distPath = path.join(__dirname, 'dist');
  app.use(express.static(distPath));
  app.get('*', (req, res) => {
    res.sendFile(path.join(distPath, 'index.html'));
  });

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`TrustVault Server running on http://0.0.0.0:${PORT}`);
  });
} catch (err) {
  // If running via plain node without TypeScript loader, delegate to tsx
  const { spawn } = await import('child_process');
  const child = spawn('npx', ['tsx', 'server.ts'], { stdio: 'inherit', shell: true });
  child.on('exit', (code) => process.exit(code || 0));
}
