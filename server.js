const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const PORT = 8001;
const BACKEND_PORT = 8000;

// Start the Python/FastAPI backend automatically
console.log('Starting Prism Mail backend...');
const pythonExe = path.join(__dirname, 'venv', 'Scripts', 'python.exe');
const appPy = path.join(__dirname, 'app.py');
const backend = spawn(pythonExe, [appPy], {
  stdio: ['ignore', 'pipe', 'pipe'],
});

backend.stdout.on('data', (data) => {
  process.stdout.write(`[backend] ${data}`);
});

backend.stderr.on('data', (data) => {
  process.stderr.write(`[backend] ${data}`);
});

backend.on('error', (err) => {
  console.error(`[backend] Failed to start: ${err.message}`);
  console.error('[backend] Make sure Python dependencies are installed (pip install -r requirements.txt)');
});

backend.on('exit', (code) => {
  console.log(`[backend] Process exited with code ${code}`);
});

// Kill backend when the Node server stops
process.on('exit', () => { backend.kill(); });
process.on('SIGINT', () => { backend.kill(); process.exit(); });
process.on('SIGTERM', () => { backend.kill(); process.exit(); });

// Static file server for the frontend
http.createServer((req, res) => {
  let filePath = req.url === '/' ? '/prism.html' : req.url;
  // Strip query string (e.g. ?error=... from OAuth callback redirect) to avoid 404
  filePath = filePath.split('?')[0].split('#')[0];
  filePath = path.join(__dirname, filePath);
  // Prevent path traversal: only serve files inside the app directory
  if (filePath !== __dirname && !filePath.startsWith(__dirname + path.sep)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('Forbidden');
    return;
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      // If the file has a query string (error redirect), try serving prism.html instead
      if (req.url.includes('?') || req.url.includes('#')) {
        fs.readFile(path.join(__dirname, 'prism.html'), (err2, data2) => {
          if (err2) {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('Not found');
            return;
          }
          res.writeHead(200, {
            'Content-Type': 'text/html',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'no-store'
          });
          res.end(data2);
        });
        return;
      }
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
      return;
    }
    const ext = path.extname(filePath);
    const mimeTypes = {
      '.html': 'text/html',
      '.js': 'application/javascript',
      '.css': 'text/css',
      '.png': 'image/png',
      '.png': 'image/png',
      '.jpg': 'image/jpeg',
      '.svg': 'image/svg+xml'
    };
    res.writeHead(200, {
      'Content-Type': mimeTypes[ext] || 'text/plain',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-store'
    });
    res.end(data);
  });
}).listen(PORT, () => {
  console.log(`Prism Mail app running at http://localhost:${PORT}/prism.html`);
  console.log(`Backend starting at http://localhost:${BACKEND_PORT}`);
});
