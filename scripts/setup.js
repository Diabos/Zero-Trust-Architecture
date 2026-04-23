#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.join(__dirname, '..');
const envPath = path.join(rootDir, '.env');
const envExamplePath = path.join(rootDir, '.env.example');

if (!fs.existsSync(envExamplePath)) {
  console.error('Missing .env.example file. Cannot bootstrap configuration.');
  process.exit(1);
}

if (!fs.existsSync(envPath)) {
  fs.copyFileSync(envExamplePath, envPath);
  console.log('Created .env from .env.example');
} else {
  console.log('.env already exists. No file was overwritten.');
}

console.log('Next steps:');
console.log('1) Edit .env with your target host/user/auth values');
console.log('2) Run: npm run status');
console.log('3) Run: npm run demo');
console.log('4) Run: npm run apply');
