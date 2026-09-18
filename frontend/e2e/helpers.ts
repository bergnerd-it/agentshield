import fs from 'fs';
import os from 'os';
import path from 'path';

export function getAdminTokenForTest(): string {
  const candidates = [
    path.join(os.homedir(), 'Library', 'Application Support', 'AgentShield', 'admin.token'),
    path.join(os.homedir(), '.agentshield', 'admin.token'),
    path.join(os.homedir(), '.local', 'share', 'agentshield', 'admin.token'),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      const token = fs.readFileSync(candidate, 'utf-8').trim();
      if (token) return token;
    }
  }
  return '';
}

export function getProxyTokenForTest(): string {
  const candidates = [
    path.join(os.homedir(), 'Library', 'Application Support', 'AgentShield', 'proxy.token'),
    path.join(os.homedir(), '.agentshield', 'proxy.token'),
    path.join(os.homedir(), '.local', 'share', 'agentshield', 'proxy.token'),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      const token = fs.readFileSync(candidate, 'utf-8').trim();
      if (token) return token;
    }
  }
  return '';
}
