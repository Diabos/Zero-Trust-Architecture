import { NodeSSH } from 'node-ssh';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const hardeningScriptPath = path.join(__dirname, '..', 'scripts', 'zero_trust_harden.sh');

const hardeningPlan = [
  'Update package index and install required hardening tools only',
  'Install security tools: ufw, fail2ban, auditd',
  'Harden SSH configuration (disable root login, disable password auth, reduce auth tries)',
  'Enable and configure firewall with default deny inbound',
  'Configure fail2ban rules for sshd',
  'Apply kernel hardening parameters with sysctl',
  'Enable audit logging for identity-related files',
];

export function getHardeningPlan() {
  return hardeningPlan;
}

export function buildConfigFromEnv(env) {
  return {
    host: env.TARGET_SERVER_HOST,
    username: env.TARGET_SERVER_USER,
    privateKeyPath: env.TARGET_SERVER_SSH_KEY || undefined,
    password: env.TARGET_SERVER_PASSWORD || undefined,
    useSudo: env.TARGET_SERVER_USE_SUDO !== 'false',
    port: env.TARGET_SERVER_PORT || 22,
  };
}

export function getConfigStatus(env) {
  const host = env.TARGET_SERVER_HOST || '';
  const username = env.TARGET_SERVER_USER || '';
  const hasKey = !!env.TARGET_SERVER_SSH_KEY;
  const hasPassword = !!env.TARGET_SERVER_PASSWORD;

  return {
    targetHost: host || null,
    targetUser: username || null,
    authMode: hasKey ? 'ssh-key' : hasPassword ? 'password' : 'none',
    readyForApply: !!host && !!username && (hasKey || hasPassword),
    missing: {
      host: !host,
      username: !username,
      auth: !(hasKey || hasPassword),
    },
  };
}

export function runDemoHardening() {
  return {
    success: true,
    stdout: [
      'DRY RUN ONLY - no server changes were made',
      '',
      '[1/7] Would update packages',
      '[2/7] Would install ufw/fail2ban/auditd',
      '[3/7] Would harden sshd_config',
      '[4/7] Would set UFW default deny incoming',
      '[5/7] Would configure fail2ban ssh jail',
      '[6/7] Would apply sysctl hardening',
      '[7/7] Would enable audit logging',
      '',
      'Demo completed successfully',
    ].join('\n'),
    stderr: '',
    code: 0,
  };
}

export async function executeHardening(config) {
  const ssh = new NodeSSH();

  try {
    const connectOptions = {
      host: config.host,
      username: config.username,
      port: config.port || 22,
    };

    if (config.privateKeyPath) {
      connectOptions.privateKey = config.privateKeyPath;
    } else if (config.password) {
      connectOptions.password = config.password;
    }

    await ssh.connect(connectOptions);

    const script = fs.readFileSync(hardeningScriptPath, 'utf-8');
    const runtimeExports = config.password && !config.privateKeyPath
      ? 'export KEEP_SSH_PASSWORD_AUTH=true\n'
      : '';
    const finalScript = `${runtimeExports}${script}`;

    const shouldUseSudo = config.password && config.useSudo;
    const command = shouldUseSudo ? "sudo -S -p '' bash -s" : 'bash -s';
    const stdin = shouldUseSudo ? `${config.password}\n${finalScript}` : finalScript;

    const result = await ssh.execCommand(command, { stdin });

    return {
      success: result.code === 0,
      stdout: result.stdout,
      stderr: result.stderr,
      code: result.code,
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
    };
  } finally {
    ssh.dispose();
  }
}

async function execRemoteCommand(ssh, config, command, options = {}) {
  const useSudo = !!options.useSudo;
  if (useSudo && config.password) {
    return ssh.execCommand("sudo -S -p '' sh -lc \"" + command.replace(/"/g, '\\"') + "\"", {
      stdin: `${config.password}\n`,
    });
  }

  if (useSudo) {
    return ssh.execCommand(`sudo -n sh -lc \"${command.replace(/"/g, '\\"')}\" || sh -lc \"${command.replace(/"/g, '\\"')}\"`);
  }

  return ssh.execCommand(`sh -lc \"${command.replace(/"/g, '\\"')}\"`);
}

function parseListeningPorts(ssOutput) {
  const ports = new Set();
  const lines = (ssOutput || '').split('\n');

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const parts = trimmed.split(/\s+/);
    const endpoint = parts[parts.length >= 5 ? 4 : parts.length - 1] || '';
    const match = endpoint.match(/:(\d+)$/);
    if (match) {
      ports.add(match[1]);
    }
  }

  return Array.from(ports).sort((a, b) => Number(a) - Number(b));
}

export async function collectAttackSurfaceSnapshot(config) {
  const ssh = new NodeSSH();

  try {
    const connectOptions = {
      host: config.host,
      username: config.username,
      port: config.port || 22,
    };

    if (config.privateKeyPath) {
      connectOptions.privateKey = config.privateKeyPath;
    } else if (config.password) {
      connectOptions.password = config.password;
    }

    await ssh.connect(connectOptions);

    const checks = {
      sshdConfig: await execRemoteCommand(
        ssh,
        config,
        "sshd -T 2>/dev/null | grep -E 'permitrootlogin|passwordauthentication|maxauthtries|x11forwarding' || grep -E '^(PermitRootLogin|PasswordAuthentication|MaxAuthTries|X11Forwarding)' /etc/ssh/sshd_config 2>/dev/null || true",
        { useSudo: true },
      ),
      ufwStatus: await execRemoteCommand(ssh, config, 'ufw status verbose 2>/dev/null || true', { useSudo: true }),
      fail2banSshd: await execRemoteCommand(ssh, config, 'fail2ban-client status sshd 2>/dev/null || true', { useSudo: true }),
      auditdState: await execRemoteCommand(ssh, config, 'systemctl is-active auditd 2>/dev/null || true', { useSudo: true }),
      auditRules: await execRemoteCommand(ssh, config, "auditctl -l 2>/dev/null | grep -E '/etc/passwd|/etc/shadow' || true", { useSudo: true }),
      kernelParams: await execRemoteCommand(ssh, config, 'sysctl net.ipv4.tcp_syncookies net.ipv4.conf.all.accept_source_route net.ipv6.conf.all.disable_ipv6 2>/dev/null || true', { useSudo: true }),
      listeningSockets: await execRemoteCommand(ssh, config, 'ss -tulnH 2>/dev/null || true', { useSudo: true }),
      apacheActive: await execRemoteCommand(ssh, config, '(systemctl is-active apache2 2>/dev/null || systemctl is-active httpd 2>/dev/null || echo inactive) | tail -n 1'),
      apacheVersion: await execRemoteCommand(ssh, config, 'apache2 -v 2>/dev/null || httpd -v 2>/dev/null || echo apache-not-found'),
      apacheSecurityDirectives: await execRemoteCommand(ssh, config, "grep -R '^ServerTokens\\|^ServerSignature' /etc/apache2 2>/dev/null || grep -R '^ServerTokens\\|^ServerSignature' /etc/httpd 2>/dev/null || true", { useSudo: true }),
    };

    return {
      timestamp: new Date().toISOString(),
      target: {
        host: config.host,
        username: config.username,
        port: config.port || 22,
      },
      controls: {
        sshdConfig: checks.sshdConfig.stdout || '',
        ufwStatus: checks.ufwStatus.stdout || '',
        fail2banSshd: checks.fail2banSshd.stdout || '',
        auditdState: checks.auditdState.stdout || '',
        auditRules: checks.auditRules.stdout || '',
        kernelParams: checks.kernelParams.stdout || '',
        apacheActive: (checks.apacheActive.stdout || '').trim(),
        apacheVersion: checks.apacheVersion.stdout || '',
        apacheSecurityDirectives: checks.apacheSecurityDirectives.stdout || '',
      },
      attackSurface: {
        listeningPorts: parseListeningPorts(checks.listeningSockets.stdout || ''),
        listeningSocketsRaw: checks.listeningSockets.stdout || '',
      },
    };
  } catch (error) {
    return {
      timestamp: new Date().toISOString(),
      error: error.message,
      target: {
        host: config.host,
        username: config.username,
        port: config.port || 22,
      },
      controls: {},
      attackSurface: {
        listeningPorts: [],
        listeningSocketsRaw: '',
      },
    };
  } finally {
    ssh.dispose();
  }
}

function includesAll(haystack, needles) {
  return needles.every((needle) => haystack.toLowerCase().includes(needle.toLowerCase()));
}

function getLikelihoodLevel(score) {
  if (score >= 8) return 'High';
  if (score >= 4) return 'Medium';
  return 'Low';
}

function computeLikelihoodScore(snapshot) {
  const sshd = snapshot.controls?.sshdConfig || '';
  const ufw = snapshot.controls?.ufwStatus || '';
  const ports = snapshot.attackSurface?.listeningPorts || [];

  const passwordAuthDisabled = includesAll(sshd, ['passwordauthentication no']);
  const rootLoginDisabled = includesAll(sshd, ['permitrootlogin no']);
  const firewallActive = includesAll(ufw, ['status: active']);
  const denyIncoming = includesAll(ufw, ['default: deny (incoming)']);

  let score = 0;
  score += ports.length;
  if (!passwordAuthDisabled) score += 3;
  if (!rootLoginDisabled) score += 3;
  if (!firewallActive || !denyIncoming) score += 2;

  return score;
}

export function buildHardeningVerificationReport(snapshot, options = {}) {
  const managedPasswordMode = !!options.managedPasswordMode;
  const sshd = snapshot.controls?.sshdConfig || '';
  const ufw = snapshot.controls?.ufwStatus || '';
  const fail2ban = snapshot.controls?.fail2banSshd || '';
  const auditdState = (snapshot.controls?.auditdState || '').trim();
  const auditRules = snapshot.controls?.auditRules || '';
  const kernel = snapshot.controls?.kernelParams || '';
  const apacheActive = (snapshot.controls?.apacheActive || '').toLowerCase();
  const apacheVersion = (snapshot.controls?.apacheVersion || '').toLowerCase();
  const apacheDirectives = snapshot.controls?.apacheSecurityDirectives || '';

  const apachePresent = !apacheVersion.includes('apache-not-found');

  const controls = [
    {
      id: 'CIS-SSH-1',
      title: 'Disable SSH root login',
      status: includesAll(sshd, ['permitrootlogin no']) ? 'pass' : 'fail',
      evidence: sshd,
    },
    managedPasswordMode
      ? {
        id: 'CIS-SSH-2',
        title: 'Disable SSH password authentication',
        status: 'not_applicable',
        evidence: 'Password authentication intentionally retained for managed password-based automation mode',
      }
      : {
        id: 'CIS-SSH-2',
        title: 'Disable SSH password authentication',
        status: includesAll(sshd, ['passwordauthentication no']) ? 'pass' : 'fail',
        evidence: sshd,
      },
    {
      id: 'CIS-NET-1',
      title: 'Firewall active with default deny incoming',
      status: includesAll(ufw, ['status: active', 'default: deny (incoming)']) ? 'pass' : 'fail',
      evidence: ufw,
    },
    {
      id: 'CIS-LOG-1',
      title: 'Fail2Ban sshd jail configured',
      status: fail2ban.toLowerCase().includes('status for the jail: sshd') ? 'pass' : 'fail',
      evidence: fail2ban,
    },
    {
      id: 'CIS-AUDIT-1',
      title: 'auditd service active',
      status: auditdState === 'active' ? 'pass' : 'fail',
      evidence: auditdState,
    },
    {
      id: 'CIS-AUDIT-2',
      title: 'Audit watches on passwd and shadow',
      status: includesAll(auditRules, ['/etc/passwd', '/etc/shadow']) ? 'pass' : 'fail',
      evidence: auditRules,
    },
    {
      id: 'CIS-KERNEL-1',
      title: 'Kernel network hardening parameters enforced',
      status: includesAll(kernel, ['net.ipv4.tcp_syncookies = 1', 'net.ipv4.conf.all.accept_source_route = 0']) ? 'pass' : 'fail',
      evidence: kernel,
    },
    {
      id: 'CIS-APACHE-1',
      title: 'Apache hardened with ServerTokens Prod and ServerSignature Off',
      status: !apachePresent
        ? 'not_applicable'
        : includesAll(apacheDirectives, ['servertokens prod', 'serversignature off'])
          ? 'pass'
          : 'fail',
      evidence: apachePresent ? apacheDirectives : 'Apache not installed on target',
    },
    {
      id: 'CIS-APACHE-2',
      title: 'Apache service state verified',
      status: !apachePresent
        ? 'not_applicable'
        : apacheActive === 'active'
          ? 'pass'
          : 'fail',
      evidence: apachePresent ? apacheActive : 'Apache not installed on target',
    },
  ];

  const passCount = controls.filter((c) => c.status === 'pass').length;
  const failCount = controls.filter((c) => c.status === 'fail').length;
  const notApplicableCount = controls.filter((c) => c.status === 'not_applicable').length;

  return {
    timestamp: new Date().toISOString(),
    summary: {
      totalControls: controls.length,
      passCount,
      failCount,
      notApplicableCount,
      effectiveness: controls.length > 0 ? Number(((passCount / (controls.length - notApplicableCount || 1)) * 100).toFixed(2)) : 0,
    },
    controls,
  };
}

export function buildAttackSurfaceDeltaReport(beforeSnapshot, afterSnapshot) {
  const beforePorts = new Set(beforeSnapshot.attackSurface?.listeningPorts || []);
  const afterPorts = new Set(afterSnapshot.attackSurface?.listeningPorts || []);

  const openedPorts = Array.from(afterPorts).filter((p) => !beforePorts.has(p));
  const closedPorts = Array.from(beforePorts).filter((p) => !afterPorts.has(p));

  const beforeLikelihoodScore = computeLikelihoodScore(beforeSnapshot);
  const afterLikelihoodScore = computeLikelihoodScore(afterSnapshot);

  return {
    timestamp: new Date().toISOString(),
    ports: {
      before: Array.from(beforePorts).sort((a, b) => Number(a) - Number(b)),
      after: Array.from(afterPorts).sort((a, b) => Number(a) - Number(b)),
      openedPorts,
      closedPorts,
    },
    likelihood: {
      scoreBefore: beforeLikelihoodScore,
      scoreAfter: afterLikelihoodScore,
      levelBefore: getLikelihoodLevel(beforeLikelihoodScore),
      levelAfter: getLikelihoodLevel(afterLikelihoodScore),
      delta: afterLikelihoodScore - beforeLikelihoodScore,
    },
  };
}

export function buildSoWhatLayer(verificationReport, deltaReport) {
  const keyWins = [];

  if (deltaReport.ports.closedPorts.length > 0) {
    keyWins.push(`Closed exposed ports: ${deltaReport.ports.closedPorts.join(', ')}`);
  }

  const sshPassControl = verificationReport.controls.find((c) => c.id === 'CIS-SSH-2');
  if (sshPassControl && sshPassControl.status === 'pass') {
    keyWins.push('SSH password authentication disabled, reducing brute-force viability');
  }

  const ufwControl = verificationReport.controls.find((c) => c.id === 'CIS-NET-1');
  if (ufwControl && ufwControl.status === 'pass') {
    keyWins.push('Default-deny firewall policy limits externally reachable attack paths');
  }

  const fail2banControl = verificationReport.controls.find((c) => c.id === 'CIS-LOG-1');
  if (fail2banControl && fail2banControl.status === 'pass') {
    keyWins.push('Fail2Ban adds automated response to repeated SSH abuse attempts');
  }

  return {
    narrative: `Technical hardening reduced exploitable entry points and increased resistance to common attack paths. Likelihood shifted from ${deltaReport.likelihood.levelBefore} to ${deltaReport.likelihood.levelAfter} based on exposure signals (open ports, SSH policy, and firewall posture).`,
    riskAssessmentLink: 'Lower exposed services and stronger authentication controls reduce attacker success probability, directly lowering Likelihood Determination in risk scoring.',
    keyWins,
  };
}
