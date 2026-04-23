#!/usr/bin/env node

import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  buildConfigFromEnv,
  getConfigStatus,
  getHardeningPlan,
  runDemoHardening,
  executeHardening,
  collectAttackSurfaceSnapshot,
  buildHardeningVerificationReport,
  buildAttackSurfaceDeltaReport,
  buildSoWhatLayer,
} from '../src/hardening.js';

dotenv.config();

const command = process.argv[2] || 'help';
const flags = new Set(process.argv.slice(3));
const jsonMode = flags.has('--json');
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const reportsDir = path.join(__dirname, '..', 'reports');

function printJson(obj) {
  console.log(JSON.stringify(obj, null, 2));
}

function printSection(title) {
  console.log(`\n=== ${title} ===`);
}

function printKeyValue(key, value) {
  console.log(`${key}: ${value}`);
}

function formatPorts(ports) {
  return ports.length > 0 ? ports.join(', ') : 'none';
}

function summarizeLog(output, maxLines = 14) {
  const lines = (output || '').split('\n').map((line) => line.trimEnd()).filter(Boolean);
  if (lines.length <= maxLines) {
    return lines.join('\n');
  }

  const shown = lines.slice(0, maxLines).join('\n');
  return `${shown}\n... (${lines.length - maxLines} more lines)`;
}

function renderMarkdownReport(report) {
  const lines = [];
  lines.push('# Hardening Verification Report');
  lines.push('');
  lines.push(`- Timestamp: ${report.timestamp}`);
  lines.push(`- Target: ${report.target.host}:${report.target.port} (${report.target.username})`);
  lines.push(`- Hardening Success: ${report.execution.success}`);
  lines.push('');

  lines.push('## Control Effectiveness Summary');
  lines.push('');
  lines.push(`- Total Controls: ${report.verification.summary.totalControls}`);
  lines.push(`- Pass: ${report.verification.summary.passCount}`);
  lines.push(`- Fail: ${report.verification.summary.failCount}`);
  lines.push(`- Not Applicable: ${report.verification.summary.notApplicableCount}`);
  lines.push(`- Effectiveness (%): ${report.verification.summary.effectiveness}`);
  lines.push('');

  lines.push('## Attack Surface Delta');
  lines.push('');
  lines.push(`- Ports Before: ${report.attackSurfaceDelta.ports.before.join(', ') || 'none'}`);
  lines.push(`- Ports After: ${report.attackSurfaceDelta.ports.after.join(', ') || 'none'}`);
  lines.push(`- Newly Opened Ports: ${report.attackSurfaceDelta.ports.openedPorts.join(', ') || 'none'}`);
  lines.push(`- Closed Ports: ${report.attackSurfaceDelta.ports.closedPorts.join(', ') || 'none'}`);
  lines.push(`- Likelihood Before: ${report.attackSurfaceDelta.likelihood.levelBefore} (score ${report.attackSurfaceDelta.likelihood.scoreBefore})`);
  lines.push(`- Likelihood After: ${report.attackSurfaceDelta.likelihood.levelAfter} (score ${report.attackSurfaceDelta.likelihood.scoreAfter})`);
  lines.push('');

  lines.push('## So-What Layer');
  lines.push('');
  lines.push(report.soWhat.narrative);
  lines.push('');
  lines.push(`Risk Link: ${report.soWhat.riskAssessmentLink}`);
  lines.push('');
  if (report.soWhat.keyWins.length > 0) {
    lines.push('Key Wins:');
    for (const win of report.soWhat.keyWins) {
      lines.push(`- ${win}`);
    }
    lines.push('');
  }

  lines.push('## Control-by-Control Results');
  lines.push('');
  for (const control of report.verification.controls) {
    lines.push(`- [${control.status.toUpperCase()}] ${control.id} ${control.title}`);
  }
  lines.push('');

  return lines.join('\n');
}

function saveDeliverables(report) {
  fs.mkdirSync(reportsDir, { recursive: true });
  const stamp = report.timestamp.replace(/[:.]/g, '-');
  const jsonPath = path.join(reportsDir, `hardening-verification-${stamp}.json`);
  const mdPath = path.join(reportsDir, `hardening-verification-${stamp}.md`);

  fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2));
  fs.writeFileSync(mdPath, renderMarkdownReport(report));

  return { jsonPath, mdPath };
}

async function run() {
  if (command === 'plan') {
    const plan = getHardeningPlan();
    if (jsonMode) {
      printJson({
        project: 'AZTIH Hardening Runner',
        plan,
      });
      return;
    }

    printSection('Hardening Plan');
    printKeyValue('Project', 'AZTIH Hardening Runner');
    for (let i = 0; i < plan.length; i += 1) {
      console.log(`${i + 1}. ${plan[i]}`);
    }
    return;
  }

  if (command === 'status') {
    const status = getConfigStatus(process.env);
    if (jsonMode) {
      printJson(status);
      return;
    }

    printSection('Configuration Status');
    printKeyValue('Target Host', status.targetHost || 'not set');
    printKeyValue('Target User', status.targetUser || 'not set');
    printKeyValue('Authentication Mode', status.authMode);
    printKeyValue('Ready For Apply', status.readyForApply ? 'yes' : 'no');

    if (!status.readyForApply) {
      printSection('Missing Requirements');
      if (status.missing.host) console.log('- TARGET_SERVER_HOST');
      if (status.missing.username) console.log('- TARGET_SERVER_USER');
      if (status.missing.auth) console.log('- TARGET_SERVER_PASSWORD or TARGET_SERVER_SSH_KEY');
    }
    return;
  }

  if (command === 'demo') {
    const demo = runDemoHardening();
    if (jsonMode) {
      printJson(demo);
      return;
    }

    printSection('Demo Run Result');
    printKeyValue('Success', demo.success ? 'yes' : 'no');
    printKeyValue('Exit Code', demo.code);
    printSection('Log Preview');
    console.log(summarizeLog(demo.stdout));
    return;
  }

  if (command === 'apply') {
    const status = getConfigStatus(process.env);
    if (!status.readyForApply) {
      printJson({
        success: false,
        error: 'Configuration incomplete for apply mode',
        status,
      });
      process.exitCode = 1;
      return;
    }

    const config = buildConfigFromEnv(process.env);
    const preSnapshot = await collectAttackSurfaceSnapshot(config);
    const executionResult = await executeHardening(config);
    const postSnapshot = await collectAttackSurfaceSnapshot(config);
    const verification = buildHardeningVerificationReport(postSnapshot, {
      managedPasswordMode: !!(config.password && !config.privateKeyPath),
    });
    const attackSurfaceDelta = buildAttackSurfaceDeltaReport(preSnapshot, postSnapshot);
    const soWhat = buildSoWhatLayer(verification, attackSurfaceDelta);

    const report = {
      timestamp: new Date().toISOString(),
      target: {
        host: config.host,
        username: config.username,
        port: config.port || 22,
      },
      execution: executionResult,
      preSnapshot,
      postSnapshot,
      verification,
      attackSurfaceDelta,
      soWhat,
    };

    const files = saveDeliverables(report);

    const payload = {
      success: executionResult.success,
      execution: executionResult,
      deliverables: {
        verificationReportJson: files.jsonPath,
        verificationReportMarkdown: files.mdPath,
      },
      verificationSummary: verification.summary,
      attackSurfaceDelta,
      soWhat,
    };

    if (jsonMode) {
      printJson(payload);
    } else {
      printSection('Apply Result');
      printKeyValue('Success', executionResult.success ? 'yes' : 'no');
      printKeyValue('Target', `${config.username}@${config.host}:${config.port || 22}`);
      printKeyValue('Timestamp', report.timestamp);

      printSection('Control Effectiveness');
      printKeyValue('Total Controls', verification.summary.totalControls);
      printKeyValue('Pass', verification.summary.passCount);
      printKeyValue('Fail', verification.summary.failCount);
      printKeyValue('Not Applicable', verification.summary.notApplicableCount);
      printKeyValue('Effectiveness (%)', verification.summary.effectiveness);

      printSection('Attack Surface Delta');
      printKeyValue('Ports Before', formatPorts(attackSurfaceDelta.ports.before));
      printKeyValue('Ports After', formatPorts(attackSurfaceDelta.ports.after));
      printKeyValue('Opened Ports', formatPorts(attackSurfaceDelta.ports.openedPorts));
      printKeyValue('Closed Ports', formatPorts(attackSurfaceDelta.ports.closedPorts));
      printKeyValue(
        'Likelihood Shift',
        `${attackSurfaceDelta.likelihood.levelBefore} (${attackSurfaceDelta.likelihood.scoreBefore}) -> ${attackSurfaceDelta.likelihood.levelAfter} (${attackSurfaceDelta.likelihood.scoreAfter})`,
      );

      printSection('So-What');
      console.log(soWhat.narrative);
      console.log(soWhat.riskAssessmentLink);
      if (soWhat.keyWins.length > 0) {
        console.log('Key Wins:');
        for (const win of soWhat.keyWins) {
          console.log(`- ${win}`);
        }
      }

      printSection('Evidence Files');
      printKeyValue('Verification Report (JSON)', files.jsonPath);
      printKeyValue('Verification Report (Markdown)', files.mdPath);

      if (executionResult.error) {
        printSection('Execution Error');
        console.log(executionResult.error);
      }

      if (executionResult.stdout) {
        printSection('Execution Log Preview');
        console.log(summarizeLog(executionResult.stdout));
      }
    }

    if (!executionResult.success) {
      process.exitCode = 1;
    }
    return;
  }

  console.log('Usage:');
  console.log('  npm run status                 -> Validate target configuration');
  console.log('  npm run plan                   -> Show exact hardening steps');
  console.log('  npm run demo                   -> Dry-run output (no changes)');
  console.log('  npm run apply                  -> Execute hardening + generate deliverables');
  console.log('  node scripts/cli.js <cmd> --json -> Machine-readable JSON output');
}

run();
