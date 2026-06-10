/**
 * analyzer.ts
 * Sends document code to the Guardrail API and returns typed Vulnerability objects.
 */
import * as vscode from 'vscode';
import axios, { AxiosError } from 'axios';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface Vulnerability {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  line: number;
  description: string;
  fix: string;
  fixed_code: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_BYTES = 50_000; // 50 KB hard cap
const CHUNK_RADIUS = 50;  // lines before/after cursor when doc > 100 lines

const SEVERITY_ORDER: Record<Vulnerability['severity'], number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

// Output channel — created once at module load, visible in Output → Guardrail
const channel = vscode.window.createOutputChannel('Guardrail');

// Module-level flag: show the "no API key" warning only once per session
let hasShownNoKeyWarning = false;

// ---------------------------------------------------------------------------
// Main exported function
// ---------------------------------------------------------------------------

export async function analyzeDocument(
  document: vscode.TextDocument,
  statusBar: vscode.StatusBarItem,
  _diagnosticCollection?: vscode.DiagnosticCollection
): Promise<Vulnerability[]> {
  // Step 1 — Read settings ------------------------------------------------
  const config = vscode.workspace.getConfiguration('guardrail');
  const apiKey = config.get<string>('apiKey', '');
  const apiUrl = config.get<string>('apiUrl', '');
  const minSeverity = config.get<string>('minSeverity', 'low') as Vulnerability['severity'];

  // Step 2 — Validate apiKey -----------------------------------------------
  if (!apiKey) {
    if (!hasShownNoKeyWarning) {
      hasShownNoKeyWarning = true;
      vscode.window.showWarningMessage(
        'Guardrail: No API key set. Add it in Settings → guardrail.apiKey'
      );
    }
    return [];
  }

  // Step 3 — Extract code chunk --------------------------------------------
  const code = document.getText().trim();
  if (!code || code.length === 0) {
    channel.appendLine(`[${new Date().toISOString()}] Skipping — empty document`);
    return [];
  }

  if (code.length < 10) {
    channel.appendLine(`[${new Date().toISOString()}] Skipping — code too short`);
    return [];
  }

  let extractedCode = document.getText();
  let startLine = 0;

  if (document.lineCount > 100) {
    const activeEditor = vscode.window.activeTextEditor;
    const cursorLine =
      activeEditor && activeEditor.document.uri.toString() === document.uri.toString()
        ? activeEditor.selection.active.line
        : Math.floor(document.lineCount / 2);

    const chunkStart = Math.max(0, cursorLine - CHUNK_RADIUS);
    const chunkEnd = Math.min(document.lineCount - 1, cursorLine + CHUNK_RADIUS);

    startLine = chunkStart;
    extractedCode = document
      .getText(new vscode.Range(chunkStart, 0, chunkEnd, Number.MAX_SAFE_INTEGER));
  }

  // Hard cap at 50 KB
  if (Buffer.byteLength(extractedCode, 'utf8') > MAX_BYTES) {
    extractedCode = Buffer.from(extractedCode, 'utf8').slice(0, MAX_BYTES).toString('utf8');
  }

  // Step 4 — Update status bar to scanning state ---------------------------
  statusBar.text = '$(sync~spin) Guardrail: Scanning...';



  try {
    // Post-debounce guard — document may have been cleared while waiting
    const text = document.getText();
    if (!text || text.trim().length < 10) {
      return [];
    }

    // Language normalization — handle IDE-specific languageId variants
    const languageMap: Record<string, string> = {
      'python': 'python',
      'python3': 'python',
      'javascriptreact': 'javascript',
      'typescriptreact': 'typescript',
      'js': 'javascript',
      'ts': 'typescript',
    };
    const normalizedLanguage = languageMap[document.languageId] ?? document.languageId;

    channel.appendLine(`[${new Date().toISOString()}] Scanning ${document.fileName} (startLine=${startLine})`);
    channel.appendLine(
      `[${new Date().toISOString()}] Sending request:\n` +
      `  language: "${normalizedLanguage}"\n` +
      `  apiUrl: "${apiUrl}"\n` +
      `  apiKey: "${apiKey ? 'SET' : 'EMPTY'}"\n` +
      `  codeLength: ${extractedCode.length}`
    );

    const response = await axios.post<{ vulnerabilities: Vulnerability[] }>(
      `${apiUrl}/analyze`,
      {
        code: extractedCode,
        language: normalizedLanguage,
        api_key: apiKey,
      },
      { timeout: 30_000 }
    );

    const vulnerabilities = response.data.vulnerabilities || [];
    channel.appendLine(`[${new Date().toISOString()}] ✅ Response received`);
    channel.appendLine(`[${new Date().toISOString()}] Found: ${vulnerabilities.length} vulnerabilities`);
    vulnerabilities.forEach((v: Vulnerability) => {
      channel.appendLine(`  → Line ${v.line}: [${v.severity}] ${v.title}`);
    });

    // Step 6 — Handle response ---------------------------------------------
    const raw: Vulnerability[] = vulnerabilities;

    // Adjust line numbers back to document-absolute positions
    const adjusted = raw.map((v) => ({
      ...v,
      line: v.line + startLine,
    }));

    // Filter by minSeverity
    const minOrder = SEVERITY_ORDER[minSeverity] ?? 1;
    const filtered = adjusted.filter(
      (v) => (SEVERITY_ORDER[v.severity] ?? 0) >= minOrder
    );

    channel.appendLine(`Found ${filtered.length} vulnerabilities (after severity filter: ${minSeverity})`);

    return filtered;

  } catch (err: unknown) {
    // Step 7 error cases ---------------------------------------------------
    const axiosErr = err as AxiosError;

    if (axiosErr.response) {
      if (axiosErr.response.status === 400) {
        channel.appendLine(`400 detail: ${JSON.stringify(axiosErr.response.data)}`);
        return [];
      }

      if (axiosErr.response.status === 429) {
        statusBar.text = '$(warning) Guardrail: Limit reached';
        vscode.window.showWarningMessage(
          'Guardrail: Daily scan limit reached. Upgrade to Pro.'
        );
        resetStatusBarAfterDelay(statusBar, 3000);
        return [];
      }

      if (axiosErr.response.status === 401) {
        vscode.window.showErrorMessage(
          'Guardrail: Invalid API key — check Settings'
        );
        resetStatusBarAfterDelay(statusBar, 3000);
        return [];
      }
    }

    if (!axiosErr.response) {
      // Network/connection error — no HTTP response received
      statusBar.text = '$(error) Guardrail: Offline';
      vscode.window.showErrorMessage(
        "Guardrail: Can't reach API. Check your connection."
      );
      resetStatusBarAfterDelay(statusBar, 3000);
      return [];
    }

    // Any other error
    console.error('Guardrail analyze error:', err);
    channel.appendLine(`Error: ${String(err)}`);
    resetStatusBarAfterDelay(statusBar, 3000);
    return [];

  } finally {
    // Step 7 — Reset status bar (always runs, overridden by error paths via timeout)
    statusBar.text = '$(shield) Guardrail';
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Resets the status bar text to the default after `delayMs` milliseconds.
 * Used by error paths that set a temporary error indicator.
 */
function resetStatusBarAfterDelay(
  statusBar: vscode.StatusBarItem,
  delayMs: number
): void {
  setTimeout(() => {
    statusBar.text = '$(shield) Guardrail';
  }, delayMs);
}
