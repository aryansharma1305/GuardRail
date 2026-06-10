/**
 * extension.ts
 * VS Code extension entry point for Guardrail — Security Scanner.
 */
import * as vscode from 'vscode';
import { analyzeDocument } from './analyzer';
import { updateDiagnostics } from './diagnostics';
import { debounce } from './debounce';
import { GuardrailCodeActionProvider } from './codeActions';

// Supported language identifiers
const SUPPORTED = ['python', 'javascript', 'typescript', 'java', 'php', 'go'];

export function activate(context: vscode.ExtensionContext): void {

  // 1. Create diagnostic collection
  const diagnosticCollection = vscode.languages.createDiagnosticCollection('guardrail');
  context.subscriptions.push(diagnosticCollection);

  // 2. Create status bar
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.text = '$(shield) Guardrail';
  statusBar.tooltip = 'Guardrail Security Scanner';
  statusBar.show();
  context.subscriptions.push(statusBar);

  // Code action provider (quick-fix lightbulbs)
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      SUPPORTED.map((lang) => ({ language: lang })),
      new GuardrailCodeActionProvider(),
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    )
  );

  // 3. Create debounced function
  const debouncedAnalyze = debounce(async (document: vscode.TextDocument) => {
    const vulnerabilities = await analyzeDocument(document, statusBar, diagnosticCollection);
    updateDiagnostics(document, vulnerabilities, diagnosticCollection);
  }, 3000);

  // 4. Listen for changes
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(event => {
      const doc = event.document;
      if (!SUPPORTED.includes(doc.languageId)) { return; }
      const config = vscode.workspace.getConfiguration('guardrail');
      if (!config.get('enabled', true)) { return; }
      debouncedAnalyze(doc);
    })
  );

  // 5. Also scan on file open
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(doc => {
      if (!SUPPORTED.includes(doc.languageId)) { return; }
      debouncedAnalyze(doc);
    })
  );

  // Scan whatever is already open when the extension activates
  const activeEditor = vscode.window.activeTextEditor;
  if (activeEditor && SUPPORTED.includes(activeEditor.document.languageId)) {
    debouncedAnalyze(activeEditor.document);
  }
}

export function deactivate(): void {
  // Subscriptions are disposed automatically by VS Code via context.subscriptions.
  // Nothing extra to clean up here.
}
