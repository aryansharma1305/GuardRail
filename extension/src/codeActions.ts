/**
 * codeActions.ts
 * One-click fix provider: reads the serialised Vulnerability stored in
 * diagnostic.code and replaces the offending line with fixed_code.
 */
import * as vscode from 'vscode';

export class GuardrailCodeActionProvider implements vscode.CodeActionProvider {
  public static readonly providedCodeActionKinds = [
    vscode.CodeActionKind.QuickFix,
  ];

  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== 'Guardrail') { continue; }
      if (!diagnostic.code) { continue; }

      try {
        const vulnerability = JSON.parse(diagnostic.code as string);
        if (!vulnerability.fixed_code) { continue; }

        const action = new vscode.CodeAction(
          `$(wrench) Fix with Guardrail: ${vulnerability.title}`,
          vscode.CodeActionKind.QuickFix
        );

        const fix = new vscode.WorkspaceEdit();
        const lineRange = new vscode.Range(
          diagnostic.range.start.line, 0,
          diagnostic.range.start.line,
          document.lineAt(diagnostic.range.start.line).text.length
        );
        fix.replace(document.uri, lineRange, vulnerability.fixed_code);

        action.edit = fix;
        action.diagnostics = [diagnostic];
        action.isPreferred = vulnerability.severity === 'critical';

        actions.push(action);

      } catch (_e) {
        continue;
      }
    }

    return actions;
  }
}
