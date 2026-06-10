/**
 * diagnostics.ts
 * Converts Guardrail findings into VS Code Diagnostics and pushes them
 * to the provided DiagnosticCollection.
 */
import * as vscode from 'vscode';
import { Vulnerability } from './analyzer';

// Finding is the internal shape used by diagnostics.ts and extension.ts.
// It maps from the Vulnerability returned by the API into a VS Code-friendly form.
export interface Finding {
  line: number;       // 0-based line index
  column: number;     // 0-based column index
  endLine?: number;
  endColumn?: number;
  message: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  rule?: string;
}

const SEVERITY_ORDER: Record<Finding['severity'], number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

function toVscodeSeverity(severity: Finding['severity']): vscode.DiagnosticSeverity {
  switch (severity) {
    case 'critical':
    case 'high':
      return vscode.DiagnosticSeverity.Error;
    case 'medium':
      return vscode.DiagnosticSeverity.Warning;
    case 'low':
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

export function applyDiagnostics(
  collection: vscode.DiagnosticCollection,
  document: vscode.TextDocument,
  findings: Finding[]
): void {
  const config = vscode.workspace.getConfiguration('guardrail');
  const minSeverity: Finding['severity'] = config.get('minSeverity') ?? 'low';
  const minOrder = SEVERITY_ORDER[minSeverity];

  const diagnostics: vscode.Diagnostic[] = findings
    .filter((f) => SEVERITY_ORDER[f.severity] >= minOrder)
    .map((f) => {
      const startLine = Math.max(0, f.line);
      const startCol = Math.max(0, f.column);
      const endLine = f.endLine !== undefined ? Math.max(0, f.endLine) : startLine;
      const endCol =
        f.endColumn !== undefined
          ? Math.max(0, f.endColumn)
          : document.lineAt(Math.min(endLine, document.lineCount - 1)).text.length;

      const range = new vscode.Range(startLine, startCol, endLine, endCol);
      const diagnostic = new vscode.Diagnostic(
        range,
        f.rule ? `[${f.rule}] ${f.message}` : f.message,
        toVscodeSeverity(f.severity)
      );
      diagnostic.source = 'Guardrail';
      return diagnostic;
    });

  collection.set(document.uri, diagnostics);
}

export function clearDiagnostics(
  collection: vscode.DiagnosticCollection,
  document: vscode.TextDocument
): void {
  collection.delete(document.uri);
}

/**
 * Converts a Vulnerability[] directly into VS Code diagnostics without
 * requiring the intermediate Finding mapping in extension.ts.
 */
export function updateDiagnostics(
  document: vscode.TextDocument,
  vulnerabilities: Vulnerability[],
  collection: vscode.DiagnosticCollection
): void {
  const diagnostics: vscode.Diagnostic[] = vulnerabilities.map((v) => {
    const line = Math.max(0, v.line - 1);
    const range = new vscode.Range(line, 0, line, 999);
    const severity =
      v.severity === 'critical' || v.severity === 'high'
        ? vscode.DiagnosticSeverity.Error
        : v.severity === 'medium'
        ? vscode.DiagnosticSeverity.Warning
        : vscode.DiagnosticSeverity.Information;
    const diagnostic = new vscode.Diagnostic(
      range,
      `🔴 ${v.title}: ${v.description}`,
      severity
    );
    diagnostic.source = 'Guardrail';
    diagnostic.code = JSON.stringify(v);
    return diagnostic;
  });
  collection.set(document.uri, diagnostics);
}
