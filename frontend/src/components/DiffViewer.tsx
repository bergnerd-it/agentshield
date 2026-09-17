import { useMemo, useState } from 'react';

interface DiffLine {
  type: 'added' | 'removed' | 'unchanged';
  text: string;
  originalLineNumber?: number;
  modifiedLineNumber?: number;
}

function computeSimpleDiff(originalText: string, modifiedText: string): DiffLine[] {
  const origLines = originalText.split('\n');
  const modLines = modifiedText.split('\n');

  // Simple and safe diff algorithm for JSON payloads
  const lines: DiffLine[] = [];

  // If identical, return all unchanged
  if (originalText === modifiedText) {
    return origLines.map((text, idx) => ({
      type: 'unchanged',
      text,
      originalLineNumber: idx + 1,
      modifiedLineNumber: idx + 1,
    }));
  }

  // Simple LCS-based or line-matching diff
  let i = 0;
  let j = 0;

  while (i < origLines.length || j < modLines.length) {
    if (i < origLines.length && j < modLines.length && origLines[i] === modLines[j]) {
      lines.push({
        type: 'unchanged',
        text: origLines[i],
        originalLineNumber: i + 1,
        modifiedLineNumber: j + 1,
      });
      i++;
      j++;
    } else {
      // Lookahead to find next match
      let matchOrig = -1;
      let matchMod = -1;
      const lookahead = 5;

      for (let d = 1; d <= lookahead; d++) {
        if (i + d < origLines.length && j < modLines.length && origLines[i + d] === modLines[j]) {
          matchOrig = i + d;
          matchMod = j;
          break;
        }
        if (i < origLines.length && j + d < modLines.length && origLines[i] === modLines[j + d]) {
          matchOrig = i;
          matchMod = j + d;
          break;
        }
      }

      if (matchOrig !== -1 && matchMod !== -1) {
        // Output removed lines up to matchOrig
        while (i < matchOrig) {
          lines.push({
            type: 'removed',
            text: origLines[i],
            originalLineNumber: i + 1,
          });
          i++;
        }
        // Output added lines up to matchMod
        while (j < matchMod) {
          lines.push({
            type: 'added',
            text: modLines[j],
            modifiedLineNumber: j + 1,
          });
          j++;
        }
      } else {
        if (i < origLines.length) {
          lines.push({
            type: 'removed',
            text: origLines[i],
            originalLineNumber: i + 1,
          });
          i++;
        }
        if (j < modLines.length) {
          lines.push({
            type: 'added',
            text: modLines[j],
            modifiedLineNumber: j + 1,
          });
          j++;
        }
      }
    }
  }

  return lines;
}

interface Props {
  originalPayload: Record<string, unknown> | null | undefined;
  redactedPayload: Record<string, unknown> | null | undefined;
  originalLabel?: string;
  redactedLabel?: string;
}

export function DiffViewer({
  originalPayload,
  redactedPayload,
  originalLabel = 'Masked Original (Request)',
  redactedLabel = 'Redacted / Policy Outcome',
}: Props) {
  const [viewMode, setViewMode] = useState<'unified' | 'split'>('unified');

  const origStr = useMemo(
    () => (originalPayload ? JSON.stringify(originalPayload, null, 2) : '(empty payload)'),
    [originalPayload]
  );
  const modStr = useMemo(
    () => (redactedPayload ? JSON.stringify(redactedPayload, null, 2) : '(empty payload)'),
    [redactedPayload]
  );

  const diffLines = useMemo(() => computeSimpleDiff(origStr, modStr), [origStr, modStr]);

  const hasDifferences = useMemo(() => origStr !== modStr, [origStr, modStr]);

  return (
    <div className="diff-viewer card" aria-label="Payload Diff Comparison">
      <div className="diff-toolbar">
        <div className="diff-summary">
          <span className="diff-badge">
            {hasDifferences ? 'Protected Content Replaced' : 'No Alterations'}
          </span>
          <span className="diff-notice">
            Zero raw secrets shown: masked previews only.
          </span>
        </div>
        <div className="diff-controls">
          <button
            type="button"
            className={`tab-item ${viewMode === 'unified' ? 'tab-item-active' : ''}`}
            onClick={() => setViewMode('unified')}
            aria-pressed={viewMode === 'unified'}
          >
            Unified View
          </button>
          <button
            type="button"
            className={`tab-item ${viewMode === 'split' ? 'tab-item-active' : ''}`}
            onClick={() => setViewMode('split')}
            aria-pressed={viewMode === 'split'}
          >
            Split View
          </button>
        </div>
      </div>

      {viewMode === 'unified' ? (
        <div className="diff-container diff-unified" role="region" aria-label="Unified diff">
          <pre className="diff-content" tabIndex={0}>
            {diffLines.map((line, idx) => (
              <div
                key={idx}
                className={`diff-line diff-line-${line.type}`}
                aria-label={`${line.type}: ${line.text}`}
              >
                <span className="diff-marker" aria-hidden="true">
                  {line.type === 'added' ? '+' : line.type === 'removed' ? '-' : ' '}
                </span>
                <span className="diff-lineno orig-lineno" aria-hidden="true">
                  {line.originalLineNumber ?? ' '}
                </span>
                <span className="diff-lineno mod-lineno" aria-hidden="true">
                  {line.modifiedLineNumber ?? ' '}
                </span>
                <code className="diff-text">{line.text}</code>
              </div>
            ))}
          </pre>
        </div>
      ) : (
        <div className="diff-container diff-split" role="region" aria-label="Side by side diff">
          <div className="diff-split-pane">
            <div className="diff-pane-header">{originalLabel}</div>
            <pre className="diff-content" tabIndex={0}>
              <code>{origStr}</code>
            </pre>
          </div>
          <div className="diff-split-pane">
            <div className="diff-pane-header">{redactedLabel}</div>
            <pre className="diff-content" tabIndex={0}>
              <code>{modStr}</code>
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
