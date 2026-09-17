import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { DiffViewer } from '../src/components/DiffViewer.tsx';

describe('DiffViewer Component', () => {
  it('renders diff lines safely as plain text without executing scripts', () => {
    const original = {
      messages: [
        { role: 'user', content: '<script>alert("xss")</script> user@example.com' },
      ],
    };
    const redacted = {
      messages: [
        { role: 'user', content: '<script>alert("xss")</script> <AS:PII:1234>' },
      ],
    };

    render(
      <DiffViewer originalPayload={original} redactedPayload={redacted} />
    );

    // Verify scripts are rendered as literal text in code blocks, never executed as DOM elements
    const scripts = document.querySelectorAll('script');
    expect(scripts.length).toBe(0);

    expect(screen.getByText(/user@example\.com/)).toBeInTheDocument();
    expect(screen.getByText(/<AS:PII:1234>/)).toBeInTheDocument();
    expect(screen.getByText('Protected Content Replaced')).toBeInTheDocument();
  });

  it('renders unchanged state when payloads match', () => {
    const payload = { model: 'gpt-4o', safe: true };

    render(
      <DiffViewer originalPayload={payload} redactedPayload={payload} />
    );

    expect(screen.getByText('No Alterations')).toBeInTheDocument();
  });
});
