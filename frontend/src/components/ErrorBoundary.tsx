import { Component, type ErrorInfo, type ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    console.error('ErrorBoundary caught an error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="error-boundary-container" role="alert">
          <h2>Something went wrong</h2>
          <p>{this.state.error?.message || 'An unexpected rendering error occurred.'}</p>
          <button
            onClick={() => this.setState({ hasError: false, error: null })}
            className="button-primary"
          >
            Try again
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
