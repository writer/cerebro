"use client";

import { Component, ReactNode } from "react";

type RouteErrorBoundaryProps = {
  children: ReactNode;
};

type RouteErrorBoundaryState = {
  hasError: boolean;
  error: Error | null;
};

class Boundary extends Component<RouteErrorBoundaryProps, RouteErrorBoundaryState> {
  state: RouteErrorBoundaryState = {
    hasError: false,
    error: null
  };

  static getDerivedStateFromError(error: Error): RouteErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: unknown) {
    console.error("Route boundary captured an error", error, errorInfo);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError && this.state.error) {
      return (
        <div className="rounded-md border border-red-900/40 bg-red-950/40 p-6 text-sm text-red-200">
          <h2 className="text-base font-semibold text-red-100">Something went wrong</h2>
          <p className="mt-2 text-red-200/80">{this.state.error.message}</p>
          <button
            type="button"
            className="mt-4 inline-flex items-center rounded-md border border-red-500/40 px-3 py-1 text-xs font-semibold text-red-100 transition hover:bg-red-900/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-300"
            onClick={this.handleReset}
          >
            Try again
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

export function RouteErrorBoundary({ children }: RouteErrorBoundaryProps) {
  return <Boundary>{children}</Boundary>;
}
