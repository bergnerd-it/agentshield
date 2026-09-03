import { useQuery } from '@tanstack/react-query';
import type { SystemStatus } from './types.ts';

export async function fetchSystemStatus(): Promise<SystemStatus> {
  const response = await fetch('/api/v1/status', {
    headers: {
      Accept: 'application/json',
    },
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch system status: HTTP ${response.status}`);
  }
  return response.json() as Promise<SystemStatus>;
}

export function useSystemStatus() {
  return useQuery<SystemStatus, Error>({
    queryKey: ['systemStatus'],
    queryFn: fetchSystemStatus,
    refetchInterval: 5000,
    retry: 2,
  });
}
