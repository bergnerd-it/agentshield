import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type {
  ApprovalAction,
  ApprovalDetail,
  ApprovalSummary,
  AuditEvent,
  DetectorList,
  EventList,
  PolicyList,
  Settings,
  SettingsUpdate,
  SystemStatus,
} from './types.ts';

export function getAdminToken(): string | null {
  try {
    if (typeof window !== 'undefined' && typeof window.localStorage !== 'undefined' && window.localStorage !== null) {
      return window.localStorage.getItem('agentshield_admin_token');
    }
  } catch {
    // Ignore storage access errors (e.g. sandboxed iframe or private browsing)
  }
  return null;
}

function getAuthHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: 'application/json',
  };
  const token = getAdminToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

// System Status
export async function fetchSystemStatus(): Promise<SystemStatus> {
  const response = await fetch('/api/v1/status', {
    headers: getAuthHeaders(),
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

// Approvals API
export async function fetchApprovals(status?: string): Promise<ApprovalSummary[]> {
  const url = status
    ? `/api/v1/approvals?status=${encodeURIComponent(status)}`
    : '/api/v1/approvals';
  const response = await fetch(url, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch approvals: HTTP ${response.status}`);
  }
  return response.json() as Promise<ApprovalSummary[]>;
}

export function useApprovals(status?: string) {
  return useQuery<ApprovalSummary[], Error>({
    queryKey: ['approvals', status ?? 'all'],
    queryFn: () => fetchApprovals(status),
    refetchInterval: 3000,
  });
}

export async function fetchApprovalDetail(id: string): Promise<ApprovalDetail> {
  const response = await fetch(`/api/v1/approvals/${encodeURIComponent(id)}`, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch approval detail: HTTP ${response.status}`);
  }
  return response.json() as Promise<ApprovalDetail>;
}

export function useApprovalDetail(id: string | null) {
  return useQuery<ApprovalDetail, Error>({
    queryKey: ['approvalDetail', id],
    queryFn: () => {
      if (!id) throw new Error('No approval ID provided');
      return fetchApprovalDetail(id);
    },
    enabled: Boolean(id),
    refetchInterval: 2000,
  });
}

export async function approveRequest(id: string, reason?: string): Promise<ApprovalAction> {
  const response = await fetch(`/api/v1/approvals/${encodeURIComponent(id)}/approve`, {
    method: 'POST',
    headers: {
      ...getAuthHeaders(),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ reason: reason || null }),
  });
  if (!response.ok) {
    throw new Error(`Failed to approve request: HTTP ${response.status}`);
  }
  return response.json() as Promise<ApprovalAction>;
}

export function useApproveMutation() {
  const queryClient = useQueryClient();
  return useMutation<ApprovalAction, Error, { id: string; reason?: string }>({
    mutationFn: ({ id, reason }) => approveRequest(id, reason),
    onSuccess: (_, { id }) => {
      void queryClient.invalidateQueries({ queryKey: ['approvals'] });
      void queryClient.invalidateQueries({ queryKey: ['approvalDetail', id] });
      void queryClient.invalidateQueries({ queryKey: ['auditEvents'] });
    },
  });
}

export async function denyRequest(id: string, reason?: string): Promise<ApprovalAction> {
  const response = await fetch(`/api/v1/approvals/${encodeURIComponent(id)}/deny`, {
    method: 'POST',
    headers: {
      ...getAuthHeaders(),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ reason: reason || null }),
  });
  if (!response.ok) {
    throw new Error(`Failed to deny request: HTTP ${response.status}`);
  }
  return response.json() as Promise<ApprovalAction>;
}

export function useDenyMutation() {
  const queryClient = useQueryClient();
  return useMutation<ApprovalAction, Error, { id: string; reason?: string }>({
    mutationFn: ({ id, reason }) => denyRequest(id, reason),
    onSuccess: (_, { id }) => {
      void queryClient.invalidateQueries({ queryKey: ['approvals'] });
      void queryClient.invalidateQueries({ queryKey: ['approvalDetail', id] });
      void queryClient.invalidateQueries({ queryKey: ['auditEvents'] });
    },
  });
}

// Audit Events API
export interface AuditEventsParams {
  limit?: number;
  offset?: number;
  action?: string;
  provider?: string;
  agent?: string;
  project?: string;
}

export async function fetchAuditEvents(params: AuditEventsParams = {}): Promise<EventList> {
  const query = new URLSearchParams();
  if (params.limit !== undefined) query.set('limit', String(params.limit));
  if (params.offset !== undefined) query.set('offset', String(params.offset));
  if (params.action) query.set('action', params.action);
  if (params.provider) query.set('provider', params.provider);
  if (params.agent) query.set('agent', params.agent);
  if (params.project) query.set('project', params.project);

  const url = `/api/v1/events${query.toString() ? `?${query.toString()}` : ''}`;
  const response = await fetch(url, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch audit events: HTTP ${response.status}`);
  }
  return response.json() as Promise<EventList>;
}

export function useAuditEvents(params: AuditEventsParams = {}) {
  return useQuery<EventList, Error>({
    queryKey: ['auditEvents', params],
    queryFn: () => fetchAuditEvents(params),
    refetchInterval: 5000,
  });
}

export async function fetchAuditEvent(id: string): Promise<AuditEvent> {
  const response = await fetch(`/api/v1/events/${encodeURIComponent(id)}`, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch audit event: HTTP ${response.status}`);
  }
  return response.json() as Promise<AuditEvent>;
}

export function useAuditEvent(id: string | null) {
  return useQuery<AuditEvent, Error>({
    queryKey: ['auditEvent', id],
    queryFn: () => {
      if (!id) throw new Error('No audit event ID provided');
      return fetchAuditEvent(id);
    },
    enabled: Boolean(id),
  });
}

// Policies API
export async function fetchPolicies(profile?: string): Promise<PolicyList> {
  const url = profile ? `/api/v1/policies?profile=${encodeURIComponent(profile)}` : '/api/v1/policies';
  const response = await fetch(url, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch policies: HTTP ${response.status}`);
  }
  return response.json() as Promise<PolicyList>;
}

export function usePolicies(profile?: string) {
  return useQuery<PolicyList, Error>({
    queryKey: ['policies', profile ?? 'active'],
    queryFn: () => fetchPolicies(profile),
  });
}

// Detectors API
export async function fetchDetectors(): Promise<DetectorList> {
  const response = await fetch('/api/v1/detectors', {
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch detectors: HTTP ${response.status}`);
  }
  return response.json() as Promise<DetectorList>;
}

export function useDetectors() {
  return useQuery<DetectorList, Error>({
    queryKey: ['detectors'],
    queryFn: fetchDetectors,
  });
}

// Settings API
export async function fetchSettings(): Promise<Settings> {
  const response = await fetch('/api/v1/settings', {
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch settings: HTTP ${response.status}`);
  }
  return response.json() as Promise<Settings>;
}

export function useSettings() {
  return useQuery<Settings, Error>({
    queryKey: ['settings'],
    queryFn: fetchSettings,
  });
}

export async function updateSettings(payload: SettingsUpdate): Promise<Settings> {
  const response = await fetch('/api/v1/settings', {
    method: 'PUT',
    headers: {
      ...getAuthHeaders(),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    throw new Error(`Failed to update settings: HTTP ${response.status}`);
  }
  return response.json() as Promise<Settings>;
}

export function useUpdateSettingsMutation() {
  const queryClient = useQueryClient();
  return useMutation<Settings, Error, SettingsUpdate>({
    mutationFn: updateSettings,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['settings'] });
      void queryClient.invalidateQueries({ queryKey: ['systemStatus'] });
    },
  });
}
