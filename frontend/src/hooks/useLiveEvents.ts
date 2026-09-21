import { useEffect, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { getAdminToken } from '../api/client.ts';

const MAX_SSE_FRAME_BYTES = 64 * 1024;

export type SSEConnectionStatus = 'connected' | 'connecting' | 'disconnected';

export interface LiveEvent<T = unknown> {
  type: string;
  data: T;
  timestamp: string;
}

export function useLiveEvents() {
  const [status, setStatus] = useState<SSEConnectionStatus>('connecting');
  const [lastEvent, setLastEvent] = useState<LiveEvent | null>(null);
  const queryClient = useQueryClient();
  const reconnectTimeoutRef = useRef<number | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);
  const retryDelayRef = useRef(1000);

  useEffect(() => {
    let isMounted = true;

    function handleEvent(eventType: string, data: string) {
      if (!isMounted) return;
      try {
        const payload = JSON.parse(data);
        setLastEvent({ type: eventType, data: payload, timestamp: new Date().toISOString() });
        if (eventType === 'approval_pending' || eventType === 'approval_resolved') {
          void queryClient.invalidateQueries({ queryKey: ['approvals'] });
          void queryClient.invalidateQueries({ queryKey: ['approvalDetail'] });
        }
        if (eventType === 'audit_event') {
          void queryClient.invalidateQueries({ queryKey: ['auditEvents'] });
        }
        if (eventType === 'system_status') {
          void queryClient.invalidateQueries({ queryKey: ['systemStatus'] });
        }
      } catch {
        // Ignore malformed SSE JSON payloads.
      }
    }

    function scheduleReconnect() {
      if (!isMounted) return;
      const delay = retryDelayRef.current;
      retryDelayRef.current = Math.min(delay * 1.5, 10000);
      reconnectTimeoutRef.current = window.setTimeout(() => void connect(), delay);
    }

    async function connect() {
      if (!isMounted || typeof window === 'undefined') return;
      setStatus('connecting');
      const token = getAdminToken();
      const controller = new AbortController();
      abortControllerRef.current = controller;

      try {
        const response = await fetch('/api/v1/events/stream', {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
          signal: controller.signal,
        });
        if (!response.ok || !response.body) throw new Error('SSE connection failed');
        setStatus('connected');
        retryDelayRef.current = 1000;

        const reader = response.body.getReader();
        const decoder = new TextDecoder('utf-8', { fatal: true });
        const encoder = new TextEncoder();
        let buffer = '';
        let trailingCarriageReturn = false;
        while (isMounted) {
          const { value, done } = await reader.read();
          if (done) {
            buffer += decoder.decode();
            if (trailingCarriageReturn) buffer += '\n';
            if (encoder.encode(buffer).byteLength > MAX_SSE_FRAME_BYTES) {
              throw new Error('SSE frame exceeds the configured size limit');
            }
            break;
          }

          let decoded = decoder.decode(value, { stream: true });
          if (trailingCarriageReturn) decoded = `\r${decoded}`;
          trailingCarriageReturn = decoded.endsWith('\r');
          if (trailingCarriageReturn) decoded = decoded.slice(0, -1);
          buffer += decoded.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

          let boundary = buffer.indexOf('\n\n');
          while (boundary >= 0) {
            const frame = buffer.slice(0, boundary);
            if (encoder.encode(frame).byteLength > MAX_SSE_FRAME_BYTES) {
              throw new Error('SSE frame exceeds the configured size limit');
            }
            buffer = buffer.slice(boundary + 2);
            let eventType = 'message';
            const dataLines: string[] = [];
            for (const line of frame.split('\n')) {
              if (line.startsWith('event:')) eventType = line.slice(6).trimStart();
              if (line.startsWith('data:')) dataLines.push(line.slice(5).trimStart());
            }
            if (dataLines.length > 0) handleEvent(eventType, dataLines.join('\n'));
            boundary = buffer.indexOf('\n\n');
          }
          if (encoder.encode(buffer).byteLength > MAX_SSE_FRAME_BYTES) {
            throw new Error('SSE frame exceeds the configured size limit');
          }
        }
        if (isMounted) {
          setStatus('disconnected');
          scheduleReconnect();
        }
      } catch (error) {
        if (!isMounted || (error instanceof DOMException && error.name === 'AbortError')) return;
        setStatus('disconnected');
        scheduleReconnect();
      }
    }

    void connect();

    return () => {
      isMounted = false;
      abortControllerRef.current?.abort();
      abortControllerRef.current = null;
      if (reconnectTimeoutRef.current !== null) {
        window.clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = null;
      }
    };
  }, [queryClient]);

  return { status, lastEvent };
}
