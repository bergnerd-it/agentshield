import { useEffect, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { getAdminToken } from '../api/client.ts';

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
  const eventSourceRef = useRef<EventSource | null>(null);
  const retryDelayRef = useRef(1000);

  useEffect(() => {
    let isMounted = true;

    function connect() {
      if (!isMounted) return;
      if (typeof window === 'undefined' || typeof EventSource === 'undefined') {
        setStatus('disconnected');
        return;
      }
      setStatus('connecting');

      const token = getAdminToken();
      const url = token
        ? `/api/v1/events/stream?token=${encodeURIComponent(token)}`
        : '/api/v1/events/stream';

      try {
        const es = new EventSource(url);
        eventSourceRef.current = es;

        es.onopen = () => {
          if (!isMounted) return;
          setStatus('connected');
          retryDelayRef.current = 1000;
        };

        es.onerror = () => {
          if (!isMounted) return;
          setStatus('disconnected');
          es.close();
          eventSourceRef.current = null;

          // Reconnect with exponential backoff capped at 10s
          const delay = retryDelayRef.current;
          retryDelayRef.current = Math.min(delay * 1.5, 10000);
          reconnectTimeoutRef.current = window.setTimeout(connect, delay);
        };

        const eventTypes = [
          'connected',
          'heartbeat',
          'approval_pending',
          'approval_decided',
          'proxy_request',
          'system_status',
        ];

        eventTypes.forEach((eventType) => {
          es.addEventListener(eventType, (evt: MessageEvent) => {
            if (!isMounted) return;
            try {
              const payload = JSON.parse(evt.data);
              const eventObj: LiveEvent = {
                type: eventType,
                data: payload,
                timestamp: new Date().toISOString(),
              };
              setLastEvent(eventObj);

              if (eventType === 'approval_pending' || eventType === 'approval_decided') {
                void queryClient.invalidateQueries({ queryKey: ['approvals'] });
                void queryClient.invalidateQueries({ queryKey: ['approvalDetail'] });
              }
              if (eventType === 'proxy_request') {
                void queryClient.invalidateQueries({ queryKey: ['auditEvents'] });
              }
              if (eventType === 'system_status') {
                void queryClient.invalidateQueries({ queryKey: ['systemStatus'] });
              }
            } catch {
              // Ignore malformed SSE json payloads
            }
          });
        });
      } catch {
        setStatus('disconnected');
      }
    }

    connect();

    return () => {
      isMounted = false;
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
      if (reconnectTimeoutRef.current !== null) {
        window.clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = null;
      }
    };
  }, [queryClient]);

  return { status, lastEvent };
}
