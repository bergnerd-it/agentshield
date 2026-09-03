/**
 * System and Health API Types
 */

export interface DatabaseStatus {
  status: string;
  migration_version?: string | null;
}

export interface SystemStatus {
  status: 'ready' | 'degraded' | string;
  version: string;
  platform: string;
  profile: 'audit' | 'balanced' | 'strict' | string;
  host: string;
  port: number;
  database: DatabaseStatus;
  frontend_available: boolean;
}
