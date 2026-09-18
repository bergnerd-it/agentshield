/**
 * OpenAPI-generated System, Approvals, Events, Policies, and Settings Types.
 * Generated from backend OpenAPI schema.
 */

import type { components } from './schema';

export type DatabaseStatus = components['schemas']['DatabaseStatus'];
export type HealthResponse = components['schemas']['HealthResponse'];
export type SystemStatusResponse = components['schemas']['SystemStatusResponse'];
export type SystemStatus = SystemStatusResponse;

export type ApprovalSummary = components['schemas']['ApprovalSummaryResponse'];
export type ApprovalDetail = components['schemas']['ApprovalDetailResponse'];
export type ApprovalAction = components['schemas']['ApprovalActionResponse'];
export type ApprovalDecision = components['schemas']['ApprovalDecisionRequest'];
export type FindingDetail = components['schemas']['FindingDetailResponse'];

export type AuditEvent = components['schemas']['AuditEventResponse'];
export type EventList = components['schemas']['EventListResponse'];

export type PolicySummary = components['schemas']['PolicySummaryResponse'];
export type PolicyDetail = components['schemas']['PolicyDetailResponse'];
export type PolicyList = components['schemas']['PolicyListResponse'];
export type PolicyRule = components['schemas']['PolicyRuleDTO'];
export type PolicyCreate = components['schemas']['PolicyCreateRequest'];
export type PolicyUpdate = components['schemas']['PolicyUpdateRequest'];

export type DetectorInfo = components['schemas']['DetectorInfo'];
export type DetectorList = components['schemas']['DetectorListResponse'];

export type Settings = components['schemas']['SettingsResponse'];
export type SettingsUpdate = components['schemas']['SettingsUpdateRequest'];

export type IntegrationStatus = components['schemas']['IntegrationStatusResponse'];
export type ConfigDiff = components['schemas']['ConfigDiffResponse'];
export type AuditExportRequest = components['schemas']['AuditExportRequest'];
