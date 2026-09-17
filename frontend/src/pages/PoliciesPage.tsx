import { useDetectors, usePolicies } from '../api/client.ts';

export function PoliciesPage() {
  const { data: policyData, isLoading: isPoliciesLoading } = usePolicies();
  const { data: detectorData, isLoading: isDetectorsLoading } = useDetectors();

  return (
    <div
      className="page-content"
      id="tabpanel-policies"
      role="tabpanel"
      aria-labelledby="tab-policies"
    >
      <div className="page-header">
        <h2>Security Policies &amp; Profiles</h2>
        <p className="page-subtitle">
          Rule precedence, active detection profiles, and inspection detector capabilities.
        </p>
      </div>

      {/* Precedence & Security Invariant Banner */}
      <div className="card policy-precedence-card">
        <h3>Policy Engine Evaluation Precedence</h3>
        <p className="policy-precedence-desc">
          When multiple detector findings match a single payload, the policy engine resolves actions strictly
          in descending order of enforcement severity:
        </p>

        <div className="precedence-diagram">
          <div className="precedence-step step-block">
            <span className="step-priority">Priority 50</span>
            <span className="step-title">BLOCK</span>
            <span className="step-desc">Immediate fail-closed stop</span>
          </div>
          <div className="precedence-arrow">➔</div>
          <div className="precedence-step step-approval">
            <span className="step-priority">Priority 40</span>
            <span className="step-title">REQUIRE_APPROVAL</span>
            <span className="step-desc">Holds payload for operator review</span>
          </div>
          <div className="precedence-arrow">➔</div>
          <div className="precedence-step step-redact">
            <span className="step-priority">Priority 30</span>
            <span className="step-title">REDACT</span>
            <span className="step-desc">Replaces PII with pseudonym</span>
          </div>
          <div className="precedence-arrow">➔</div>
          <div className="precedence-step step-warn">
            <span className="step-priority">Priority 20</span>
            <span className="step-title">WARN</span>
            <span className="step-desc">Audit note, passes payload</span>
          </div>
          <div className="precedence-arrow">➔</div>
          <div className="precedence-step step-allow">
            <span className="step-priority">Priority 10</span>
            <span className="step-title">ALLOW</span>
            <span className="step-desc">Forward untouched</span>
          </div>
        </div>

        <div className="security-invariant-callout">
          <strong>🔒 Non-Negotiable Security Invariant:</strong>
          <span>
            Detected credentials, API keys, passwords, and secrets ALWAYS trigger <code>BLOCK</code>.
            Secret findings can never be downgraded to <code>REQUIRE_APPROVAL</code> or approved for egress.
          </span>
        </div>
      </div>

      {/* Effective Profile and Rules */}
      <div className="card rules-card">
        <div className="rules-header">
          <h3>
            Active Profile: <span className="capitalize color-primary">{policyData?.active_profile || 'Balanced'}</span>
          </h3>
          <span className="card-hint">
            {policyData?.rules.length ?? 0} active rule{policyData?.rules.length !== 1 ? 's' : ''} evaluated per request
          </span>
        </div>

        {isPoliciesLoading ? (
          <p>Loading security policies…</p>
        ) : (
          <div className="table-responsive">
            <table className="traffic-table" role="table" aria-label="Active policy rules">
              <thead>
                <tr>
                  <th>Rule ID</th>
                  <th>Action</th>
                  <th>Priority</th>
                  <th>Finding Category</th>
                  <th>Min Severity</th>
                  <th>Scope</th>
                </tr>
              </thead>
              <tbody>
                {policyData?.rules && policyData.rules.length > 0 ? (
                  policyData.rules.map((rule) => (
                    <tr key={rule.id}>
                      <td>
                        <code>{rule.id}</code>
                      </td>
                      <td>
                        <span className={`action-pill action-${rule.action.toLowerCase()}`}>
                          {rule.action}
                        </span>
                      </td>
                      <td>{rule.priority}</td>
                      <td>
                        <span className="finding-chip">{rule.category ?? 'ALL'}</span>
                      </td>
                      <td>{rule.minimum_severity ?? '-'}</td>
                      <td>
                        <span className="text-muted">
                          {rule.provider ? `${rule.provider} ` : 'any provider '}
                          {rule.direction ? `(${rule.direction})` : ''}
                        </span>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={6} className="text-center text-muted">
                      No custom rules loaded. Profile default behavior applies.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Detectors Registry */}
      <div className="card detectors-card">
        <h3>Registered Security Detectors</h3>
        <p className="page-subtitle">
          Pluggable inspection modules scanning inbound agent requests and outbound responses.
        </p>

        {isDetectorsLoading ? (
          <p>Loading detector registry…</p>
        ) : (
          <div className="detectors-grid">
            {detectorData?.detectors.map((det) => (
              <div key={det.id} className="card detector-item-card">
                <div className="detector-item-header">
                  <div>
                    <h4>{det.name}</h4>
                    <span className="detector-version">
                      ID: <code>{det.id}</code> (v{det.version})
                    </span>
                  </div>
                  <span className={`status-pill ${det.enabled ? 'dot-green-pill' : 'dot-red-pill'}`}>
                    {det.enabled ? 'ACTIVE' : 'DISABLED'}
                  </span>
                </div>

                <p className="detector-desc">{det.description}</p>

                {det.is_blocking_only && (
                  <div className="blocking-only-tag">
                    ⛔ Irreversible Block: Detects secrets that can never be forwarded
                  </div>
                )}

                <div className="detector-categories">
                  <span className="card-label">Categories:</span>
                  <div className="finding-chips">
                    {det.supported_categories.map((cat, idx) => (
                      <span key={idx} className="finding-chip-sm">
                        {cat}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
