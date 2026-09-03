export function TrafficPage() {
  return (
    <div className="page-content" id="tabpanel-traffic" role="tabpanel" aria-labelledby="tab-traffic">
      <div className="page-header">
        <h2>Live Traffic Inspector</h2>
        <p className="page-subtitle">
          Real-time inspection of inbound coding agent requests and scanned findings (Milestone 2 &amp; 5).
        </p>
      </div>
      <div className="card empty-state">
        <p>No active proxy traffic. Coding agent endpoints will be active in Milestone 2.</p>
      </div>
    </div>
  );
}
