export type TabId =
  | 'dashboard'
  | 'traffic'
  | 'approvals'
  | 'policies'
  | 'integrations'
  | 'audit'
  | 'settings';

interface TabItem {
  id: TabId;
  label: string;
}

const TABS: TabItem[] = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'traffic', label: 'Live Traffic' },
  { id: 'approvals', label: 'Approvals' },
  { id: 'policies', label: 'Policies' },
  { id: 'integrations', label: 'Integrations' },
  { id: 'audit', label: 'Audit Log' },
  { id: 'settings', label: 'Settings' },
];

interface Props {
  activeTab: TabId;
  onSelectTab: (tab: TabId) => void;
}

export function Navigation({ activeTab, onSelectTab }: Props) {
  return (
    <nav className="nav-container" aria-label="Main Navigation">
      <div className="tab-list" role="tablist">
        {TABS.map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              role="tab"
              aria-selected={isActive}
              aria-controls={`tabpanel-${tab.id}`}
              id={`tab-${tab.id}`}
              tabIndex={isActive ? 0 : -1}
              onClick={() => onSelectTab(tab.id)}
              className={`tab-item ${isActive ? 'tab-item-active' : ''}`}
            >
              {tab.label}
            </button>
          );
        })}
      </div>
    </nav>
  );
}
