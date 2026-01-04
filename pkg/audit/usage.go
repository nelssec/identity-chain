package audit

import (
	"context"
	"sort"
	"time"

	"github.com/nelssec/identity-chain/pkg/graph"
)

type Analyzer struct {
	source  Source
	tracker *UsageTracker
	graph   *graph.Graph
}

func NewAnalyzer(source Source, g *graph.Graph) *Analyzer {
	return &Analyzer{
		source:  source,
		tracker: NewUsageTracker(),
		graph:   g,
	}
}

func (a *Analyzer) Analyze(ctx context.Context, opts QueryOptions) error {
	events, err := a.source.GetEvents(ctx, opts)
	if err != nil {
		return err
	}

	for _, event := range events {
		a.tracker.Track(event)
	}

	return nil
}

func (a *Analyzer) AnalyzeStream(ctx context.Context, opts QueryOptions) error {
	ch, err := a.source.StreamEvents(ctx, opts)
	if err != nil {
		return err
	}

	for event := range ch {
		a.tracker.Track(event)
	}

	return nil
}

func (a *Analyzer) GetUnusedPermissions(since time.Duration) []UnusedPermission {
	granted := a.extractGrantedPermissions()
	return a.tracker.GetUnusedPermissions(granted, since)
}

func (a *Analyzer) extractGrantedPermissions() []GrantedPermission {
	var permissions []GrantedPermission

	serviceAccounts := a.graph.GetNodesByType(graph.NodeServiceAccount)

	for _, sa := range serviceAccounts {
		saKey := "system:serviceaccount:" + sa.Namespace + ":" + sa.Name

		edges := a.graph.GetOutEdges(sa.ID)
		for _, edge := range edges {
			if edge.Type != graph.EdgeBinds {
				continue
			}

			role := a.graph.GetNode(edge.To)
			if role == nil {
				continue
			}

			roleEdges := a.graph.GetOutEdges(role.ID)
			for _, roleEdge := range roleEdges {
				if roleEdge.Type != graph.EdgeGrants {
					continue
				}

				resource := a.graph.GetNode(roleEdge.To)
				if resource == nil {
					continue
				}

				for _, verb := range roleEdge.Metadata.Verbs {
					permissions = append(permissions, GrantedPermission{
						ServiceAccount: saKey,
						Namespace:      sa.Namespace,
						Resource:       resource.Metadata.ResourceKind,
						Verb:           verb,
						ViaRole:        role.Name,
						APIGroup:       "",
					})
				}
			}
		}
	}

	return permissions
}

func (a *Analyzer) GetUsageReport() *UsageReport {
	report := &UsageReport{
		GeneratedAt:   time.Now(),
		TotalRecords:  len(a.tracker.records),
		SAUsage:       make(map[string]*ServiceAccountUsage),
	}

	for _, record := range a.tracker.GetRecords() {
		saKey := record.ServiceAccount
		if _, exists := report.SAUsage[saKey]; !exists {
			report.SAUsage[saKey] = &ServiceAccountUsage{
				ServiceAccount: saKey,
				Resources:      make(map[string]*ResourceUsage),
			}
		}

		saUsage := report.SAUsage[saKey]
		saUsage.TotalCalls += record.Count
		saUsage.SuccessCalls += record.SuccessCount
		saUsage.FailedCalls += record.FailureCount

		if saUsage.FirstSeen.IsZero() || record.FirstSeen.Before(saUsage.FirstSeen) {
			saUsage.FirstSeen = record.FirstSeen
		}
		if record.LastSeen.After(saUsage.LastSeen) {
			saUsage.LastSeen = record.LastSeen
		}

		resKey := record.Namespace + "/" + record.Resource
		if _, exists := saUsage.Resources[resKey]; !exists {
			saUsage.Resources[resKey] = &ResourceUsage{
				Namespace: record.Namespace,
				Resource:  record.Resource,
				Verbs:     make(map[string]int64),
			}
		}

		resUsage := saUsage.Resources[resKey]
		resUsage.TotalCalls += record.Count
		resUsage.Verbs[record.Verb] += record.Count

		if resUsage.FirstSeen.IsZero() || record.FirstSeen.Before(resUsage.FirstSeen) {
			resUsage.FirstSeen = record.FirstSeen
		}
		if record.LastSeen.After(resUsage.LastSeen) {
			resUsage.LastSeen = record.LastSeen
		}
	}

	return report
}

type UsageReport struct {
	GeneratedAt  time.Time
	TotalRecords int
	SAUsage      map[string]*ServiceAccountUsage
}

type ServiceAccountUsage struct {
	ServiceAccount string
	TotalCalls     int64
	SuccessCalls   int64
	FailedCalls    int64
	FirstSeen      time.Time
	LastSeen       time.Time
	Resources      map[string]*ResourceUsage
}

type ResourceUsage struct {
	Namespace  string
	Resource   string
	TotalCalls int64
	Verbs      map[string]int64
	FirstSeen  time.Time
	LastSeen   time.Time
}

func (a *Analyzer) GetOverprivilegedSAs(since time.Duration) []OverprivilegedSA {
	unused := a.GetUnusedPermissions(since)
	granted := a.extractGrantedPermissions()

	saStats := make(map[string]*OverprivilegedSA)

	for _, perm := range granted {
		if _, exists := saStats[perm.ServiceAccount]; !exists {
			saStats[perm.ServiceAccount] = &OverprivilegedSA{
				ServiceAccount:     perm.ServiceAccount,
				Namespace:          extractNamespace(perm.ServiceAccount),
				Name:               extractSAName(perm.ServiceAccount),
				GrantedPermissions: 0,
				UsedPermissions:    0,
				UnusedPermissions:  make([]UnusedPermission, 0),
			}
		}
		saStats[perm.ServiceAccount].GrantedPermissions++
	}

	for _, u := range unused {
		if sa, exists := saStats[u.ServiceAccount]; exists {
			sa.UnusedPermissions = append(sa.UnusedPermissions, u)
		}
	}

	for _, sa := range saStats {
		sa.UsedPermissions = sa.GrantedPermissions - len(sa.UnusedPermissions)
		if sa.GrantedPermissions > 0 {
			sa.UsageRatio = float64(sa.UsedPermissions) / float64(sa.GrantedPermissions)
		}
	}

	var result []OverprivilegedSA
	for _, sa := range saStats {
		if len(sa.UnusedPermissions) > 0 {
			result = append(result, *sa)
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return len(result[i].UnusedPermissions) > len(result[j].UnusedPermissions)
	})

	return result
}

type OverprivilegedSA struct {
	ServiceAccount     string
	Namespace          string
	Name               string
	GrantedPermissions int
	UsedPermissions    int
	UnusedPermissions  []UnusedPermission
	UsageRatio         float64
}

func extractNamespace(saKey string) string {
	parts := splitSAKey(saKey)
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
}

func extractSAName(saKey string) string {
	parts := splitSAKey(saKey)
	if len(parts) >= 4 {
		return parts[3]
	}
	return ""
}

func splitSAKey(key string) []string {
	var parts []string
	current := ""
	for _, c := range key {
		if c == ':' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

type RealTimeMonitor struct {
	source    Source
	tracker   *UsageTracker
	callbacks []func(Event)
	alerts    []AlertRule
}

func NewRealTimeMonitor(source Source) *RealTimeMonitor {
	return &RealTimeMonitor{
		source:  source,
		tracker: NewUsageTracker(),
	}
}

func (m *RealTimeMonitor) AddCallback(cb func(Event)) {
	m.callbacks = append(m.callbacks, cb)
}

func (m *RealTimeMonitor) AddAlertRule(rule AlertRule) {
	m.alerts = append(m.alerts, rule)
}

func (m *RealTimeMonitor) Start(ctx context.Context, opts QueryOptions) error {
	ch, err := m.source.StreamEvents(ctx, opts)
	if err != nil {
		return err
	}

	for event := range ch {
		m.tracker.Track(event)

		for _, cb := range m.callbacks {
			cb(event)
		}

		for _, rule := range m.alerts {
			if rule.Matches(event) {
				rule.Action(event)
			}
		}
	}

	return nil
}

type AlertRule struct {
	Name    string
	Matches func(Event) bool
	Action  func(Event)
}

func HighRiskVerbRule(action func(Event)) AlertRule {
	return AlertRule{
		Name: "high-risk-verb",
		Matches: func(e Event) bool {
			switch e.Verb {
			case "delete", "deletecollection", "create", "patch", "update":
				switch e.ObjectRef.Resource {
				case "secrets", "roles", "clusterroles", "rolebindings", "clusterrolebindings":
					return true
				}
			case "exec", "attach", "portforward":
				return true
			}
			return false
		},
		Action: action,
	}
}

func SecretsAccessRule(action func(Event)) AlertRule {
	return AlertRule{
		Name: "secrets-access",
		Matches: func(e Event) bool {
			return e.ObjectRef.Resource == "secrets" && e.ResponseStatus.Code >= 200 && e.ResponseStatus.Code < 300
		},
		Action: action,
	}
}

func PrivilegeEscalationRule(action func(Event)) AlertRule {
	return AlertRule{
		Name: "privilege-escalation",
		Matches: func(e Event) bool {
			if e.ObjectRef.Resource == "rolebindings" || e.ObjectRef.Resource == "clusterrolebindings" {
				if e.Verb == "create" || e.Verb == "update" || e.Verb == "patch" {
					return true
				}
			}
			if e.ObjectRef.Resource == "pods" && e.Verb == "create" {
				return true
			}
			return false
		},
		Action: action,
	}
}

func UnauthorizedAccessRule(action func(Event)) AlertRule {
	return AlertRule{
		Name: "unauthorized-access",
		Matches: func(e Event) bool {
			return e.ResponseStatus.Code == 403 || e.ResponseStatus.Reason == "Forbidden"
		},
		Action: action,
	}
}
