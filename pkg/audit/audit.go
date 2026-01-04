package audit

import (
	"context"
	"time"
)

type Event struct {
	Timestamp         time.Time
	AuditID           string
	Stage             string
	RequestURI        string
	Verb              string
	User              UserInfo
	SourceIPs         []string
	ObjectRef         ObjectReference
	ResponseStatus    ResponseStatus
	RequestObject     map[string]interface{}
	ResponseObject    map[string]interface{}
	Annotations       map[string]string
}

type UserInfo struct {
	Username string
	UID      string
	Groups   []string
	Extra    map[string][]string
}

type ObjectReference struct {
	Resource        string
	Namespace       string
	Name            string
	UID             string
	APIGroup        string
	APIVersion      string
	ResourceVersion string
	Subresource     string
}

type ResponseStatus struct {
	Code    int
	Status  string
	Message string
	Reason  string
}

type Source interface {
	Name() string
	GetEvents(ctx context.Context, opts QueryOptions) ([]Event, error)
	StreamEvents(ctx context.Context, opts QueryOptions) (<-chan Event, error)
	Close() error
}

type QueryOptions struct {
	StartTime       time.Time
	EndTime         time.Time
	Namespace       string
	User            string
	Resource        string
	Verb            string
	Limit           int
	IncludeSystem   bool
}

type UsageRecord struct {
	ServiceAccount string
	Namespace      string
	Resource       string
	Verb           string
	APIGroup       string
	Count          int64
	FirstSeen      time.Time
	LastSeen       time.Time
	SuccessCount   int64
	FailureCount   int64
}

type UsageTracker struct {
	records map[string]*UsageRecord
}

func NewUsageTracker() *UsageTracker {
	return &UsageTracker{
		records: make(map[string]*UsageRecord),
	}
}

func (t *UsageTracker) Track(event Event) {
	if !isServiceAccountUser(event.User.Username) {
		return
	}

	key := t.recordKey(event)
	record, exists := t.records[key]

	if !exists {
		record = &UsageRecord{
			ServiceAccount: extractServiceAccount(event.User.Username),
			Namespace:      event.ObjectRef.Namespace,
			Resource:       event.ObjectRef.Resource,
			Verb:           event.Verb,
			APIGroup:       event.ObjectRef.APIGroup,
			FirstSeen:      event.Timestamp,
		}
		t.records[key] = record
	}

	record.Count++
	record.LastSeen = event.Timestamp

	if event.ResponseStatus.Code >= 200 && event.ResponseStatus.Code < 300 {
		record.SuccessCount++
	} else {
		record.FailureCount++
	}
}

func (t *UsageTracker) recordKey(event Event) string {
	return event.User.Username + ":" + event.ObjectRef.Namespace + ":" + event.ObjectRef.Resource + ":" + event.Verb
}

func (t *UsageTracker) GetRecords() []*UsageRecord {
	records := make([]*UsageRecord, 0, len(t.records))
	for _, r := range t.records {
		records = append(records, r)
	}
	return records
}

func (t *UsageTracker) GetRecordsForSA(saNamespace, saName string) []*UsageRecord {
	saKey := "system:serviceaccount:" + saNamespace + ":" + saName
	var records []*UsageRecord
	for _, r := range t.records {
		if r.ServiceAccount == saKey {
			records = append(records, r)
		}
	}
	return records
}

func (t *UsageTracker) GetUnusedPermissions(grantedPerms []GrantedPermission, since time.Duration) []UnusedPermission {
	var unused []UnusedPermission
	cutoff := time.Now().Add(-since)

	for _, granted := range grantedPerms {
		used := false
		var lastUsed time.Time

		for _, record := range t.records {
			if matchesPermission(granted, record) {
				used = true
				if record.LastSeen.After(lastUsed) {
					lastUsed = record.LastSeen
				}
			}
		}

		if !used || lastUsed.Before(cutoff) {
			unused = append(unused, UnusedPermission{
				ServiceAccount: granted.ServiceAccount,
				Namespace:      granted.Namespace,
				Resource:       granted.Resource,
				Verb:           granted.Verb,
				ViaRole:        granted.ViaRole,
				NeverUsed:      !used,
				LastUsed:       lastUsed,
				DaysSinceUse:   int(time.Since(lastUsed).Hours() / 24),
			})
		}
	}

	return unused
}

type GrantedPermission struct {
	ServiceAccount string
	Namespace      string
	Resource       string
	Verb           string
	ViaRole        string
	APIGroup       string
}

type UnusedPermission struct {
	ServiceAccount string
	Namespace      string
	Resource       string
	Verb           string
	ViaRole        string
	NeverUsed      bool
	LastUsed       time.Time
	DaysSinceUse   int
}

func matchesPermission(granted GrantedPermission, record *UsageRecord) bool {
	if granted.ServiceAccount != record.ServiceAccount {
		return false
	}

	if granted.Namespace != "" && granted.Namespace != record.Namespace {
		return false
	}

	resourceMatch := granted.Resource == record.Resource ||
		granted.Resource == "*" ||
		(len(granted.Resource) > 0 && granted.Resource[len(granted.Resource)-1] == '*' &&
			len(record.Resource) >= len(granted.Resource)-1 &&
			record.Resource[:len(granted.Resource)-1] == granted.Resource[:len(granted.Resource)-1])

	if !resourceMatch {
		return false
	}

	verbMatch := granted.Verb == record.Verb || granted.Verb == "*"
	return verbMatch
}

func isServiceAccountUser(username string) bool {
	return len(username) > 22 && username[:22] == "system:serviceaccount:"
}

func extractServiceAccount(username string) string {
	return username
}

type AuditSummary struct {
	TotalEvents       int64
	UniqueUsers       int
	UniqueResources   int
	TimeRange         TimeRange
	TopResources      []ResourceCount
	TopUsers          []UserCount
	VerbDistribution  map[string]int64
	FailureRate       float64
}

type TimeRange struct {
	Start time.Time
	End   time.Time
}

type ResourceCount struct {
	Resource  string
	Namespace string
	Count     int64
}

type UserCount struct {
	User  string
	Count int64
}

func (t *UsageTracker) Summarize() *AuditSummary {
	summary := &AuditSummary{
		VerbDistribution: make(map[string]int64),
	}

	users := make(map[string]int64)
	resources := make(map[string]int64)
	var totalSuccess, totalFailure int64

	for _, record := range t.records {
		summary.TotalEvents += record.Count
		users[record.ServiceAccount] += record.Count
		resources[record.Namespace+"/"+record.Resource] += record.Count
		summary.VerbDistribution[record.Verb] += record.Count
		totalSuccess += record.SuccessCount
		totalFailure += record.FailureCount

		if summary.TimeRange.Start.IsZero() || record.FirstSeen.Before(summary.TimeRange.Start) {
			summary.TimeRange.Start = record.FirstSeen
		}
		if record.LastSeen.After(summary.TimeRange.End) {
			summary.TimeRange.End = record.LastSeen
		}
	}

	summary.UniqueUsers = len(users)
	summary.UniqueResources = len(resources)

	if totalSuccess+totalFailure > 0 {
		summary.FailureRate = float64(totalFailure) / float64(totalSuccess+totalFailure)
	}

	for user, count := range users {
		summary.TopUsers = append(summary.TopUsers, UserCount{User: user, Count: count})
	}

	for resource, count := range resources {
		parts := splitOnce(resource, "/")
		summary.TopResources = append(summary.TopResources, ResourceCount{
			Namespace: parts[0],
			Resource:  parts[1],
			Count:     count,
		})
	}

	return summary
}

func splitOnce(s, sep string) [2]string {
	for i := 0; i < len(s); i++ {
		if i+len(sep) <= len(s) && s[i:i+len(sep)] == sep {
			return [2]string{s[:i], s[i+len(sep):]}
		}
	}
	return [2]string{s, ""}
}
