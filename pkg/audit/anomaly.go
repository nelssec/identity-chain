package audit

import (
	"sort"
	"strings"
	"time"
)

type AnomalyDetector struct {
	baseline      *BehaviorBaseline
	thresholds    AnomalyThresholds
	observations  []Event
	windowSize    time.Duration
}

type AnomalyThresholds struct {
	UnusualHourStart       int
	UnusualHourEnd         int
	HighVolumeMultiplier   float64
	FailureRateThreshold   float64
	SensitiveResourceAccess bool
}

type BehaviorBaseline struct {
	SAProfiles    map[string]*SABehaviorProfile
	GlobalStats   GlobalBehaviorStats
	BaselineStart time.Time
	BaselineEnd   time.Time
}

type SABehaviorProfile struct {
	ServiceAccount    string
	AverageCallsPerHour float64
	CommonResources   map[string]int
	CommonVerbs       map[string]int
	UsualHours        map[int]int
	FailureRate       float64
	TotalCalls        int64
}

type GlobalBehaviorStats struct {
	TotalEvents           int64
	AverageEventsPerHour  float64
	TopResources          map[string]int64
	TopVerbs              map[string]int64
}

type AnomalyFinding struct {
	Timestamp   time.Time
	Type        AnomalyType
	Severity    string
	ServiceAccount string
	Description string
	Event       *Event
	Score       float64
	Context     map[string]interface{}
}

type AnomalyType string

const (
	AnomalyUnusualTime       AnomalyType = "unusual_time"
	AnomalyHighVolume        AnomalyType = "high_volume"
	AnomalyNewResource       AnomalyType = "new_resource"
	AnomalyNewVerb           AnomalyType = "new_verb"
	AnomalyHighFailureRate   AnomalyType = "high_failure_rate"
	AnomalySensitiveAccess   AnomalyType = "sensitive_access"
	AnomalyLateralMovement   AnomalyType = "lateral_movement"
	AnomalyPrivilegeEscalation AnomalyType = "privilege_escalation"
	AnomalyDataExfiltration  AnomalyType = "data_exfiltration"
	AnomalyCredentialAccess  AnomalyType = "credential_access"
)

func NewAnomalyDetector(windowSize time.Duration) *AnomalyDetector {
	return &AnomalyDetector{
		baseline: &BehaviorBaseline{
			SAProfiles: make(map[string]*SABehaviorProfile),
		},
		thresholds: AnomalyThresholds{
			UnusualHourStart:      22,
			UnusualHourEnd:        6,
			HighVolumeMultiplier:  3.0,
			FailureRateThreshold:  0.3,
			SensitiveResourceAccess: true,
		},
		windowSize: windowSize,
	}
}

func (d *AnomalyDetector) SetThresholds(t AnomalyThresholds) {
	d.thresholds = t
}

func (d *AnomalyDetector) BuildBaseline(events []Event) {
	d.baseline = &BehaviorBaseline{
		SAProfiles: make(map[string]*SABehaviorProfile),
		GlobalStats: GlobalBehaviorStats{
			TopResources: make(map[string]int64),
			TopVerbs:     make(map[string]int64),
		},
	}

	if len(events) == 0 {
		return
	}

	d.baseline.BaselineStart = events[0].Timestamp
	d.baseline.BaselineEnd = events[len(events)-1].Timestamp

	for _, event := range events {
		if !isServiceAccountUser(event.User.Username) {
			continue
		}

		d.baseline.GlobalStats.TotalEvents++
		d.baseline.GlobalStats.TopResources[event.ObjectRef.Resource]++
		d.baseline.GlobalStats.TopVerbs[event.Verb]++

		saKey := event.User.Username
		profile, exists := d.baseline.SAProfiles[saKey]
		if !exists {
			profile = &SABehaviorProfile{
				ServiceAccount:  saKey,
				CommonResources: make(map[string]int),
				CommonVerbs:     make(map[string]int),
				UsualHours:      make(map[int]int),
			}
			d.baseline.SAProfiles[saKey] = profile
		}

		profile.TotalCalls++
		profile.CommonResources[event.ObjectRef.Resource]++
		profile.CommonVerbs[event.Verb]++
		profile.UsualHours[event.Timestamp.Hour()]++

		if event.ResponseStatus.Code >= 400 {
			profile.FailureRate = (profile.FailureRate*float64(profile.TotalCalls-1) + 1) / float64(profile.TotalCalls)
		} else {
			profile.FailureRate = (profile.FailureRate * float64(profile.TotalCalls-1)) / float64(profile.TotalCalls)
		}
	}

	duration := d.baseline.BaselineEnd.Sub(d.baseline.BaselineStart)
	hours := duration.Hours()
	if hours > 0 {
		d.baseline.GlobalStats.AverageEventsPerHour = float64(d.baseline.GlobalStats.TotalEvents) / hours
		for _, profile := range d.baseline.SAProfiles {
			profile.AverageCallsPerHour = float64(profile.TotalCalls) / hours
		}
	}
}

func (d *AnomalyDetector) Detect(event Event) []AnomalyFinding {
	var findings []AnomalyFinding

	if !isServiceAccountUser(event.User.Username) {
		return findings
	}

	saKey := event.User.Username
	profile := d.baseline.SAProfiles[saKey]

	findings = append(findings, d.detectTimeAnomaly(event, profile)...)
	findings = append(findings, d.detectResourceAnomaly(event, profile)...)
	findings = append(findings, d.detectVerbAnomaly(event, profile)...)
	findings = append(findings, d.detectSensitiveAccess(event)...)
	findings = append(findings, d.detectLateralMovement(event)...)
	findings = append(findings, d.detectPrivilegeEscalation(event)...)
	findings = append(findings, d.detectCredentialAccess(event)...)

	return findings
}

func (d *AnomalyDetector) detectTimeAnomaly(event Event, profile *SABehaviorProfile) []AnomalyFinding {
	var findings []AnomalyFinding

	hour := event.Timestamp.Hour()
	isUnusualHour := hour >= d.thresholds.UnusualHourStart || hour < d.thresholds.UnusualHourEnd

	if isUnusualHour {
		score := 0.5
		if profile != nil && profile.UsualHours[hour] == 0 {
			score = 0.8
		}

		findings = append(findings, AnomalyFinding{
			Timestamp:      event.Timestamp,
			Type:           AnomalyUnusualTime,
			Severity:       "medium",
			ServiceAccount: event.User.Username,
			Description:    "Activity detected during unusual hours",
			Event:          &event,
			Score:          score,
			Context: map[string]interface{}{
				"hour":     hour,
				"resource": event.ObjectRef.Resource,
				"verb":     event.Verb,
			},
		})
	}

	return findings
}

func (d *AnomalyDetector) detectResourceAnomaly(event Event, profile *SABehaviorProfile) []AnomalyFinding {
	var findings []AnomalyFinding

	if profile != nil && profile.CommonResources[event.ObjectRef.Resource] == 0 {
		findings = append(findings, AnomalyFinding{
			Timestamp:      event.Timestamp,
			Type:           AnomalyNewResource,
			Severity:       "low",
			ServiceAccount: event.User.Username,
			Description:    "Access to previously unused resource type",
			Event:          &event,
			Score:          0.4,
			Context: map[string]interface{}{
				"resource": event.ObjectRef.Resource,
				"verb":     event.Verb,
			},
		})
	}

	return findings
}

func (d *AnomalyDetector) detectVerbAnomaly(event Event, profile *SABehaviorProfile) []AnomalyFinding {
	var findings []AnomalyFinding

	if profile != nil && profile.CommonVerbs[event.Verb] == 0 {
		severity := "low"
		score := 0.3

		if event.Verb == "delete" || event.Verb == "deletecollection" {
			severity = "high"
			score = 0.7
		} else if event.Verb == "create" || event.Verb == "patch" || event.Verb == "update" {
			severity = "medium"
			score = 0.5
		}

		findings = append(findings, AnomalyFinding{
			Timestamp:      event.Timestamp,
			Type:           AnomalyNewVerb,
			Severity:       severity,
			ServiceAccount: event.User.Username,
			Description:    "Service account used a new verb for the first time",
			Event:          &event,
			Score:          score,
			Context: map[string]interface{}{
				"verb":     event.Verb,
				"resource": event.ObjectRef.Resource,
			},
		})
	}

	return findings
}

func (d *AnomalyDetector) detectSensitiveAccess(event Event) []AnomalyFinding {
	var findings []AnomalyFinding

	if !d.thresholds.SensitiveResourceAccess {
		return findings
	}

	sensitiveResources := map[string]string{
		"secrets":                "critical",
		"serviceaccounts/token":  "critical",
		"certificatesigningrequests": "high",
		"roles":                  "high",
		"clusterroles":           "high",
		"rolebindings":           "high",
		"clusterrolebindings":    "high",
		"nodes":                  "high",
		"persistentvolumes":      "medium",
	}

	if severity, isSensitive := sensitiveResources[event.ObjectRef.Resource]; isSensitive {
		if event.ResponseStatus.Code >= 200 && event.ResponseStatus.Code < 300 {
			findings = append(findings, AnomalyFinding{
				Timestamp:      event.Timestamp,
				Type:           AnomalySensitiveAccess,
				Severity:       severity,
				ServiceAccount: event.User.Username,
				Description:    "Access to sensitive resource",
				Event:          &event,
				Score:          0.6,
				Context: map[string]interface{}{
					"resource":  event.ObjectRef.Resource,
					"verb":      event.Verb,
					"namespace": event.ObjectRef.Namespace,
					"name":      event.ObjectRef.Name,
				},
			})
		}
	}

	return findings
}

func (d *AnomalyDetector) detectLateralMovement(event Event) []AnomalyFinding {
	var findings []AnomalyFinding

	lateralIndicators := map[string]bool{
		"pods/exec":       true,
		"pods/attach":     true,
		"pods/portforward": true,
	}

	if lateralIndicators[event.ObjectRef.Resource] {
		findings = append(findings, AnomalyFinding{
			Timestamp:      event.Timestamp,
			Type:           AnomalyLateralMovement,
			Severity:       "high",
			ServiceAccount: event.User.Username,
			Description:    "Potential lateral movement activity",
			Event:          &event,
			Score:          0.7,
			Context: map[string]interface{}{
				"resource":  event.ObjectRef.Resource,
				"namespace": event.ObjectRef.Namespace,
				"pod":       event.ObjectRef.Name,
			},
		})
	}

	return findings
}

func (d *AnomalyDetector) detectPrivilegeEscalation(event Event) []AnomalyFinding {
	var findings []AnomalyFinding

	privEscPatterns := map[string][]string{
		"rolebindings":        {"create", "update", "patch"},
		"clusterrolebindings": {"create", "update", "patch"},
		"roles":               {"create", "update", "patch", "escalate", "bind"},
		"clusterroles":        {"create", "update", "patch", "escalate", "bind"},
		"serviceaccounts/token": {"create"},
	}

	if verbs, exists := privEscPatterns[event.ObjectRef.Resource]; exists {
		for _, verb := range verbs {
			if event.Verb == verb && event.ResponseStatus.Code >= 200 && event.ResponseStatus.Code < 300 {
				findings = append(findings, AnomalyFinding{
					Timestamp:      event.Timestamp,
					Type:           AnomalyPrivilegeEscalation,
					Severity:       "critical",
					ServiceAccount: event.User.Username,
					Description:    "Potential privilege escalation attempt",
					Event:          &event,
					Score:          0.9,
					Context: map[string]interface{}{
						"resource": event.ObjectRef.Resource,
						"verb":     event.Verb,
						"target":   event.ObjectRef.Name,
					},
				})
				break
			}
		}
	}

	return findings
}

func (d *AnomalyDetector) detectCredentialAccess(event Event) []AnomalyFinding {
	var findings []AnomalyFinding

	credentialResources := map[string]bool{
		"secrets":               true,
		"serviceaccounts/token": true,
		"configmaps":            true,
	}

	readVerbs := map[string]bool{
		"get":   true,
		"list":  true,
		"watch": true,
	}

	if credentialResources[event.ObjectRef.Resource] && readVerbs[event.Verb] {
		if event.ResponseStatus.Code >= 200 && event.ResponseStatus.Code < 300 {
			severity := "medium"
			score := 0.5

			if event.ObjectRef.Resource == "secrets" {
				severity = "high"
				score = 0.7
			}

			if event.ObjectRef.Name != "" && strings.Contains(strings.ToLower(event.ObjectRef.Name), "token") {
				severity = "critical"
				score = 0.85
			}

			findings = append(findings, AnomalyFinding{
				Timestamp:      event.Timestamp,
				Type:           AnomalyCredentialAccess,
				Severity:       severity,
				ServiceAccount: event.User.Username,
				Description:    "Access to credential-related resource",
				Event:          &event,
				Score:          score,
				Context: map[string]interface{}{
					"resource":  event.ObjectRef.Resource,
					"verb":      event.Verb,
					"namespace": event.ObjectRef.Namespace,
					"name":      event.ObjectRef.Name,
				},
			})
		}
	}

	return findings
}

func (d *AnomalyDetector) AnalyzeEvents(events []Event) *AnomalyReport {
	report := &AnomalyReport{
		AnalyzedEvents:  len(events),
		FindingsByType:  make(map[AnomalyType]int),
		FindingsBySA:    make(map[string]int),
	}

	for _, event := range events {
		findings := d.Detect(event)
		for _, f := range findings {
			report.Findings = append(report.Findings, f)
			report.FindingsByType[f.Type]++
			report.FindingsBySA[f.ServiceAccount]++

			switch f.Severity {
			case "critical":
				report.CriticalFindings++
			case "high":
				report.HighFindings++
			case "medium":
				report.MediumFindings++
			case "low":
				report.LowFindings++
			}
		}
	}

	sort.Slice(report.Findings, func(i, j int) bool {
		return report.Findings[i].Score > report.Findings[j].Score
	})

	return report
}

type AnomalyReport struct {
	AnalyzedEvents   int
	Findings         []AnomalyFinding
	FindingsByType   map[AnomalyType]int
	FindingsBySA     map[string]int
	CriticalFindings int
	HighFindings     int
	MediumFindings   int
	LowFindings      int
}

func (r *AnomalyReport) TopAnomalies(n int) []AnomalyFinding {
	if n >= len(r.Findings) {
		return r.Findings
	}
	return r.Findings[:n]
}

func (r *AnomalyReport) GetFindingsByType(t AnomalyType) []AnomalyFinding {
	var results []AnomalyFinding
	for _, f := range r.Findings {
		if f.Type == t {
			results = append(results, f)
		}
	}
	return results
}

func (r *AnomalyReport) GetFindingsBySA(sa string) []AnomalyFinding {
	var results []AnomalyFinding
	for _, f := range r.Findings {
		if f.ServiceAccount == sa {
			results = append(results, f)
		}
	}
	return results
}
