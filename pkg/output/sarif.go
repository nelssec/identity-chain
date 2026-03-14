package output

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/nelssec/identity-chain/pkg/analysis"
)

// ---------------------------------------------------------------------------
// SARIF Writer – Static Analysis Results Interchange Format v2.1.0
// ---------------------------------------------------------------------------
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

// SARIFWriter produces SARIF output from identity-chain analysis results.
type SARIFWriter struct {
	w           io.Writer
	toolVersion string
}

// NewSARIFWriter creates a new SARIF writer.
func NewSARIFWriter(w io.Writer, toolVersion string) *SARIFWriter {
	return &SARIFWriter{w: w, toolVersion: toolVersion}
}

// sarifDocument is the root SARIF document.
type sarifDocument struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool         `json:"tool"`
	Results    []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
}

type sarifInvocation struct {
	StartTimeUTC string `json:"startTimeUtc"`
	EndTimeUTC   string `json:"endTimeUtc"`
	ExitCode     int    `json:"exitCode"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	ShortDescription sarifMessage     `json:"shortDescription"`
	Help             *sarifHelp       `json:"help,omitempty"`
	DefaultConfig    sarifRuleConfig  `json:"defaultConfiguration"`
}

type sarifHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID       string            `json:"ruleId"`
	Level        string            `json:"level"`
	Message      sarifMessage      `json:"message"`
	Kind         string            `json:"kind"`
	Fingerprints map[string]string `json:"fingerprints,omitempty"`
}

// computeFingerprint generates a stable fingerprint for deduplication across scans.
func computeFingerprint(ruleID, message string) string {
	h := sha256.Sum256([]byte(ruleID + ":" + message))
	return fmt.Sprintf("%x", h[:16])
}

// remediationMarkdown returns remediation guidance in markdown format for a given rule.
func remediationMarkdown(ruleID, severity, title, remediation string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## %s\n\n", title))
	sb.WriteString(fmt.Sprintf("**Severity:** %s\n\n", strings.ToUpper(severity)))
	if remediation != "" {
		sb.WriteString("### Remediation Steps\n\n")
		sb.WriteString(remediation)
		sb.WriteString("\n\n")
	}
	sb.WriteString(fmt.Sprintf("### References\n\n- [identity-chain docs](https://github.com/nelssec/identity-chain)\n- Rule ID: `%s`\n", ruleID))
	return sb.String()
}

// WriteCombinedResults serialises all findings as a SARIF document.
func (s *SARIFWriter) WriteCombinedResults(
	rbac *analysis.RBACAuditResult,
	podSec *analysis.PodSecurityResult,
	netPol *analysis.NetworkPolicyResult,
	cloud *analysis.CloudIAMAuditResult,
) error {
	startTime := time.Now().UTC()

	doc := sarifDocument{
		Version: "2.1.0",
		Schema:  "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "identity-chain",
						Version:        s.toolVersion,
						InformationURI: "https://github.com/nelssec/identity-chain",
					},
				},
			},
		},
	}

	run := &doc.Runs[0]
	ruleMap := map[string]sarifRule{}

	// RBAC findings
	if rbac != nil {
		for _, f := range rbac.Findings {
			msgText := f.Title + ": " + f.Description
			fp := computeFingerprint(f.CheckID, msgText)
			run.Results = append(run.Results, sarifResult{
				RuleID:  f.CheckID,
				Level:   severityToSARIFLevel(string(f.Severity)),
				Message: sarifMessage{Text: msgText},
				Kind:    "fail",
				Fingerprints: map[string]string{
					"identity-chain/v1": fp,
				},
			})
			if _, ok := ruleMap[f.CheckID]; !ok {
				ruleMap[f.CheckID] = sarifRule{
					ID:               f.CheckID,
					Name:             f.CheckID,
					ShortDescription: sarifMessage{Text: f.Title},
					Help: &sarifHelp{
						Text:     f.Remediation,
						Markdown: remediationMarkdown(f.CheckID, string(f.Severity), f.Title, f.Remediation),
					},
					DefaultConfig: sarifRuleConfig{Level: severityToSARIFLevel(string(f.Severity))},
				}
			}
		}
	}

	// Pod security findings
	if podSec != nil {
		for _, f := range podSec.Findings {
			msgText := f.Title + ": " + f.Description
			fp := computeFingerprint(f.CheckID, msgText)
			run.Results = append(run.Results, sarifResult{
				RuleID:  f.CheckID,
				Level:   severityToSARIFLevel(string(f.Severity)),
				Message: sarifMessage{Text: msgText},
				Kind:    "fail",
				Fingerprints: map[string]string{
					"identity-chain/v1": fp,
				},
			})
			if _, ok := ruleMap[f.CheckID]; !ok {
				ruleMap[f.CheckID] = sarifRule{
					ID:               f.CheckID,
					Name:             f.CheckID,
					ShortDescription: sarifMessage{Text: f.Title},
					Help: &sarifHelp{
						Text:     f.Remediation,
						Markdown: remediationMarkdown(f.CheckID, string(f.Severity), f.Title, f.Remediation),
					},
					DefaultConfig: sarifRuleConfig{Level: severityToSARIFLevel(string(f.Severity))},
				}
			}
		}
	}

	// Network policy findings
	if netPol != nil {
		for _, f := range netPol.Findings {
			msgText := f.Title + ": " + f.Description
			fp := computeFingerprint(f.CheckID, msgText)
			run.Results = append(run.Results, sarifResult{
				RuleID:  f.CheckID,
				Level:   severityToSARIFLevel(string(f.Severity)),
				Message: sarifMessage{Text: msgText},
				Kind:    "fail",
				Fingerprints: map[string]string{
					"identity-chain/v1": fp,
				},
			})
			if _, ok := ruleMap[f.CheckID]; !ok {
				ruleMap[f.CheckID] = sarifRule{
					ID:               f.CheckID,
					Name:             f.CheckID,
					ShortDescription: sarifMessage{Text: f.Title},
					Help: &sarifHelp{
						Text:     f.Remediation,
						Markdown: remediationMarkdown(f.CheckID, string(f.Severity), f.Title, f.Remediation),
					},
					DefaultConfig: sarifRuleConfig{Level: severityToSARIFLevel(string(f.Severity))},
				}
			}
		}
	}

	// Cloud IAM findings
	if cloud != nil {
		for _, f := range cloud.Findings {
			ruleID := string(f.Category)
			msgText := f.Title + ": " + f.Description
			fp := computeFingerprint(ruleID, msgText)
			run.Results = append(run.Results, sarifResult{
				RuleID:  ruleID,
				Level:   severityToSARIFLevel(string(f.Severity)),
				Message: sarifMessage{Text: msgText},
				Kind:    "fail",
				Fingerprints: map[string]string{
					"identity-chain/v1": fp,
				},
			})
			if _, ok := ruleMap[ruleID]; !ok {
				ruleMap[ruleID] = sarifRule{
					ID:               ruleID,
					Name:             ruleID,
					ShortDescription: sarifMessage{Text: f.Title},
					Help: &sarifHelp{
						Text:     f.Remediation,
						Markdown: remediationMarkdown(ruleID, string(f.Severity), f.Title, f.Remediation),
					},
					DefaultConfig: sarifRuleConfig{Level: severityToSARIFLevel(string(f.Severity))},
				}
			}
		}
	}

	// Sort rules for deterministic output
	rules := make([]sarifRule, 0, len(ruleMap))
	for _, r := range ruleMap {
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	run.Tool.Driver.Rules = rules

	if run.Results == nil {
		run.Results = []sarifResult{}
	}

	endTime := time.Now().UTC()
	run.Invocations = []sarifInvocation{
		{
			StartTimeUTC: startTime.Format(time.RFC3339),
			EndTimeUTC:   endTime.Format(time.RFC3339),
			ExitCode:     0,
		},
	}

	enc := json.NewEncoder(s.w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func severityToSARIFLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "none"
	}
}
