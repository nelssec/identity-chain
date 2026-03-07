package output

import (
	"encoding/json"
	"io"
	"time"

	"github.com/nelssec/identity-chain/pkg/analysis"
)

// ---------------------------------------------------------------------------
// SARIF Writer – Static Analysis Results Interchange Format v2.1.0
// ---------------------------------------------------------------------------
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

// SARIFWriter produces SARIF output from identity-chain analysis results.
type SARIFWriter struct {
	w          io.Writer
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
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	InformationURI  string      `json:"informationUri"`
	Rules           []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	DefaultConfig    sarifRuleConfig     `json:"defaultConfiguration"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID  string        `json:"ruleId"`
	Level   string        `json:"level"`
	Message sarifMessage  `json:"message"`
	Kind    string        `json:"kind"`
}

// WriteCombinedResults serialises all findings as a SARIF document.
func (s *SARIFWriter) WriteCombinedResults(
	rbac *analysis.RBACAuditResult,
	podSec *analysis.PodSecurityResult,
	netPol *analysis.NetworkPolicyResult,
	cloud *analysis.CloudIAMAuditResult,
) error {
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

	// RBAC findings
	if rbac != nil {
		for _, f := range rbac.Findings {
			run.Results = append(run.Results, sarifResult{
				RuleID:  f.CheckID,
				Level:   severityToSARIFLevel(string(f.Severity)),
				Message: sarifMessage{Text: f.Title + ": " + f.Description},
				Kind:    "fail",
			})
		}
	}

	// Pod security findings
	if podSec != nil {
		for _, f := range podSec.Findings {
			run.Results = append(run.Results, sarifResult{
				RuleID:  f.CheckID,
				Level:   severityToSARIFLevel(string(f.Severity)),
				Message: sarifMessage{Text: f.Title + ": " + f.Description},
				Kind:    "fail",
			})
		}
	}

	// Network policy findings
	if netPol != nil {
		for _, f := range netPol.Findings {
			run.Results = append(run.Results, sarifResult{
				RuleID:  f.CheckID,
				Level:   severityToSARIFLevel(string(f.Severity)),
				Message: sarifMessage{Text: f.Title + ": " + f.Description},
				Kind:    "fail",
			})
		}
	}

	// Cloud IAM findings
	if cloud != nil {
		for _, f := range cloud.Findings {
			run.Results = append(run.Results, sarifResult{
				RuleID:  string(f.Category),
				Level:   severityToSARIFLevel(string(f.Severity)),
				Message: sarifMessage{Text: f.Title + ": " + f.Description},
				Kind:    "fail",
			})
		}
	}

	if run.Results == nil {
		run.Results = []sarifResult{}
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

// ensure time is used (for future timestamp embedding)
var _ = time.Now
