package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/nelssec/identity-chain/pkg/analysis"
	"github.com/nelssec/identity-chain/pkg/graph"
)

// SARIFWriter writes findings in SARIF 2.1.0 format.
type SARIFWriter struct {
	w       io.Writer
	version string
}

// NewSARIFWriter returns a SARIF writer for exporting findings.
func NewSARIFWriter(w io.Writer, version string) *SARIFWriter {
	return &SARIFWriter{w: w, version: version}
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
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
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name,omitempty"`
	ShortDescription sarifMessage        `json:"shortDescription,omitempty"`
	DefaultConfig    sarifDefaultConfig  `json:"defaultConfiguration,omitempty"`
}

type sarifDefaultConfig struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID  string       `json:"ruleId"`
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
}

func severityToSARIFLevel(sev graph.Severity) string {
	switch sev {
	case graph.SeverityCritical, graph.SeverityHigh:
		return "error"
	case graph.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// WriteCombinedResults writes RBAC, pod security, network policy, and cloud IAM results as SARIF.
func (sw *SARIFWriter) WriteCombinedResults(
	rbac *analysis.RBACAuditResult,
	podSec *analysis.PodSecurityResult,
	netPol *analysis.NetworkPolicyResult,
	cloud *analysis.CloudIAMAuditResult,
) error {
	var results []sarifResult
	var rules []sarifRule
	ruleSet := map[string]bool{}

	addRule := func(id string, title string, sev graph.Severity) {
		if ruleSet[id] {
			return
		}
		ruleSet[id] = true
		rules = append(rules, sarifRule{
			ID:               id,
			Name:             title,
			ShortDescription: sarifMessage{Text: title},
			DefaultConfig:    sarifDefaultConfig{Level: severityToSARIFLevel(sev)},
		})
	}

	if rbac != nil {
		for _, f := range rbac.Findings {
			addRule(f.CheckID, f.Title, f.Severity)
			desc := f.Description
			for _, a := range f.Affected {
				if a.Details != "" {
					desc += " — " + a.Details
					break
				}
			}
			results = append(results, sarifResult{
				RuleID:  f.CheckID,
				Level:   severityToSARIFLevel(f.Severity),
				Message: sarifMessage{Text: desc},
			})
		}
	}

	if podSec != nil {
		for _, f := range podSec.Findings {
			addRule(f.CheckID, f.Title, f.Severity)
			results = append(results, sarifResult{
				RuleID:  f.CheckID,
				Level:   severityToSARIFLevel(f.Severity),
				Message: sarifMessage{Text: f.Description},
			})
		}
	}

	if netPol != nil {
		for _, f := range netPol.Findings {
			addRule(f.CheckID, f.Title, f.Severity)
			results = append(results, sarifResult{
				RuleID:  f.CheckID,
				Level:   severityToSARIFLevel(f.Severity),
				Message: sarifMessage{Text: f.Description},
			})
		}
	}

	if cloud != nil {
		for i, f := range cloud.Findings {
			ruleID := fmt.Sprintf("CLOUD%03d", i+1)
			addRule(ruleID, f.Title, f.Severity)
			results = append(results, sarifResult{
				RuleID:  ruleID,
				Level:   severityToSARIFLevel(f.Severity),
				Message: sarifMessage{Text: f.Description},
			})
		}
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "identity-chain",
						Version:        sw.version,
						InformationURI: "https://github.com/nelssec/identity-chain",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(sw.w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
