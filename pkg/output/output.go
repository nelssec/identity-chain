package output

import (
	"io"

	"github.com/nelssec/identity-chain/pkg/analysis"
	"github.com/nelssec/identity-chain/pkg/graph"
)

type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatDOT   Format = "dot"
	FormatHTML  Format = "html"
)

type Writer interface {
	WriteBlastResult(result *analysis.BlastResult) error
	WriteBlastResults(results []*analysis.BlastResult) error
	WriteGraph(g *graph.Graph) error
	WriteStats(stats graph.GraphStats) error
	WritePrivescResults(results []*analysis.PrivescResult) error
	WriteWhoCanResult(result *analysis.WhoCanResult) error
	WriteWhatCanResult(result *analysis.ReverseRBACResult) error
	WriteRBACAuditResult(result *analysis.RBACAuditResult) error
	WriteCloudAuditResult(result *analysis.CloudIAMAuditResult) error
	WritePodSecurityResult(result *analysis.PodSecurityResult) error
	WriteNetworkPolicyResult(result *analysis.NetworkPolicyResult) error
	WriteAttackPathResults(results []*analysis.AttackPathResult) error
}

func NewWriter(w io.Writer, format Format) Writer {
	switch format {
	case FormatJSON:
		return NewJSONWriter(w)
	case FormatDOT:
		return NewDOTWriter(w)
	case FormatHTML:
		return NewHTMLWriter(w)
	default:
		return NewTableWriter(w)
	}
}
