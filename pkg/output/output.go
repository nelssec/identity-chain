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

// WriterOptions configures format-specific writer behavior.
type WriterOptions struct {
	Verbose bool
	NoColor bool
	Compact bool // JSON compact mode (no indentation)
}

func NewWriter(w io.Writer, format Format) Writer {
	return NewWriterWithOptions(w, format, WriterOptions{})
}

func NewWriterWithOptions(w io.Writer, format Format, opts WriterOptions) Writer {
	switch format {
	case FormatJSON:
		return NewJSONWriterWithOptions(w, JSONOptions{Compact: opts.Compact})
	case FormatDOT:
		return NewDOTWriter(w)
	default:
		return NewTableWriterWithOptions(w, TableOptions{
			Verbose: opts.Verbose,
			NoColor: opts.NoColor,
		})
	}
}
