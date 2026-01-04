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
