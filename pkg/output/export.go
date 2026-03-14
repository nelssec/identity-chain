package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/nelssec/identity-chain/pkg/analysis"
	"github.com/nelssec/identity-chain/pkg/graph"
)

// ExportHTMLData holds all data needed for the self-contained HTML export.
type ExportHTMLData struct {
	ClusterName  string
	Version      string
	BlastResults []*analysis.BlastResult
	RBACAudit    *analysis.RBACAuditResult
	PodSecurity  *analysis.PodSecurityResult
	NetworkPolicy *analysis.NetworkPolicyResult
	CloudAudit   *analysis.CloudIAMAuditResult
	AttackPaths  []*analysis.AttackPathResult
}

// ExportHTML writes a self-contained HTML report to the given writer.
func ExportHTML(w io.Writer, data ExportHTMLData) error {
	// Compute summary stats
	totalFindings := 0
	critical := 0
	high := 0
	medium := 0
	low := 0
	nsCounts := map[string]int{}

	countSeverity := func(sev string) {
		totalFindings++
		switch strings.ToLower(sev) {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		case "low":
			low++
		}
	}

	if data.RBACAudit != nil {
		for _, f := range data.RBACAudit.Findings {
			countSeverity(string(f.Severity))
		}
	}
	if data.PodSecurity != nil {
		for _, f := range data.PodSecurity.Findings {
			countSeverity(string(f.Severity))
		}
	}
	if data.NetworkPolicy != nil {
		for _, f := range data.NetworkPolicy.Findings {
			countSeverity(string(f.Severity))
		}
	}
	if data.CloudAudit != nil {
		for _, f := range data.CloudAudit.Findings {
			countSeverity(string(f.Severity))
		}
	}

	// Top namespaces from blast results
	for _, r := range data.BlastResults {
		if r.SourceWorkload != nil {
			nsCounts[r.SourceWorkload.Namespace]++
		}
	}

	// Build finding cards JSON
	type findingJSON struct {
		ID          string `json:"id"`
		Severity    string `json:"severity"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Remediation string `json:"remediation"`
		Category    string `json:"category"`
	}

	var findings []findingJSON
	if data.RBACAudit != nil {
		for _, f := range data.RBACAudit.Findings {
			findings = append(findings, findingJSON{
				ID: f.CheckID, Severity: string(f.Severity), Title: f.Title,
				Description: f.Description, Remediation: f.Remediation, Category: "RBAC",
			})
		}
	}
	if data.PodSecurity != nil {
		for _, f := range data.PodSecurity.Findings {
			findings = append(findings, findingJSON{
				ID: f.CheckID, Severity: string(f.Severity), Title: f.Title,
				Description: f.Description, Remediation: f.Remediation, Category: "Pod Security",
			})
		}
	}
	if data.NetworkPolicy != nil {
		for _, f := range data.NetworkPolicy.Findings {
			findings = append(findings, findingJSON{
				ID: f.CheckID, Severity: string(f.Severity), Title: f.Title,
				Description: f.Description, Remediation: f.Remediation, Category: "Network Policy",
			})
		}
	}
	if data.CloudAudit != nil {
		for _, f := range data.CloudAudit.Findings {
			findings = append(findings, findingJSON{
				ID: string(f.Category), Severity: string(f.Severity), Title: f.Title,
				Description: f.Description, Remediation: f.Remediation, Category: "Cloud IAM",
			})
		}
	}

	// Build blast radius chains for top 5 critical findings
	type chainNode struct {
		Label string `json:"label"`
		Type  string `json:"type"`
	}
	type chainLink struct {
		SA       string      `json:"sa"`
		Nodes    []chainNode `json:"nodes"`
		Severity string      `json:"severity"`
	}
	var chains []chainLink

	critCount := 0
	for _, r := range data.BlastResults {
		if r.MaxSeverity != graph.SeverityCritical || critCount >= 5 {
			continue
		}
		critCount++
		saName := "unknown"
		if r.ServiceAccount != nil {
			saName = r.ServiceAccount.Namespace + "/" + r.ServiceAccount.Name
		}
		var nodes []chainNode
		for _, res := range r.K8sResources {
			if len(nodes) >= 5 {
				break
			}
			nodes = append(nodes, chainNode{
				Label: res.ViaRole + " → " + res.Resource.Name,
				Type:  "k8s",
			})
		}
		for _, cr := range r.CloudRoles {
			if len(nodes) >= 5 {
				break
			}
			nodes = append(nodes, chainNode{Label: cr.RoleARN, Type: "cloud"})
		}
		chains = append(chains, chainLink{SA: saName, Nodes: nodes, Severity: string(r.MaxSeverity)})
	}

	findingsJSON, _ := json.Marshal(findings)
	chainsJSON, _ := json.Marshal(chains)

	clusterName := data.ClusterName
	if clusterName == "" {
		clusterName = "unknown"
	}
	version := data.Version
	if version == "" {
		version = "0.3.1"
	}

	// Build the donut chart SVG
	donutSVG := buildDonutSVG(critical, high, medium, low)

	_, err := fmt.Fprintf(w, exportHTMLTemplate,
		clusterName,
		time.Now().UTC().Format(time.RFC3339),
		totalFindings, critical, high, medium, low,
		donutSVG,
		string(findingsJSON),
		string(chainsJSON),
		version, clusterName, time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
	)
	return err
}

func buildDonutSVG(critical, high, medium, low int) string {
	total := critical + high + medium + low
	if total == 0 {
		return `<svg viewBox="0 0 120 120" width="200" height="200"><circle cx="60" cy="60" r="50" fill="none" stroke="#ddd" stroke-width="20"/><text x="60" y="65" text-anchor="middle" font-size="16" fill="#666">0</text></svg>`
	}

	type segment struct {
		value int
		color string
		label string
	}
	segs := []segment{
		{critical, "#dc3545", "Critical"},
		{high, "#fd7e14", "High"},
		{medium, "#ffc107", "Medium"},
		{low, "#17a2b8", "Low"},
	}

	circumference := 314.159 // 2 * pi * 50
	var parts []string
	offset := 0.0
	for _, s := range segs {
		if s.value == 0 {
			continue
		}
		pct := float64(s.value) / float64(total)
		dashLen := pct * circumference
		gapLen := circumference - dashLen
		parts = append(parts, fmt.Sprintf(
			`<circle cx="60" cy="60" r="50" fill="none" stroke="%s" stroke-width="20" stroke-dasharray="%.2f %.2f" stroke-dashoffset="%.2f" transform="rotate(-90 60 60)"/>`,
			s.color, dashLen, gapLen, -offset))
		offset += dashLen
	}

	return fmt.Sprintf(`<svg viewBox="0 0 120 120" width="200" height="200">%s<text x="60" y="65" text-anchor="middle" font-size="16" font-weight="bold" fill="#333">%d</text></svg>`,
		strings.Join(parts, "\n"), total)
}

const exportHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Identity Chain Security Report — %s</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f7fa;color:#333;display:flex;min-height:100vh}
.sidebar{width:240px;background:#1a1a2e;color:#eee;padding:20px;position:fixed;height:100vh;overflow-y:auto}
.sidebar h2{font-size:16px;margin-bottom:20px;color:#fff}
.sidebar a{display:block;padding:10px 12px;color:#ccc;text-decoration:none;border-radius:6px;margin-bottom:4px;font-size:14px}
.sidebar a:hover,.sidebar a.active{background:#16213e;color:#fff}
.main{margin-left:240px;padding:30px;flex:1}
.timestamp{font-size:12px;color:#888;margin-top:4px}
.summary-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:16px;margin-bottom:30px}
.card{background:#fff;border-radius:10px;padding:20px;box-shadow:0 2px 8px rgba(0,0,0,.06);text-align:center}
.card .value{font-size:28px;font-weight:700}
.card .label{font-size:12px;color:#888;margin-top:4px}
.card.critical .value{color:#dc3545}
.card.high .value{color:#fd7e14}
.card.medium .value{color:#ffc107}
.card.low .value{color:#17a2b8}
.section{background:#fff;border-radius:10px;padding:24px;margin-bottom:24px;box-shadow:0 2px 8px rgba(0,0,0,.06);display:none}
.section.active{display:block}
.section h3{margin-bottom:16px;font-size:18px}
.badge{display:inline-block;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:600;color:#fff;text-transform:uppercase}
.badge.critical{background:#dc3545}
.badge.high{background:#fd7e14}
.badge.medium{background:#ffc107;color:#333}
.badge.low{background:#17a2b8}
.finding-card{border:1px solid #e9ecef;border-radius:8px;margin-bottom:12px;overflow:hidden}
.finding-header{padding:12px 16px;cursor:pointer;display:flex;align-items:center;gap:10px;background:#fafbfc}
.finding-header:hover{background:#f0f2f5}
.finding-body{padding:16px;border-top:1px solid #e9ecef;display:none}
.finding-body.open{display:block}
.finding-body p{margin-bottom:8px;font-size:14px;line-height:1.5}
.finding-body .remediation{background:#e8f5e9;padding:10px 14px;border-radius:6px;font-size:13px;margin-top:8px}
.donut-wrap{display:flex;align-items:center;gap:24px;margin-bottom:20px}
.legend{display:flex;flex-direction:column;gap:6px}
.legend-item{display:flex;align-items:center;gap:8px;font-size:13px}
.legend-dot{width:12px;height:12px;border-radius:50%%}
.chain-graph{margin-top:12px;padding:12px;background:#fafbfc;border-radius:8px;font-size:13px}
.chain-node{display:inline-block;padding:4px 10px;border-radius:4px;margin:2px 4px;font-size:12px}
.chain-node.k8s{background:#e3f2fd;color:#1565c0}
.chain-node.cloud{background:#fce4ec;color:#c62828}
.chain-arrow{color:#999;margin:0 2px}
footer{text-align:center;color:#999;font-size:12px;padding:20px 0;margin-top:20px;border-top:1px solid #eee}
</style>
</head>
<body>
<nav class="sidebar">
<h2>Identity Chain</h2>
<a href="#" class="active" onclick="showSection('overview')">Overview</a>
<a href="#" onclick="showSection('findings')">Findings</a>
<a href="#" onclick="showSection('blast')">Blast Radius</a>
</nav>
<div class="main">
<h1>Security Scan Report</h1>
<p class="timestamp">Generated: %s</p>

<div id="section-overview" class="section active">
<div class="summary-cards">
<div class="card"><div class="value">%d</div><div class="label">Total Findings</div></div>
<div class="card critical"><div class="value">%d</div><div class="label">Critical</div></div>
<div class="card high"><div class="value">%d</div><div class="label">High</div></div>
<div class="card medium"><div class="value">%d</div><div class="label">Medium</div></div>
<div class="card low"><div class="value">%d</div><div class="label">Low</div></div>
</div>
<h3>Severity Distribution</h3>
<div class="donut-wrap">
%s
<div class="legend">
<div class="legend-item"><div class="legend-dot" style="background:#dc3545"></div>Critical</div>
<div class="legend-item"><div class="legend-dot" style="background:#fd7e14"></div>High</div>
<div class="legend-item"><div class="legend-dot" style="background:#ffc107"></div>Medium</div>
<div class="legend-item"><div class="legend-dot" style="background:#17a2b8"></div>Low</div>
</div>
</div>
</div>

<div id="section-findings" class="section">
<h3>All Findings</h3>
<div id="findings-list"></div>
</div>

<div id="section-blast" class="section">
<h3>Blast Radius — Top Critical Chains</h3>
<div id="chains-list"></div>
</div>

<footer>identity-chain v%s | Cluster: %s | Scan: %s</footer>
</div>
<script>
var findings = %s;
var chains = %s;

function showSection(id) {
  document.querySelectorAll('.section').forEach(function(s){s.classList.remove('active')});
  document.getElementById('section-'+id).classList.add('active');
  document.querySelectorAll('.sidebar a').forEach(function(a){a.classList.remove('active')});
  event.target.classList.add('active');
}

function renderFindings() {
  var el = document.getElementById('findings-list');
  if (!findings || findings.length===0) { el.innerHTML='<p>No findings.</p>'; return; }
  var html = '';
  findings.forEach(function(f, i) {
    html += '<div class="finding-card">' +
      '<div class="finding-header" onclick="toggleFinding('+i+')">' +
      '<span class="badge '+f.severity+'">'+f.severity+'</span>' +
      '<strong>'+f.id+'</strong> '+f.title+' <span style="margin-left:auto;color:#999;font-size:12px">'+f.category+'</span>' +
      '</div>' +
      '<div class="finding-body" id="fb-'+i+'">' +
      '<p>'+f.description+'</p>' +
      (f.remediation ? '<div class="remediation"><strong>Remediation:</strong> '+f.remediation+'</div>' : '') +
      '</div></div>';
  });
  el.innerHTML = html;
}

function toggleFinding(i) {
  var el = document.getElementById('fb-'+i);
  el.classList.toggle('open');
}

function renderChains() {
  var el = document.getElementById('chains-list');
  if (!chains || chains.length===0) { el.innerHTML='<p>No critical chains found.</p>'; return; }
  var html = '';
  chains.forEach(function(c) {
    html += '<div class="chain-graph"><strong>'+c.sa+'</strong>';
    c.nodes.forEach(function(n) {
      html += ' <span class="chain-arrow">→</span> <span class="chain-node '+n.type+'">'+n.label+'</span>';
    });
    html += '</div>';
  });
  el.innerHTML = html;
}

renderFindings();
renderChains();
</script>
</body>
</html>`
