package watch

import (
	"fmt"
	"net/http"
	"os"
	"sync"
)

type Metrics struct {
	mu    sync.RWMutex
	state *WatchState
}

func NewMetrics() *Metrics {
	return &Metrics{}
}

func (m *Metrics) Update(state *WatchState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state = state
}

func (m *Metrics) Serve(addr string) {
	http.HandleFunc("/metrics", m.handler)
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	http.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		m.mu.RLock()
		hasState := m.state != nil
		m.mu.RUnlock()
		if hasState {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("not ready"))
		}
	})

	fmt.Fprintf(os.Stderr, "Metrics server listening on %s\n", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Metrics server error: %v\n", err)
	}
}

func (m *Metrics) handler(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	fmt.Fprintln(w, "# HELP idc_findings_total Total number of security findings by severity")
	fmt.Fprintln(w, "# TYPE idc_findings_total gauge")

	if m.state == nil {
		fmt.Fprintln(w, `idc_findings_total{severity="critical"} 0`)
		fmt.Fprintln(w, `idc_findings_total{severity="high"} 0`)
		fmt.Fprintln(w, `idc_findings_total{severity="medium"} 0`)
		fmt.Fprintln(w, `idc_findings_total{severity="low"} 0`)
	} else {
		fmt.Fprintf(w, "idc_findings_total{severity=\"critical\"} %d\n", m.state.Summary.CriticalCount)
		fmt.Fprintf(w, "idc_findings_total{severity=\"high\"} %d\n", m.state.Summary.HighCount)
		fmt.Fprintf(w, "idc_findings_total{severity=\"medium\"} %d\n", m.state.Summary.MediumCount)
		fmt.Fprintf(w, "idc_findings_total{severity=\"low\"} %d\n", m.state.Summary.LowCount)
	}

	fmt.Fprintln(w, "# HELP idc_resources_total Total number of resources by type")
	fmt.Fprintln(w, "# TYPE idc_resources_total gauge")

	if m.state == nil {
		fmt.Fprintln(w, `idc_resources_total{type="workload"} 0`)
		fmt.Fprintln(w, `idc_resources_total{type="serviceaccount"} 0`)
		fmt.Fprintln(w, `idc_resources_total{type="role"} 0`)
	} else {
		fmt.Fprintf(w, "idc_resources_total{type=\"workload\"} %d\n", m.state.Summary.WorkloadCount)
		fmt.Fprintf(w, "idc_resources_total{type=\"serviceaccount\"} %d\n", m.state.Summary.SACount)
		fmt.Fprintf(w, "idc_resources_total{type=\"role\"} %d\n", m.state.Summary.RoleCount)
	}

	fmt.Fprintln(w, "# HELP idc_last_analysis_timestamp_seconds Unix timestamp of last analysis")
	fmt.Fprintln(w, "# TYPE idc_last_analysis_timestamp_seconds gauge")

	if m.state == nil {
		fmt.Fprintln(w, "idc_last_analysis_timestamp_seconds 0")
	} else {
		fmt.Fprintf(w, "idc_last_analysis_timestamp_seconds %d\n", m.state.Timestamp.Unix())
	}

	fmt.Fprintln(w, "# HELP idc_rbac_findings_total RBAC findings by check ID")
	fmt.Fprintln(w, "# TYPE idc_rbac_findings_total gauge")

	if m.state != nil {
		checkCounts := make(map[string]int)
		for _, f := range m.state.RBACFindings {
			checkCounts[f.CheckID]++
		}
		for checkID, count := range checkCounts {
			fmt.Fprintf(w, "idc_rbac_findings_total{check_id=\"%s\"} %d\n", checkID, count)
		}
	}

	fmt.Fprintln(w, "# HELP idc_pod_security_findings_total Pod security findings by check ID")
	fmt.Fprintln(w, "# TYPE idc_pod_security_findings_total gauge")

	if m.state != nil {
		checkCounts := make(map[string]int)
		for _, f := range m.state.PodSecFindings {
			checkCounts[f.CheckID]++
		}
		for checkID, count := range checkCounts {
			fmt.Fprintf(w, "idc_pod_security_findings_total{check_id=\"%s\"} %d\n", checkID, count)
		}
	}

	fmt.Fprintln(w, "# HELP idc_network_policy_findings_total Network policy findings by check ID")
	fmt.Fprintln(w, "# TYPE idc_network_policy_findings_total gauge")

	if m.state != nil {
		checkCounts := make(map[string]int)
		for _, f := range m.state.NetPolFindings {
			checkCounts[f.CheckID]++
		}
		for checkID, count := range checkCounts {
			fmt.Fprintf(w, "idc_network_policy_findings_total{check_id=\"%s\"} %d\n", checkID, count)
		}
	}
}
