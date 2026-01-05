package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type Store struct {
	BaseDir string
}

type ScanResult struct {
	ID           string                 `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	ClusterName  string                 `json:"cluster_name"`
	Context      string                 `json:"context"`
	Summary      ScanSummary            `json:"summary"`
	RBACFindings int                    `json:"rbac_findings"`
	PodSecFindings int                  `json:"pod_sec_findings"`
	NetPolFindings int                  `json:"net_pol_findings"`
	CISCompliance  *CISComplianceScore  `json:"cis_compliance,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

type ScanSummary struct {
	TotalWorkloads       int            `json:"total_workloads"`
	TotalServiceAccounts int            `json:"total_service_accounts"`
	TotalRoles           int            `json:"total_roles"`
	TotalFindings        int            `json:"total_findings"`
	FindingsBySeverity   map[string]int `json:"findings_by_severity"`
	CriticalCount        int            `json:"critical_count"`
	HighCount            int            `json:"high_count"`
	MediumCount          int            `json:"medium_count"`
	LowCount             int            `json:"low_count"`
}

type CISComplianceScore struct {
	TotalControls  int     `json:"total_controls"`
	PassedControls int     `json:"passed_controls"`
	FailedControls int     `json:"failed_controls"`
	Percentage     float64 `json:"percentage"`
}

type ClusterConfig struct {
	Name        string `json:"name"`
	Context     string `json:"context"`
	KubeConfig  string `json:"kubeconfig,omitempty"`
	Description string `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

type MultiClusterConfig struct {
	Clusters []ClusterConfig `json:"clusters"`
}

type TrendData struct {
	ClusterName   string        `json:"cluster_name"`
	DataPoints    []TrendPoint  `json:"data_points"`
	TrendSummary  TrendSummary  `json:"trend_summary"`
}

type TrendPoint struct {
	Timestamp      time.Time `json:"timestamp"`
	TotalFindings  int       `json:"total_findings"`
	CriticalCount  int       `json:"critical_count"`
	HighCount      int       `json:"high_count"`
	CISCompliance  float64   `json:"cis_compliance,omitempty"`
}

type TrendSummary struct {
	FirstScan        time.Time `json:"first_scan"`
	LastScan         time.Time `json:"last_scan"`
	TotalScans       int       `json:"total_scans"`
	FindingsDelta    int       `json:"findings_delta"`
	CriticalDelta    int       `json:"critical_delta"`
	TrendDirection   string    `json:"trend_direction"`
	CISDelta         float64   `json:"cis_delta,omitempty"`
}

func NewStore(baseDir string) (*Store, error) {
	if baseDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		baseDir = filepath.Join(homeDir, ".idc")
	}

	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create store directory: %w", err)
	}

	scansDir := filepath.Join(baseDir, "scans")
	if err := os.MkdirAll(scansDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create scans directory: %w", err)
	}

	return &Store{BaseDir: baseDir}, nil
}

func (s *Store) SaveScan(result *ScanResult) error {
	if result.ID == "" {
		result.ID = fmt.Sprintf("%s-%d", result.ClusterName, result.Timestamp.Unix())
	}

	filename := fmt.Sprintf("%s.json", result.ID)
	path := filepath.Join(s.BaseDir, "scans", filename)

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal scan result: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write scan result: %w", err)
	}

	return nil
}

func (s *Store) LoadScans(clusterName string, limit int) ([]*ScanResult, error) {
	scansDir := filepath.Join(s.BaseDir, "scans")
	entries, err := os.ReadDir(scansDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read scans directory: %w", err)
	}

	var results []*ScanResult
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		path := filepath.Join(scansDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var result ScanResult
		if err := json.Unmarshal(data, &result); err != nil {
			continue
		}

		if clusterName == "" || result.ClusterName == clusterName {
			results = append(results, &result)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Timestamp.After(results[j].Timestamp)
	})

	if limit > 0 && len(results) > limit {
		results = results[:limit]
	}

	return results, nil
}

func (s *Store) GetTrend(clusterName string, since time.Duration) (*TrendData, error) {
	scans, err := s.LoadScans(clusterName, 0)
	if err != nil {
		return nil, err
	}

	if len(scans) == 0 {
		return nil, nil
	}

	cutoff := time.Now().Add(-since)
	var filtered []*ScanResult
	for _, scan := range scans {
		if scan.Timestamp.After(cutoff) {
			filtered = append(filtered, scan)
		}
	}

	if len(filtered) == 0 {
		filtered = scans[:1]
	}

	trend := &TrendData{
		ClusterName: clusterName,
	}

	for i := len(filtered) - 1; i >= 0; i-- {
		scan := filtered[i]
		point := TrendPoint{
			Timestamp:     scan.Timestamp,
			TotalFindings: scan.Summary.TotalFindings,
			CriticalCount: scan.Summary.CriticalCount,
			HighCount:     scan.Summary.HighCount,
		}
		if scan.CISCompliance != nil {
			point.CISCompliance = scan.CISCompliance.Percentage
		}
		trend.DataPoints = append(trend.DataPoints, point)
	}

	if len(trend.DataPoints) > 0 {
		first := trend.DataPoints[0]
		last := trend.DataPoints[len(trend.DataPoints)-1]

		trend.TrendSummary = TrendSummary{
			FirstScan:      first.Timestamp,
			LastScan:       last.Timestamp,
			TotalScans:     len(trend.DataPoints),
			FindingsDelta:  last.TotalFindings - first.TotalFindings,
			CriticalDelta:  last.CriticalCount - first.CriticalCount,
			CISDelta:       last.CISCompliance - first.CISCompliance,
		}

		if trend.TrendSummary.FindingsDelta < 0 {
			trend.TrendSummary.TrendDirection = "improving"
		} else if trend.TrendSummary.FindingsDelta > 0 {
			trend.TrendSummary.TrendDirection = "degrading"
		} else {
			trend.TrendSummary.TrendDirection = "stable"
		}
	}

	return trend, nil
}

func (s *Store) LoadMultiClusterConfig() (*MultiClusterConfig, error) {
	path := filepath.Join(s.BaseDir, "clusters.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read clusters config: %w", err)
	}

	var config MultiClusterConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse clusters config: %w", err)
	}

	return &config, nil
}

func (s *Store) SaveMultiClusterConfig(config *MultiClusterConfig) error {
	path := filepath.Join(s.BaseDir, "clusters.json")
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal clusters config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write clusters config: %w", err)
	}

	return nil
}

func (s *Store) GetLatestScans() (map[string]*ScanResult, error) {
	scans, err := s.LoadScans("", 0)
	if err != nil {
		return nil, err
	}

	latest := make(map[string]*ScanResult)
	for _, scan := range scans {
		if existing, ok := latest[scan.ClusterName]; !ok || scan.Timestamp.After(existing.Timestamp) {
			latest[scan.ClusterName] = scan
		}
	}

	return latest, nil
}

func (s *Store) CompareClusters() ([]ClusterComparison, error) {
	latest, err := s.GetLatestScans()
	if err != nil {
		return nil, err
	}

	var comparisons []ClusterComparison
	for name, scan := range latest {
		comp := ClusterComparison{
			ClusterName:    name,
			LastScan:       scan.Timestamp,
			TotalFindings:  scan.Summary.TotalFindings,
			CriticalCount:  scan.Summary.CriticalCount,
			HighCount:      scan.Summary.HighCount,
		}
		if scan.CISCompliance != nil {
			comp.CISCompliance = scan.CISCompliance.Percentage
		}
		comparisons = append(comparisons, comp)
	}

	sort.Slice(comparisons, func(i, j int) bool {
		return comparisons[i].CriticalCount > comparisons[j].CriticalCount
	})

	return comparisons, nil
}

type ClusterComparison struct {
	ClusterName   string    `json:"cluster_name"`
	LastScan      time.Time `json:"last_scan"`
	TotalFindings int       `json:"total_findings"`
	CriticalCount int       `json:"critical_count"`
	HighCount     int       `json:"high_count"`
	CISCompliance float64   `json:"cis_compliance"`
}
