package analysis

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// SnapshotVersion is the current snapshot format version.
const SnapshotVersion = "1.0"

// GraphStats holds high-level graph statistics for portability.
type SnapshotGraphStats struct {
	TotalNodes    int `json:"total_nodes"`
	TotalEdges    int `json:"total_edges"`
	WorkloadCount int `json:"workload_count"`
	SACount       int `json:"service_account_count"`
	RoleCount     int `json:"role_count"`
}

// Snapshot is the portable JSON format for a findings snapshot.
type Snapshot struct {
	Version    string                 `json:"version"`
	Timestamp  string                 `json:"timestamp"`
	GraphStats *SnapshotGraphStats    `json:"graph_stats,omitempty"`
	Findings   ScanFindings           `json:"findings"`
}

// NewSnapshot creates a Snapshot with the current version and timestamp.
func NewSnapshot(findings ScanFindings, graphStats *SnapshotGraphStats) *Snapshot {
	return &Snapshot{
		Version:    SnapshotVersion,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		GraphStats: graphStats,
		Findings:   findings,
	}
}

// WriteSnapshot writes a snapshot to the given file path, or stdout if path is empty.
func WriteSnapshot(snap *Snapshot, path string) error {
	var w *os.File
	if path != "" {
		var err error
		w, err = os.Create(path)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer w.Close()
	} else {
		w = os.Stdout
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(snap)
}

// LoadScanFindings reads a snapshot file and returns the ScanFindings.
// It supports both the new versioned format and the legacy flat format.
func LoadScanFindings(path string) (*ScanFindings, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return ParseScanFindings(data)
}

// ParseScanFindings parses snapshot JSON data and returns the ScanFindings.
// It supports both the new versioned format and the legacy flat format.
func ParseScanFindings(data []byte) (*ScanFindings, error) {
	// Try new format first (has "findings" wrapper)
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err == nil && snap.Version != "" {
		return &snap.Findings, nil
	}

	// Fall back to legacy flat format
	var findings ScanFindings
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, fmt.Errorf("failed to parse snapshot: %w", err)
	}

	return &findings, nil
}
