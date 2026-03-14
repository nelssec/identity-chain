package cloud

import (
	"testing"

	"github.com/nelssec/identity-chain/pkg/graph"
)

func TestExtractGCPSAName(t *testing.T) {
	tests := []struct {
		name  string
		email string
		want  string
	}{
		{
			name:  "standard GCP service account",
			email: "my-sa@my-project.iam.gserviceaccount.com",
			want:  "my-sa",
		},
		{
			name:  "no @ sign",
			email: "my-sa",
			want:  "my-sa",
		},
		{
			name:  "empty string",
			email: "",
			want:  "",
		},
		{
			name:  "multiple @ signs",
			email: "user@domain@extra",
			want:  "user",
		},
		{
			name:  "compute default SA",
			email: "123456789-compute@developer.gserviceaccount.com",
			want:  "123456789-compute",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractGCPSAName(tt.email)
			if got != tt.want {
				t.Errorf("extractGCPSAName(%q) = %q, want %q", tt.email, got, tt.want)
			}
		})
	}
}

func TestExtractGCPProject(t *testing.T) {
	tests := []struct {
		name  string
		email string
		want  string
	}{
		{
			name:  "standard GCP service account",
			email: "my-sa@my-project.iam.gserviceaccount.com",
			want:  "my-project",
		},
		{
			name:  "no @ sign returns empty",
			email: "my-sa",
			want:  "",
		},
		{
			name:  "non-gserviceaccount domain returns empty",
			email: "user@gmail.com",
			want:  "",
		},
		{
			name:  "empty string",
			email: "",
			want:  "",
		},
		{
			name:  "project with dashes",
			email: "sa@my-cool-project-123.iam.gserviceaccount.com",
			want:  "my-cool-project-123",
		},
		{
			name:  "developer gserviceaccount domain returns empty",
			email: "sa@developer.gserviceaccount.com",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractGCPProject(tt.email)
			if got != tt.want {
				t.Errorf("extractGCPProject(%q) = %q, want %q", tt.email, got, tt.want)
			}
		})
	}
}

func TestClassifyGCPResource(t *testing.T) {
	tests := []struct {
		name     string
		resource string
		want     string
	}{
		{"GCS bucket by domain", "//storage.googleapis.com/my-bucket", "gcs-bucket"},
		{"GCS bucket by gs://", "gs://my-bucket", "gcs-bucket"},
		{"BigQuery", "//bigquery.googleapis.com/projects/p/datasets/d", "bigquery-dataset"},
		{"Secret Manager", "//secretmanager.googleapis.com/projects/p/secrets/s", "secret-manager"},
		{"Compute", "//compute.googleapis.com/projects/p/zones/z/instances/i", "compute-instance"},
		{"GKE", "//container.googleapis.com/projects/p/locations/l/clusters/c", "gke-cluster"},
		{"Cloud Functions", "//cloudfunctions.googleapis.com/projects/p/locations/l/functions/f", "cloud-function"},
		{"Cloud Run", "//run.googleapis.com/projects/p/locations/l/services/s", "cloud-run"},
		{"Pub/Sub", "//pubsub.googleapis.com/projects/p/topics/t", "pubsub-topic"},
		{"Cloud SQL", "//cloudsql.googleapis.com/projects/p/instances/i", "cloud-sql"},
		{"Cloud KMS", "//cloudkms.googleapis.com/projects/p/locations/l/keyRings/r/cryptoKeys/k", "cloud-kms"},
		{"wildcard", "*", "gcp-resource"},
		{"unknown resource", "//unknown.googleapis.com/foo", "gcp-resource"},
		{"empty string", "", "gcp-resource"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyGCPResource(tt.resource)
			if got != tt.want {
				t.Errorf("classifyGCPResource(%q) = %q, want %q", tt.resource, got, tt.want)
			}
		})
	}
}

func TestClassifyGCPPermissionSeverity(t *testing.T) {
	tests := []struct {
		name        string
		permissions []string
		want        graph.Severity
	}{
		{
			name:        "admin permission is critical",
			permissions: []string{"resourcemanager.projects.admin"},
			want:        graph.SeverityCritical,
		},
		{
			name:        "setIamPolicy is critical",
			permissions: []string{"resourcemanager.projects.setIamPolicy"},
			want:        graph.SeverityCritical,
		},
		{
			name:        "owner suffix is critical",
			permissions: []string{"resourcemanager.projects.owner"},
			want:        graph.SeverityCritical,
		},
		{
			name:        "plain owner is critical",
			permissions: []string{"owner"},
			want:        graph.SeverityCritical,
		},
		{
			name:        "secretmanager access is critical",
			permissions: []string{"secretmanager.versions.access"},
			want:        graph.SeverityCritical,
		},
		{
			name:        "create permission is high",
			permissions: []string{"compute.instances.create"},
			want:        graph.SeverityHigh,
		},
		{
			name:        "delete permission is high",
			permissions: []string{"compute.instances.delete"},
			want:        graph.SeverityHigh,
		},
		{
			name:        "update permission is high",
			permissions: []string{"compute.instances.update"},
			want:        graph.SeverityHigh,
		},
		{
			name:        "write permission is high",
			permissions: []string{"logging.logEntries.write"},
			want:        graph.SeverityHigh,
		},
		{
			name:        "storage.objects.get is high",
			permissions: []string{"storage.objects.get"},
			want:        graph.SeverityHigh,
		},
		{
			name:        "read-only permission is medium",
			permissions: []string{"compute.instances.get", "compute.instances.list"},
			want:        graph.SeverityMedium,
		},
		{
			name:        "empty permissions is medium",
			permissions: []string{},
			want:        graph.SeverityMedium,
		},
		{
			name:        "critical takes precedence over high",
			permissions: []string{"compute.instances.create", "resourcemanager.projects.setIamPolicy"},
			want:        graph.SeverityCritical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyGCPPermissionSeverity(tt.permissions)
			if got != tt.want {
				t.Errorf("ClassifyGCPPermissionSeverity(%v) = %v, want %v", tt.permissions, got, tt.want)
			}
		})
	}
}
