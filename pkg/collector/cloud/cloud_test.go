package cloud

import (
	"context"
	"testing"

	"github.com/nelssec/identity-chain/pkg/graph"
)

func TestDetectProvider(t *testing.T) {
	tests := []struct {
		name         string
		annotations  map[string]string
		wantProvider Provider
		wantValue    string
	}{
		{
			name:         "nil annotations",
			annotations:  nil,
			wantProvider: "",
			wantValue:    "",
		},
		{
			name:         "empty annotations",
			annotations:  map[string]string{},
			wantProvider: "",
			wantValue:    "",
		},
		{
			name:         "AWS EKS annotation",
			annotations:  map[string]string{"eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/my-role"},
			wantProvider: ProviderAWS,
			wantValue:    "arn:aws:iam::123456789012:role/my-role",
		},
		{
			name:         "GCP GKE annotation",
			annotations:  map[string]string{"iam.gke.io/gcp-service-account": "sa@project.iam.gserviceaccount.com"},
			wantProvider: ProviderGCP,
			wantValue:    "sa@project.iam.gserviceaccount.com",
		},
		{
			name:         "Azure workload identity annotation",
			annotations:  map[string]string{"azure.workload.identity/client-id": "client-id-123"},
			wantProvider: ProviderAzure,
			wantValue:    "client-id-123",
		},
		{
			name: "unrelated annotations only",
			annotations: map[string]string{
				"app.kubernetes.io/name": "my-app",
			},
			wantProvider: "",
			wantValue:    "",
		},
		{
			name: "AWS takes precedence when multiple present",
			annotations: map[string]string{
				"eks.amazonaws.com/role-arn":         "arn:aws:iam::123456789012:role/my-role",
				"iam.gke.io/gcp-service-account":    "sa@project.iam.gserviceaccount.com",
				"azure.workload.identity/client-id":  "client-id-123",
			},
			wantProvider: ProviderAWS,
			wantValue:    "arn:aws:iam::123456789012:role/my-role",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, value := DetectProvider(tt.annotations)
			if provider != tt.wantProvider {
				t.Errorf("DetectProvider() provider = %v, want %v", provider, tt.wantProvider)
			}
			if value != tt.wantValue {
				t.Errorf("DetectProvider() value = %v, want %v", value, tt.wantValue)
			}
		})
	}
}

func TestClassifyCloudSeverity(t *testing.T) {
	tests := []struct {
		name         string
		actions      []string
		resourceType string
		want         graph.Severity
	}{
		{
			name:         "wildcard action is critical",
			actions:      []string{"*"},
			resourceType: "s3-bucket",
			want:         graph.SeverityCritical,
		},
		{
			name:         "star-colon-star is critical",
			actions:      []string{"*:*"},
			resourceType: "unknown",
			want:         graph.SeverityCritical,
		},
		{
			name:         "iam wildcard is critical (admin action)",
			actions:      []string{"iam:*"},
			resourceType: "iam-resource",
			want:         graph.SeverityCritical,
		},
		{
			name:         "sts:AssumeRole is critical",
			actions:      []string{"sts:AssumeRole"},
			resourceType: "sts-resource",
			want:         graph.SeverityCritical,
		},
		{
			name:         "s3:GetObject matches s3:* admin pattern so critical",
			actions:      []string{"s3:GetObject"},
			resourceType: "s3-bucket",
			want:         graph.SeverityCritical,
		},
		{
			name:         "lambda:InvokeFunction matches lambda:* admin pattern so critical",
			actions:      []string{"lambda:InvokeFunction"},
			resourceType: "lambda-function",
			want:         graph.SeverityCritical,
		},
		{
			name:         "high risk resource type with s3 action matches admin",
			actions:      []string{"s3:ListBuckets"},
			resourceType: "secret",
			want:         graph.SeverityCritical,
		},
		{
			name:         "bigquery.tables.getData is high risk only",
			actions:      []string{"bigquery.tables.getData"},
			resourceType: "bigquery",
			want:         graph.SeverityHigh,
		},
		{
			name:         "high risk resource type elevates benign action",
			actions:      []string{"logs:DescribeLogGroups"},
			resourceType: "database",
			want:         graph.SeverityHigh,
		},
		{
			name:         "medium severity default",
			actions:      []string{"logs:DescribeLogGroups"},
			resourceType: "logs",
			want:         graph.SeverityMedium,
		},
		{
			name:         "empty actions with non-high-risk resource",
			actions:      []string{},
			resourceType: "logs",
			want:         graph.SeverityMedium,
		},
		{
			name:         "kms:Decrypt is admin/critical",
			actions:      []string{"kms:Decrypt"},
			resourceType: "kms-key",
			want:         graph.SeverityCritical,
		},
		{
			name:         "secretsmanager:GetSecretValue matches secretsmanager:* admin so critical",
			actions:      []string{"secretsmanager:GetSecretValue"},
			resourceType: "secrets-manager",
			want:         graph.SeverityCritical,
		},
		{
			name:         "GCP roles/owner is admin/critical",
			actions:      []string{"roles/owner"},
			resourceType: "gcp-resource",
			want:         graph.SeverityCritical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyCloudSeverity(tt.actions, tt.resourceType)
			if got != tt.want {
				t.Errorf("ClassifyCloudSeverity(%v, %q) = %v, want %v", tt.actions, tt.resourceType, got, tt.want)
			}
		})
	}
}

func TestNewMultiCloudCollector(t *testing.T) {
	mcc := NewMultiCloudCollector()
	if mcc == nil {
		t.Fatal("NewMultiCloudCollector() returned nil")
	}
	if mcc.collectors == nil {
		t.Fatal("NewMultiCloudCollector() collectors map is nil")
	}
	if len(mcc.collectors) != 0 {
		t.Errorf("NewMultiCloudCollector() collectors map should be empty, got %d", len(mcc.collectors))
	}
}

type mockCollector struct {
	provider Provider
}

func (m *mockCollector) Provider() Provider                                                          { return m.provider }
func (m *mockCollector) CollectRole(_ context.Context, _ string) (*RoleInfo, error)                  { return nil, nil }
func (m *mockCollector) GetResourceAccess(_ context.Context, _ *RoleInfo) ([]ResourceAccess, error)  { return nil, nil }

func TestRegisterAndGetCollector(t *testing.T) {
	mcc := NewMultiCloudCollector()

	awsMock := &mockCollector{provider: ProviderAWS}
	gcpMock := &mockCollector{provider: ProviderGCP}

	mcc.Register(awsMock)
	mcc.Register(gcpMock)

	tests := []struct {
		name     string
		provider Provider
		wantNil  bool
	}{
		{"get AWS collector", ProviderAWS, false},
		{"get GCP collector", ProviderGCP, false},
		{"get Azure collector (not registered)", ProviderAzure, true},
		{"get empty provider", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mcc.GetCollector(tt.provider)
			if tt.wantNil && got != nil {
				t.Errorf("GetCollector(%q) = %v, want nil", tt.provider, got)
			}
			if !tt.wantNil && got == nil {
				t.Errorf("GetCollector(%q) = nil, want non-nil", tt.provider)
			}
		})
	}
}

func TestRegisterOverwrite(t *testing.T) {
	mcc := NewMultiCloudCollector()
	mock1 := &mockCollector{provider: ProviderAWS}
	mock2 := &mockCollector{provider: ProviderAWS}

	mcc.Register(mock1)
	mcc.Register(mock2)

	got := mcc.GetCollector(ProviderAWS)
	if got.(*mockCollector) != mock2 {
		t.Error("Register should overwrite existing collector for same provider")
	}
}

func TestMatchAction(t *testing.T) {
	tests := []struct {
		name    string
		action  string
		pattern string
		want    bool
	}{
		{"exact match", "s3:GetObject", "s3:GetObject", true},
		{"no match", "s3:GetObject", "s3:PutObject", false},
		{"wildcard prefix match", "s3:GetObject", "s3:*", true},
		{"wildcard exact service", "iam:CreateRole", "iam:*", true},
		{"wildcard no match", "ec2:RunInstances", "s3:*", false},
		{"full wildcard", "anything", "*", true},
		{"empty action vs pattern", "", "s3:*", false},
		{"empty pattern", "s3:GetObject", "", false},
		{"same string single char", "a", "a", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchAction(tt.action, tt.pattern)
			if got != tt.want {
				t.Errorf("matchAction(%q, %q) = %v, want %v", tt.action, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestIsAdminAction(t *testing.T) {
	tests := []struct {
		name   string
		action string
		want   bool
	}{
		{"iam wildcard", "iam:*", true},
		{"iam:CreateRole", "iam:CreateRole", true},
		{"sts:AssumeRole", "sts:AssumeRole", true},
		{"kms:Decrypt", "kms:Decrypt", true},
		{"s3:GetObject matches s3:* so is admin", "s3:GetObject", true},
		{"cloudwatch:GetMetricData is not admin", "cloudwatch:GetMetricData", false},
		{"roles/owner", "roles/owner", true},
		{"roles/editor", "roles/editor", true},
		{"benign action", "logs:DescribeLogGroups", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAdminAction(tt.action)
			if got != tt.want {
				t.Errorf("isAdminAction(%q) = %v, want %v", tt.action, got, tt.want)
			}
		})
	}
}

func TestIsHighRiskAction(t *testing.T) {
	tests := []struct {
		name   string
		action string
		want   bool
	}{
		{"s3:GetObject", "s3:GetObject", true},
		{"s3:PutObject", "s3:PutObject", true},
		{"s3:DeleteObject", "s3:DeleteObject", true},
		{"secretsmanager:GetSecretValue", "secretsmanager:GetSecretValue", true},
		{"dynamodb:*", "dynamodb:*", true},
		{"lambda:InvokeFunction", "lambda:InvokeFunction", true},
		{"storage.objects.get", "storage.objects.get", true},
		{"bigquery.tables.getData", "bigquery.tables.getData", true},
		{"not high risk", "logs:DescribeLogGroups", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isHighRiskAction(tt.action)
			if got != tt.want {
				t.Errorf("isHighRiskAction(%q) = %v, want %v", tt.action, got, tt.want)
			}
		})
	}
}

func TestIsHighRiskResource(t *testing.T) {
	tests := []struct {
		name         string
		resourceType string
		want         bool
	}{
		{"s3", "s3", true},
		{"bucket", "bucket", true},
		{"secret", "secret", true},
		{"kms", "kms", true},
		{"database", "database", true},
		{"rds", "rds", true},
		{"dynamodb", "dynamodb", true},
		{"storage", "storage", true},
		{"bigquery", "bigquery", true},
		{"s3-bucket contains s3", "s3-bucket", true},
		{"logs is not high risk", "logs", false},
		{"ec2 is not high risk", "ec2", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isHighRiskResource(tt.resourceType)
			if got != tt.want {
				t.Errorf("isHighRiskResource(%q) = %v, want %v", tt.resourceType, got, tt.want)
			}
		})
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		substr string
		want   bool
	}{
		{"exact match", "hello", "hello", true},
		{"substring", "hello world", "world", true},
		{"not found", "hello", "xyz", false},
		{"empty substr in non-empty", "hello", "", true},
		{"empty both", "", "", true},
		{"substr longer than string", "hi", "hello", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := contains(tt.s, tt.substr)
			if got != tt.want {
				t.Errorf("contains(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
			}
		})
	}
}
