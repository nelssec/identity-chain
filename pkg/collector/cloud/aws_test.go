package cloud

import (
	"testing"

	"github.com/nelssec/identity-chain/pkg/graph"
)

func TestExtractRoleName(t *testing.T) {
	tests := []struct {
		name    string
		roleARN string
		want    string
	}{
		{
			name:    "standard ARN",
			roleARN: "arn:aws:iam::123456789012:role/my-role",
			want:    "my-role",
		},
		{
			name:    "ARN with path",
			roleARN: "arn:aws:iam::123456789012:role/path/to/my-role",
			want:    "my-role",
		},
		{
			name:    "just role name no slashes",
			roleARN: "arn:aws:iam::123456789012:role",
			want:    "role",
		},
		{
			name:    "plain string no separators",
			roleARN: "my-role",
			want:    "my-role",
		},
		{
			name:    "colon separated fallback",
			roleARN: "prefix:my-role",
			want:    "my-role",
		},
		{
			name:    "empty string",
			roleARN: "",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRoleName(tt.roleARN)
			if got != tt.want {
				t.Errorf("extractRoleName(%q) = %q, want %q", tt.roleARN, got, tt.want)
			}
		})
	}
}

func TestExtractAccountID(t *testing.T) {
	tests := []struct {
		name    string
		roleARN string
		want    string
	}{
		{
			name:    "standard ARN",
			roleARN: "arn:aws:iam::123456789012:role/my-role",
			want:    "123456789012",
		},
		{
			name:    "too few parts",
			roleARN: "arn:aws:iam",
			want:    "",
		},
		{
			name:    "empty string",
			roleARN: "",
			want:    "",
		},
		{
			name:    "exactly 5 parts",
			roleARN: "a:b:c:d:account-id",
			want:    "account-id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractAccountID(tt.roleARN)
			if got != tt.want {
				t.Errorf("extractAccountID(%q) = %q, want %q", tt.roleARN, got, tt.want)
			}
		})
	}
}

func TestParseTrustPolicy(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		wantNil bool
		wantLen int
	}{
		{
			name:    "invalid JSON",
			doc:     "not json",
			wantNil: true,
		},
		{
			name:    "empty JSON",
			doc:     "{}",
			wantNil: false,
			wantLen: 0,
		},
		{
			name: "single string principal",
			doc: `{
				"Statement": [{
					"Principal": {"Service": "ec2.amazonaws.com"}
				}]
			}`,
			wantNil: false,
			wantLen: 1,
		},
		{
			name: "array principal",
			doc: `{
				"Statement": [{
					"Principal": {"AWS": ["arn:aws:iam::111:root", "arn:aws:iam::222:root"]}
				}]
			}`,
			wantNil: false,
			wantLen: 2,
		},
		{
			name: "multiple statements",
			doc: `{
				"Statement": [
					{"Principal": {"Service": "ec2.amazonaws.com"}},
					{"Principal": {"AWS": "arn:aws:iam::111:root"}}
				]
			}`,
			wantNil: false,
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseTrustPolicy(tt.doc)
			if tt.wantNil {
				if got != nil {
					t.Errorf("parseTrustPolicy() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("parseTrustPolicy() = nil, want non-nil")
			}
			if len(got.TrustedEntities) != tt.wantLen {
				t.Errorf("parseTrustPolicy() trusted entities len = %d, want %d", len(got.TrustedEntities), tt.wantLen)
			}
		})
	}
}

func TestParsePolicyDocument(t *testing.T) {
	tests := []struct {
		name          string
		doc           string
		wantVersion   string
		wantStmtCount int
	}{
		{
			name:          "invalid JSON returns empty doc",
			doc:           "not json",
			wantVersion:   "",
			wantStmtCount: 0,
		},
		{
			name: "single statement with string action and resource",
			doc: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action": "s3:GetObject",
					"Resource": "arn:aws:s3:::my-bucket/*"
				}]
			}`,
			wantVersion:   "2012-10-17",
			wantStmtCount: 1,
		},
		{
			name: "statement with array actions and resources",
			doc: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Sid": "AllowS3",
					"Effect": "Allow",
					"Action": ["s3:GetObject", "s3:PutObject"],
					"Resource": ["arn:aws:s3:::bucket1/*", "arn:aws:s3:::bucket2/*"]
				}]
			}`,
			wantVersion:   "2012-10-17",
			wantStmtCount: 1,
		},
		{
			name: "multiple statements",
			doc: `{
				"Version": "2012-10-17",
				"Statement": [
					{"Effect": "Allow", "Action": "*", "Resource": "*"},
					{"Effect": "Deny", "Action": "iam:*", "Resource": "*"}
				]
			}`,
			wantVersion:   "2012-10-17",
			wantStmtCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parsePolicyDocument(tt.doc)
			if got == nil {
				t.Fatal("parsePolicyDocument() returned nil")
			}
			if got.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", got.Version, tt.wantVersion)
			}
			if len(got.Statement) != tt.wantStmtCount {
				t.Errorf("Statement count = %d, want %d", len(got.Statement), tt.wantStmtCount)
			}
		})
	}
}

func TestParsePolicyDocumentActions(t *testing.T) {
	doc := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["s3:GetObject", "s3:PutObject"],
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`

	got := parsePolicyDocument(doc)
	if len(got.Statement) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(got.Statement))
	}
	stmt := got.Statement[0]
	if len(stmt.Action) != 2 {
		t.Errorf("expected 2 actions, got %d", len(stmt.Action))
	}
	if len(stmt.Resource) != 1 {
		t.Errorf("expected 1 resource, got %d", len(stmt.Resource))
	}
}

func TestToStringSlice(t *testing.T) {
	tests := []struct {
		name string
		v    interface{}
		want []string
	}{
		{
			name: "string input",
			v:    "hello",
			want: []string{"hello"},
		},
		{
			name: "slice of interfaces",
			v:    []interface{}{"a", "b", "c"},
			want: []string{"a", "b", "c"},
		},
		{
			name: "slice with non-string ignored",
			v:    []interface{}{"a", 42, "b"},
			want: []string{"a", "b"},
		},
		{
			name: "nil input",
			v:    nil,
			want: nil,
		},
		{
			name: "unsupported type",
			v:    123,
			want: nil,
		},
		{
			name: "empty slice",
			v:    []interface{}{},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toStringSlice(tt.v)
			if tt.want == nil {
				if got != nil {
					t.Errorf("toStringSlice() = %v, want nil", got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("toStringSlice() len = %d, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("toStringSlice()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestIsAdminPolicy(t *testing.T) {
	tests := []struct {
		name string
		doc  *PolicyDocument
		want bool
	}{
		{
			name: "admin policy - star action and star resource",
			doc: &PolicyDocument{
				Statement: []Statement{{
					Effect:   "Allow",
					Action:   []string{"*"},
					Resource: []string{"*"},
				}},
			},
			want: true,
		},
		{
			name: "not admin - star action but specific resource",
			doc: &PolicyDocument{
				Statement: []Statement{{
					Effect:   "Allow",
					Action:   []string{"*"},
					Resource: []string{"arn:aws:s3:::my-bucket"},
				}},
			},
			want: false,
		},
		{
			name: "not admin - specific action and star resource",
			doc: &PolicyDocument{
				Statement: []Statement{{
					Effect:   "Allow",
					Action:   []string{"s3:GetObject"},
					Resource: []string{"*"},
				}},
			},
			want: false,
		},
		{
			name: "not admin - deny effect",
			doc: &PolicyDocument{
				Statement: []Statement{{
					Effect:   "Deny",
					Action:   []string{"*"},
					Resource: []string{"*"},
				}},
			},
			want: false,
		},
		{
			name: "empty statements",
			doc:  &PolicyDocument{Statement: []Statement{}},
			want: false,
		},
		{
			name: "admin in second statement",
			doc: &PolicyDocument{
				Statement: []Statement{
					{Effect: "Allow", Action: []string{"s3:GetObject"}, Resource: []string{"*"}},
					{Effect: "Allow", Action: []string{"*"}, Resource: []string{"*"}},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAdminPolicy(tt.doc)
			if got != tt.want {
				t.Errorf("isAdminPolicy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsAWSManagedAdmin(t *testing.T) {
	tests := []struct {
		name      string
		policyARN string
		want      bool
	}{
		{"AdministratorAccess", "arn:aws:iam::aws:policy/AdministratorAccess", true},
		{"PowerUserAccess", "arn:aws:iam::aws:policy/PowerUserAccess", true},
		{"IAMFullAccess", "arn:aws:iam::aws:policy/IAMFullAccess", true},
		{"ReadOnlyAccess", "arn:aws:iam::aws:policy/ReadOnlyAccess", false},
		{"custom policy", "arn:aws:iam::123456789012:policy/my-policy", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAWSManagedAdmin(tt.policyARN)
			if got != tt.want {
				t.Errorf("isAWSManagedAdmin(%q) = %v, want %v", tt.policyARN, got, tt.want)
			}
		})
	}
}

func TestClassifyAWSResource(t *testing.T) {
	tests := []struct {
		name        string
		resourceARN string
		want        string
	}{
		{"wildcard", "*", "all-resources"},
		{"s3 bucket", "arn:aws:s3:::my-bucket", "s3-bucket"},
		{"secretsmanager", "arn:aws:secretsmanager:us-east-1:123456789012:secret:mysecret", "secrets-manager"},
		{"ssm", "arn:aws:ssm:us-east-1:123456789012:parameter/myp", "ssm-parameter"},
		{"kms", "arn:aws:kms:us-east-1:123456789012:key/my-key", "kms-key"},
		{"dynamodb", "arn:aws:dynamodb:us-east-1:123456789012:table/mytable", "dynamodb-table"},
		{"rds", "arn:aws:rds:us-east-1:123456789012:db:mydb", "rds-database"},
		{"ec2", "arn:aws:ec2:us-east-1:123456789012:instance/i-1234", "ec2-instance"},
		{"lambda", "arn:aws:lambda:us-east-1:123456789012:function:myfn", "lambda-function"},
		{"ecs", "arn:aws:ecs:us-east-1:123456789012:service/mycluster/mysvc", "ecs-service"},
		{"eks", "arn:aws:eks:us-east-1:123456789012:cluster/mycluster", "eks-cluster"},
		{"sqs", "arn:aws:sqs:us-east-1:123456789012:myqueue", "sqs-queue"},
		{"sns", "arn:aws:sns:us-east-1:123456789012:mytopic", "sns-topic"},
		{"iam", "arn:aws:iam::123456789012:role/myrole", "iam-resource"},
		{"sts", "arn:aws:sts::123456789012:assumed-role/myrole/session", "sts-resource"},
		{"unknown service", "arn:aws:elasticache:us-east-1:123456789012:cluster:mycluster", "elasticache"},
		{"too few parts", "arn:aws", "unknown"},
		{"empty string", "", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyAWSResource(tt.resourceARN)
			if got != tt.want {
				t.Errorf("classifyAWSResource(%q) = %q, want %q", tt.resourceARN, got, tt.want)
			}
		})
	}
}

func TestMergeActions(t *testing.T) {
	tests := []struct {
		name     string
		existing []string
		new      []string
		wantLen  int
	}{
		{
			name:     "no overlap",
			existing: []string{"s3:GetObject"},
			new:      []string{"s3:PutObject"},
			wantLen:  2,
		},
		{
			name:     "full overlap",
			existing: []string{"s3:GetObject"},
			new:      []string{"s3:GetObject"},
			wantLen:  1,
		},
		{
			name:     "partial overlap",
			existing: []string{"s3:GetObject", "s3:PutObject"},
			new:      []string{"s3:PutObject", "s3:DeleteObject"},
			wantLen:  3,
		},
		{
			name:     "empty existing",
			existing: []string{},
			new:      []string{"s3:GetObject"},
			wantLen:  1,
		},
		{
			name:     "empty new",
			existing: []string{"s3:GetObject"},
			new:      []string{},
			wantLen:  1,
		},
		{
			name:     "both empty",
			existing: []string{},
			new:      []string{},
			wantLen:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeActions(tt.existing, tt.new)
			if len(got) != tt.wantLen {
				t.Errorf("mergeActions() len = %d, want %d; got %v", len(got), tt.wantLen, got)
			}
		})
	}
}

func TestClassifyAWSSeverity(t *testing.T) {
	tests := []struct {
		name         string
		actions      []string
		resourceType string
		want         graph.Severity
	}{
		{"delegates to ClassifyCloudSeverity critical", []string{"*"}, "s3", graph.SeverityCritical},
		{"delegates to ClassifyCloudSeverity medium", []string{"logs:Describe"}, "logs", graph.SeverityMedium},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyAWSSeverity(tt.actions, tt.resourceType)
			if got != tt.want {
				t.Errorf("ClassifyAWSSeverity() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSafeString(t *testing.T) {
	tests := []struct {
		name string
		s    *string
		want string
	}{
		{"nil pointer", nil, ""},
		{"non-nil pointer", strPtr("hello"), "hello"},
		{"empty string pointer", strPtr(""), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := safeString(tt.s)
			if got != tt.want {
				t.Errorf("safeString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func strPtr(s string) *string {
	return &s
}
