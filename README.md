# Identity Chain (idc)

**Kubernetes Identity & Blast Radius Analyzer**

Identity Chain maps the complete identity chain from Kubernetes workloads through RBAC to cloud IAM (AWS, Azure, GCP), enabling blast radius analysis for security assessments and incident response.

## What It Does

When a Kubernetes workload is compromised, attackers can leverage its identity to:
- Access K8s secrets, configmaps, and other resources via RBAC
- Assume cloud IAM roles via IRSA (AWS), Workload Identity (GCP/Azure)
- Pivot to cloud resources like S3 buckets, secrets managers, databases

**idc** traces these identity chains and calculates the blast radius - showing exactly what an attacker could access.

## Installation

### From Releases

Download the latest binary for your platform from [Releases](https://github.com/nelssec/identity-chain/releases).

```bash
# macOS (Apple Silicon)
curl -L https://github.com/nelssec/identity-chain/releases/latest/download/idc-darwin-arm64 -o idc
chmod +x idc && sudo mv idc /usr/local/bin/

# macOS (Intel)
curl -L https://github.com/nelssec/identity-chain/releases/latest/download/idc-darwin-amd64 -o idc
chmod +x idc && sudo mv idc /usr/local/bin/

# Linux (amd64)
curl -L https://github.com/nelssec/identity-chain/releases/latest/download/idc-linux-amd64 -o idc
chmod +x idc && sudo mv idc /usr/local/bin/

# Windows (PowerShell)
Invoke-WebRequest -Uri https://github.com/nelssec/identity-chain/releases/latest/download/idc-windows-amd64.exe -OutFile idc.exe
```

### From Source

```bash
git clone https://github.com/nelssec/identity-chain.git
cd identity-chain
go build -o idc ./cmd/idc/
```

## Quick Start

```bash
# Scan all namespaces and show blast radius for all workloads
idc blast --all -A

# Generate interactive HTML visualization
idc blast --all -A -o html > blast-report.html

# Include cloud IAM analysis (AWS)
idc blast --all -A --include-cloud --aws-region us-west-2 -o html > blast-report.html

# Analyze a specific workload
idc blast --workload deployment/api-server -n production

# Show cluster statistics
idc scan -A

# Export full identity graph (for Graphviz)
idc graph -A -o dot > cluster.dot
dot -Tpng cluster.dot -o cluster.png
```

## Commands

### `idc blast` - Blast Radius Analysis

Calculate the blast radius for workloads by tracing identity chains.

```bash
# All workloads in all namespaces
idc blast --all -A

# Specific workload
idc blast --workload deployment/api-server -n prod
idc blast --workload sts/postgres -n database
idc blast --workload ds/fluentd -n logging

# Output formats
idc blast --all -A -o table   # Default, human-readable
idc blast --all -A -o json    # Machine-readable
idc blast --all -A -o html    # Interactive visualization
```

### `idc identity` - Cloud Identity Bindings

Show Kubernetes service accounts with cloud identity bindings.

```bash
# Show all cloud identity bindings
idc identity -A

# With AWS IAM policy details
idc identity -A --aws-region us-west-2

# With Azure role assignment details
idc identity -A --azure-subscription <subscription-id>
```

### `idc graph` - Export Identity Graph

Export the complete identity chain graph.

```bash
# DOT format for Graphviz
idc graph -A -o dot > cluster.dot

# JSON format
idc graph -A -o json > cluster.json

# HTML visualization
idc graph -A -o html > graph.html
```

### `idc scan` - Cluster Statistics

Show identity chain statistics for the cluster.

```bash
idc scan -A
```

### `idc unused` - Find Unused Permissions

Analyze audit logs to find permissions granted but never used.

```bash
# From audit log files
idc unused --since 30d --audit-source file --audit-path /var/log/audit/

# From Elasticsearch
idc unused --since 7d --audit-source elasticsearch --es-endpoint http://es:9200
```

## Global Flags

| Flag | Description |
|------|-------------|
| `-n, --namespace` | Kubernetes namespace (default: "default") |
| `-A, --all-namespaces` | Scan all namespaces |
| `--kubeconfig` | Path to kubeconfig file |
| `--context` | Kubernetes context to use |
| `-o, --output` | Output format: table, json, dot, html |
| `--include-system` | Include system namespaces (kube-system, etc.) |
| `--include-cloud` | Include cloud IAM analysis |
| `--aws-region` | AWS region for IAM lookups |
| `--gcp-project` | GCP project for IAM lookups |
| `--azure-subscription` | Azure subscription ID |

## Cloud Provider Support

### AWS (IRSA - IAM Roles for Service Accounts)

Detects ServiceAccounts with the `eks.amazonaws.com/role-arn` annotation and fetches:
- Attached IAM policies (managed and inline)
- Policy statements with actions and resources
- Trust policy conditions

```bash
idc blast --all -A --include-cloud --aws-region us-west-2
```

**Required AWS permissions:**
```json
{
  "Effect": "Allow",
  "Action": [
    "iam:GetRole",
    "iam:ListRolePolicies",
    "iam:GetRolePolicy",
    "iam:ListAttachedRolePolicies",
    "iam:GetPolicy",
    "iam:GetPolicyVersion"
  ],
  "Resource": "*"
}
```

### GCP (Workload Identity)

Detects ServiceAccounts with the `iam.gke.io/gcp-service-account` annotation.

```bash
idc blast --all -A --include-cloud --gcp-project my-project
```

### Azure (Workload Identity)

Detects ServiceAccounts with the `azure.workload.identity/client-id` annotation.

```bash
idc blast --all -A --include-cloud --azure-subscription <subscription-id>
```

## Output Formats

### HTML Visualization

The HTML output provides an interactive graph visualization:

- **Click nodes** to see detailed blast radius information
- **Filter by type** (workload, service account, role, cloud role)
- **Filter by risk** (critical, high, medium, low)
- **Zoom and pan** to explore large graphs

```bash
idc blast --all -A -o html > report.html
open report.html
```

### JSON Output

Machine-readable output for integration with other tools:

```bash
idc blast --all -A -o json | jq '.[] | select(.max_severity == "critical")'
```

### DOT/Graphviz Output

For custom visualizations:

```bash
idc graph -A -o dot | dot -Tsvg > cluster.svg
```

## Examples

### Security Assessment

```bash
# Find all overprivileged workloads
idc blast --all -A -o json | jq '.[] | select(.max_severity == "critical" or .max_severity == "high")'

# Generate executive summary
idc scan -A

# Create visual report
idc blast --all -A --include-cloud --aws-region us-west-2 -o html > security-report.html
```

### Incident Response

```bash
# What can this compromised pod access?
idc blast --workload pod/compromised-pod -n production --include-cloud --aws-region us-west-2

# What workloads use this service account?
idc identity -A | grep suspicious-sa
```

### Compliance

```bash
# Find service accounts with secrets access
idc blast --all -A -o json | jq '.[] | select(.k8s_resources[]?.name == "secrets")'

# Find workloads with cloud admin access
idc blast --all -A --include-cloud -o json | jq '.[] | select(.cloud_roles[]?.policies[]?.is_admin == true)'
```

## Architecture

```
Workload (Pod/Deployment/etc.)
    │
    └──uses──► ServiceAccount
                    │
                    ├──binds──► Role/ClusterRole
                    │               │
                    │               └──grants──► K8s Resources (secrets, pods, etc.)
                    │
                    └──assumes──► Cloud Role (AWS/GCP/Azure)
                                      │
                                      └──allows──► Cloud Resources (S3, Secrets Manager, etc.)
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

MIT License - see [LICENSE](LICENSE) for details.
