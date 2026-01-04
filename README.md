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

### `idc privesc` - Privilege Escalation Detection

Find privilege escalation paths in RBAC configurations.

```bash
# Scan all workloads for privesc paths
idc privesc --all -A

# Check specific workload
idc privesc --workload deployment/api-server -n prod

# Output as JSON
idc privesc --all -A -o json
```

**Detected vectors:**
- `bind_roles` - Can create/modify RoleBindings
- `escalate_verb` - Has escalate permission on roles
- `impersonate` - Can impersonate users/groups/service accounts
- `create_pods` - Can create pods (mount secrets, use other SAs)
- `create_workloads` - Can create deployments/daemonsets/etc.
- `csr_approval` - Can approve certificate signing requests
- `node_proxy` - Can access node proxy API
- `secrets_access` - Can read secrets cluster-wide
- `webhook_modify` - Can modify admission webhooks
- `token_request` - Can request service account tokens

### `idc whocan` - Reverse RBAC Lookup

Find all subjects that can perform a specific action.

```bash
# Who can get secrets?
idc whocan get secrets -A

# Who can create pods in production?
idc whocan create pods -n production

# Who can delete deployments?
idc whocan delete deployments -A

# Output as JSON
idc whocan get secrets -A -o json
```

### `idc whatcan` - Forward RBAC Lookup

Show all permissions for a specific service account.

```bash
# What can this service account do?
idc whatcan my-service-account -n default

# Output as JSON
idc whatcan my-service-account -n default -o json
```

### `idc rbac-audit` - RBAC Security Audit

Run comprehensive RBAC security checks.

```bash
# Run all checks
idc rbac-audit -A

# Run specific checks only
idc rbac-audit -A --checks RBAC003,RBAC005

# Skip specific checks
idc rbac-audit -A --skip-checks RBAC001,RBAC002

# Output as JSON
idc rbac-audit -A -o json
```

**Security checks (15 total):**

| ID | Name | Severity |
|----|------|----------|
| RBAC001 | Default ServiceAccount Usage | Medium |
| RBAC002 | Automounted SA Tokens | Low |
| RBAC003 | Wildcard Permissions | Critical |
| RBAC004 | cluster-admin Usage | Critical |
| RBAC005 | Secrets Access | High |
| RBAC006 | Pod Exec Access | High |
| RBAC007 | Bind/Escalate Permissions | Critical |
| RBAC008 | Impersonation Permissions | Critical |
| RBAC009 | Cross-Namespace Bindings | Medium |
| RBAC010 | Unused ServiceAccounts | Low |
| RBAC011 | Node/Proxy Access | High |
| RBAC012 | CSR Permissions | High |
| RBAC013 | Webhook Modification | Critical |
| RBAC014 | Workload Creation | Medium |
| RBAC015 | Dangerous Verbs | High |

### `idc cloud-audit` - Cloud IAM Security Audit

Analyze cloud IAM configurations for security issues. Works with AWS, Azure, and GCP.

```bash
# AWS - Audit IRSA roles
idc cloud-audit -A --include-cloud --aws-region us-west-2

# Azure - Audit Workload Identity
idc cloud-audit -A --include-cloud --azure-subscription <subscription-id>

# GCP - Audit Workload Identity
idc cloud-audit -A --include-cloud --gcp-project my-project

# Output as JSON
idc cloud-audit -A --include-cloud --aws-region us-west-2 -o json
```

**Detected issues:**
- Admin policy attachments (AdministratorAccess, Owner, roles/owner)
- IAM privilege escalation paths (iam:*, iam:CreateRole, etc.)
- Cross-account access via trust policies
- Overly permissive policies (service:* wildcards)
- Sensitive data access (s3:*, secretsmanager:*, keyvault, etc.)

### `idc pod-security` - Pod Security Audit

Analyze workloads for security misconfigurations based on Pod Security Standards.

```bash
# Run all checks
idc pod-security -A

# Run in specific namespace
idc pod-security -n production

# Run specific checks only
idc pod-security -A --checks PSS001,PSS006

# Skip specific checks
idc pod-security -A --skip-checks PSS009,PSS010

# Output as JSON
idc pod-security -A -o json
```

**Security checks (12 total):**

| ID | Name | Category | Severity |
|----|------|----------|----------|
| PSS001 | Privileged Containers | privilege_escalation | Critical |
| PSS002 | Host Network | network_exposure | High |
| PSS003 | Host PID | privilege_escalation | High |
| PSS004 | Host IPC | privilege_escalation | Medium |
| PSS005 | Host Path Volumes | data_access | High |
| PSS006 | Dangerous Capabilities | privilege_escalation | Critical |
| PSS007 | Running as Root | privilege_escalation | Medium |
| PSS008 | Allow Privilege Escalation | privilege_escalation | High |
| PSS009 | Missing Security Context | misconfiguration | Low |
| PSS010 | Writable Root Filesystem | data_integrity | Low |
| PSS011 | Host Ports | network_exposure | Medium |
| PSS012 | Secrets in Environment | secret_exposure | Medium |

### `idc network-policy` - Network Policy Audit

Analyze workloads for network policy coverage and security issues.

```bash
# Run all checks
idc network-policy -A

# Run in specific namespace
idc network-policy -n production

# Run specific checks only
idc network-policy -A --checks NET001,NET002

# Skip specific checks
idc network-policy -A --skip-checks NET007

# Output as JSON
idc network-policy -A -o json
```

**Security checks (8 total):**

| ID | Name | Category | Severity |
|----|------|----------|----------|
| NET001 | No Network Policy | missing_policy | High |
| NET002 | Externally Exposed Without Policy | external_exposure | Critical |
| NET003 | Allow All Ingress | overly_permissive | Medium |
| NET004 | Allow All Egress | overly_permissive | Medium |
| NET005 | Wide CIDR Block | overly_permissive | Medium |
| NET006 | No Ingress Policy | incomplete_policy | Medium |
| NET007 | No Egress Policy | incomplete_policy | Low |
| NET008 | Host Network Exposed | host_exposure | High |

### `idc attack-path` - Attack Path Visualization

Analyze and visualize potential attack paths from compromised workloads.

```bash
# Analyze all workloads for attack paths
idc attack-path --all -A

# Analyze specific workload
idc attack-path --workload deployment/api-server -n prod

# Include cloud attack paths
idc attack-path --all -A --include-cloud --aws-region us-west-2

# Output as JSON
idc attack-path --all -A -o json

# Generate DOT graph for visualization
idc attack-path --all -A -o dot > attack-paths.dot
```

**Attack techniques detected (with MITRE ATT&CK mapping):**

| Technique | MITRE ID | Description |
|-----------|----------|-------------|
| Initial Access | T1190 | Attacker gains foothold in workload |
| Secrets Access | T1552.007 | Read K8s secrets containing credentials |
| Credential Theft | T1528 | Steal service account tokens |
| Identity Assumption | T1550 | Assume another identity using stolen credentials |
| Container Execution | T1609 | Execute commands in other containers |
| Container Deployment | T1610 | Create pods with different SAs |
| Privilege Escalation | T1078.004 | Escalate via RBAC manipulation |
| Cloud Resource Access | T1078.004 | Access cloud via IRSA/Workload Identity |
| Lateral Movement | T1021 | Move to other workloads |
| Cluster Takeover | T1098 | Gain cluster-admin access |

**Features:**
- Step-by-step attack chains with MITRE ATT&CK references
- Risk scoring for each path
- Mitigation recommendations
- Cloud and cluster impact indicators
- Cross-namespace path detection

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
