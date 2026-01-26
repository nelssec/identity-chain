package analysis

type ComplianceFramework string

const (
	FrameworkCIS     ComplianceFramework = "CIS"
	FrameworkNSACISA ComplianceFramework = "NSA-CISA"
	FrameworkNIST    ComplianceFramework = "NIST-800-53"
	FrameworkSOC2    ComplianceFramework = "SOC2"
	FrameworkPCIDSS  ComplianceFramework = "PCI-DSS"
)

type ControlMapping struct {
	CheckID       string
	CISControls   []string
	NSACISARef    []string
	NISTControls  []string
	SOC2Controls  []string
	PCIDSSReqs    []string
}

var CheckControlMappings = map[string]ControlMapping{
	"RBAC001": {
		CheckID:       "RBAC001",
		CISControls:   []string{"5.1.1", "5.1.2"},
		NSACISARef:    []string{"IAM-1", "IAM-2"},
		NISTControls:  []string{"AC-2", "AC-3", "AC-6"},
		SOC2Controls:  []string{"CC6.1", "CC6.2", "CC6.3"},
		PCIDSSReqs:    []string{"7.1", "7.2"},
	},
	"RBAC002": {
		CheckID:       "RBAC002",
		CISControls:   []string{"5.1.3"},
		NSACISARef:    []string{"IAM-3"},
		NISTControls:  []string{"AC-6(1)", "AC-6(5)"},
		SOC2Controls:  []string{"CC6.1"},
		PCIDSSReqs:    []string{"7.1.2"},
	},
	"RBAC003": {
		CheckID:       "RBAC003",
		CISControls:   []string{"5.1.4", "5.1.5"},
		NSACISARef:    []string{"IAM-4"},
		NISTControls:  []string{"AC-6(9)", "AC-6(10)"},
		SOC2Controls:  []string{"CC6.2", "CC6.3"},
		PCIDSSReqs:    []string{"7.2.1"},
	},
	"RBAC004": {
		CheckID:       "RBAC004",
		CISControls:   []string{"5.1.6"},
		NSACISARef:    []string{"IAM-5"},
		NISTControls:  []string{"AC-2(1)", "AC-2(4)"},
		SOC2Controls:  []string{"CC6.1", "CC6.2"},
		PCIDSSReqs:    []string{"7.1.1"},
	},
	"RBAC005": {
		CheckID:       "RBAC005",
		CISControls:   []string{"5.1.8"},
		NSACISARef:    []string{"IAM-6"},
		NISTControls:  []string{"AC-6(2)"},
		SOC2Controls:  []string{"CC6.3"},
		PCIDSSReqs:    []string{"7.2.2"},
	},
	"RBAC006": {
		CheckID:       "RBAC006",
		CISControls:   []string{"5.2.1"},
		NSACISARef:    []string{"IAM-7"},
		NISTControls:  []string{"AC-3(4)"},
		SOC2Controls:  []string{"CC6.1"},
		PCIDSSReqs:    []string{"7.1"},
	},
	"RBAC007": {
		CheckID:       "RBAC007",
		CISControls:   []string{"5.2.2"},
		NSACISARef:    []string{"IAM-8"},
		NISTControls:  []string{"AC-2(3)"},
		SOC2Controls:  []string{"CC6.2"},
		PCIDSSReqs:    []string{"7.1.3"},
	},
	"RBAC008": {
		CheckID:       "RBAC008",
		CISControls:   []string{"5.2.3"},
		NSACISARef:    []string{"IAM-9"},
		NISTControls:  []string{"AC-6"},
		SOC2Controls:  []string{"CC6.1"},
		PCIDSSReqs:    []string{"7.2"},
	},
	"RBAC009": {
		CheckID:       "RBAC009",
		CISControls:   []string{"5.2.4"},
		NSACISARef:    []string{"IAM-10"},
		NISTControls:  []string{"AC-6(1)"},
		SOC2Controls:  []string{"CC6.3"},
		PCIDSSReqs:    []string{"7.2.1"},
	},
	"RBAC010": {
		CheckID:       "RBAC010",
		CISControls:   []string{"5.2.5"},
		NSACISARef:    []string{"IAM-11"},
		NISTControls:  []string{"AC-2(2)"},
		SOC2Controls:  []string{"CC6.1", "CC6.2"},
		PCIDSSReqs:    []string{"7.1.2"},
	},
	"RBAC011": {
		CheckID:       "RBAC011",
		CISControls:   []string{"5.2.6"},
		NSACISARef:    []string{"IAM-12"},
		NISTControls:  []string{"AC-3"},
		SOC2Controls:  []string{"CC6.1"},
		PCIDSSReqs:    []string{"7.2"},
	},
	"RBAC012": {
		CheckID:       "RBAC012",
		CISControls:   []string{"5.3.1"},
		NSACISARef:    []string{"IAM-13"},
		NISTControls:  []string{"AC-2(7)"},
		SOC2Controls:  []string{"CC6.2"},
		PCIDSSReqs:    []string{"7.1.4"},
	},
	"RBAC013": {
		CheckID:       "RBAC013",
		CISControls:   []string{"5.3.2"},
		NSACISARef:    []string{"IAM-14"},
		NISTControls:  []string{"AC-6(5)"},
		SOC2Controls:  []string{"CC6.3"},
		PCIDSSReqs:    []string{"7.2.2"},
	},
	"RBAC014": {
		CheckID:       "RBAC014",
		CISControls:   []string{"5.4.1"},
		NSACISARef:    []string{"IAM-15"},
		NISTControls:  []string{"AC-6"},
		SOC2Controls:  []string{"CC6.1"},
		PCIDSSReqs:    []string{"7.1"},
	},
	"RBAC015": {
		CheckID:       "RBAC015",
		CISControls:   []string{"5.4.2"},
		NSACISARef:    []string{"IAM-16"},
		NISTControls:  []string{"AC-2", "AC-3"},
		SOC2Controls:  []string{"CC6.1", "CC6.2"},
		PCIDSSReqs:    []string{"7.1", "7.2"},
	},

	"PSS001": {
		CheckID:       "PSS001",
		CISControls:   []string{"5.2.1", "5.2.2"},
		NSACISARef:    []string{"POD-1"},
		NISTControls:  []string{"AC-6", "CM-7"},
		SOC2Controls:  []string{"CC6.1", "CC6.6"},
		PCIDSSReqs:    []string{"2.2", "6.2"},
	},
	"PSS002": {
		CheckID:       "PSS002",
		CISControls:   []string{"5.2.3"},
		NSACISARef:    []string{"POD-2"},
		NISTControls:  []string{"AC-6(10)"},
		SOC2Controls:  []string{"CC6.1"},
		PCIDSSReqs:    []string{"2.2.1"},
	},
	"PSS003": {
		CheckID:       "PSS003",
		CISControls:   []string{"5.2.4"},
		NSACISARef:    []string{"POD-3"},
		NISTControls:  []string{"AC-3(3)"},
		SOC2Controls:  []string{"CC6.6"},
		PCIDSSReqs:    []string{"2.2.2"},
	},
	"PSS004": {
		CheckID:       "PSS004",
		CISControls:   []string{"5.2.5"},
		NSACISARef:    []string{"POD-4"},
		NISTControls:  []string{"AC-6", "SC-7"},
		SOC2Controls:  []string{"CC6.1", "CC6.6"},
		PCIDSSReqs:    []string{"1.3", "2.2"},
	},
	"PSS005": {
		CheckID:       "PSS005",
		CISControls:   []string{"5.2.6"},
		NSACISARef:    []string{"POD-5"},
		NISTControls:  []string{"AC-6(1)"},
		SOC2Controls:  []string{"CC6.1"},
		PCIDSSReqs:    []string{"2.2"},
	},
	"PSS006": {
		CheckID:       "PSS006",
		CISControls:   []string{"5.2.7"},
		NSACISARef:    []string{"POD-6"},
		NISTControls:  []string{"CM-7"},
		SOC2Controls:  []string{"CC6.6"},
		PCIDSSReqs:    []string{"2.2.3"},
	},
	"PSS007": {
		CheckID:       "PSS007",
		CISControls:   []string{"5.2.8"},
		NSACISARef:    []string{"POD-7"},
		NISTControls:  []string{"CM-7(1)"},
		SOC2Controls:  []string{"CC6.6"},
		PCIDSSReqs:    []string{"2.2.4"},
	},
	"PSS008": {
		CheckID:       "PSS008",
		CISControls:   []string{"5.2.9"},
		NSACISARef:    []string{"POD-8"},
		NISTControls:  []string{"SC-4"},
		SOC2Controls:  []string{"CC6.1"},
		PCIDSSReqs:    []string{"3.4"},
	},
	"PSS009": {
		CheckID:       "PSS009",
		CISControls:   []string{"5.2.10"},
		NSACISARef:    []string{"POD-9"},
		NISTControls:  []string{"AC-6"},
		SOC2Controls:  []string{"CC6.1"},
		PCIDSSReqs:    []string{"7.1"},
	},
	"PSS010": {
		CheckID:       "PSS010",
		CISControls:   []string{"5.2.11"},
		NSACISARef:    []string{"POD-10"},
		NISTControls:  []string{"CM-7"},
		SOC2Controls:  []string{"CC6.6"},
		PCIDSSReqs:    []string{"2.2"},
	},

	"NET001": {
		CheckID:       "NET001",
		CISControls:   []string{"5.3.1"},
		NSACISARef:    []string{"NET-1"},
		NISTControls:  []string{"SC-7", "SC-7(5)"},
		SOC2Controls:  []string{"CC6.6", "CC6.7"},
		PCIDSSReqs:    []string{"1.1", "1.2", "1.3"},
	},
	"NET002": {
		CheckID:       "NET002",
		CISControls:   []string{"5.3.2"},
		NSACISARef:    []string{"NET-2"},
		NISTControls:  []string{"SC-7(4)"},
		SOC2Controls:  []string{"CC6.6"},
		PCIDSSReqs:    []string{"1.2.1"},
	},
	"NET003": {
		CheckID:       "NET003",
		CISControls:   []string{"5.3.3"},
		NSACISARef:    []string{"NET-3"},
		NISTControls:  []string{"AC-4"},
		SOC2Controls:  []string{"CC6.6", "CC6.7"},
		PCIDSSReqs:    []string{"1.3.1"},
	},

	"CLOUD001": {
		CheckID:       "CLOUD001",
		CISControls:   []string{"5.4.1"},
		NSACISARef:    []string{"CLOUD-1"},
		NISTControls:  []string{"AC-2(12)", "AC-6"},
		SOC2Controls:  []string{"CC6.1", "CC6.2"},
		PCIDSSReqs:    []string{"7.1", "7.2"},
	},
	"CLOUD002": {
		CheckID:       "CLOUD002",
		CISControls:   []string{"5.4.2"},
		NSACISARef:    []string{"CLOUD-2"},
		NISTControls:  []string{"IA-5"},
		SOC2Controls:  []string{"CC6.1"},
		PCIDSSReqs:    []string{"8.2"},
	},
	"CLOUD003": {
		CheckID:       "CLOUD003",
		CISControls:   []string{"5.4.3"},
		NSACISARef:    []string{"CLOUD-3"},
		NISTControls:  []string{"AC-6(5)"},
		SOC2Controls:  []string{"CC6.3"},
		PCIDSSReqs:    []string{"7.2.1"},
	},

	"EXP001": {
		CheckID:       "EXP001",
		CISControls:   []string{"5.1.2"},
		NSACISARef:    []string{"SEC-1"},
		NISTControls:  []string{"SC-28", "SC-28(1)"},
		SOC2Controls:  []string{"CC6.1", "CC6.7"},
		PCIDSSReqs:    []string{"3.4", "3.5"},
	},
	"EXP002": {
		CheckID:       "EXP002",
		CISControls:   []string{"5.2.9"},
		NSACISARef:    []string{"SEC-2"},
		NISTControls:  []string{"AC-17"},
		SOC2Controls:  []string{"CC6.1", "CC6.6"},
		PCIDSSReqs:    []string{"2.3"},
	},
	"EXP003": {
		CheckID:       "EXP003",
		CISControls:   []string{"5.2.2"},
		NSACISARef:    []string{"SEC-3"},
		NISTControls:  []string{"AC-6", "CM-7"},
		SOC2Controls:  []string{"CC6.1", "CC6.6"},
		PCIDSSReqs:    []string{"2.2", "6.2"},
	},
	"EXP004": {
		CheckID:       "EXP004",
		CISControls:   []string{"5.1.1"},
		NSACISARef:    []string{"SEC-4"},
		NISTControls:  []string{"AC-2", "AC-6"},
		SOC2Controls:  []string{"CC6.1", "CC6.2"},
		PCIDSSReqs:    []string{"7.1"},
	},
	"EXP005": {
		CheckID:       "EXP005",
		CISControls:   []string{"5.1.3"},
		NSACISARef:    []string{"SEC-5"},
		NISTControls:  []string{"AC-6(1)"},
		SOC2Controls:  []string{"CC6.1"},
		PCIDSSReqs:    []string{"7.1.2"},
	},

	"COMMON001": {
		CheckID:       "COMMON001",
		CISControls:   []string{"5.1.5"},
		NSACISARef:    []string{"IAM-17"},
		NISTControls:  []string{"AC-6(9)"},
		SOC2Controls:  []string{"CC6.1"},
		PCIDSSReqs:    []string{"7.1"},
	},
	"COMMON002": {
		CheckID:       "COMMON002",
		CISControls:   []string{"5.1.1"},
		NSACISARef:    []string{"IAM-18"},
		NISTControls:  []string{"AC-2", "AC-6"},
		SOC2Controls:  []string{"CC6.1", "CC6.2"},
		PCIDSSReqs:    []string{"7.1", "7.2"},
	},
	"COMMON003": {
		CheckID:       "COMMON003",
		CISControls:   []string{"5.1.3"},
		NSACISARef:    []string{"IAM-19"},
		NISTControls:  []string{"AC-6"},
		SOC2Controls:  []string{"CC6.1"},
		PCIDSSReqs:    []string{"7.2"},
	},
	"COMMON004": {
		CheckID:       "COMMON004",
		CISControls:   []string{"5.2.1"},
		NSACISARef:    []string{"POD-11"},
		NISTControls:  []string{"AC-6", "CM-7"},
		SOC2Controls:  []string{"CC6.1", "CC6.6"},
		PCIDSSReqs:    []string{"2.2"},
	},
	"COMMON005": {
		CheckID:       "COMMON005",
		CISControls:   []string{"5.2.4"},
		NSACISARef:    []string{"POD-12"},
		NISTControls:  []string{"SC-7"},
		SOC2Controls:  []string{"CC6.6"},
		PCIDSSReqs:    []string{"1.3"},
	},
	"COMMON006": {
		CheckID:       "COMMON006",
		CISControls:   []string{"5.4.1"},
		NSACISARef:    []string{"SEC-6"},
		NISTControls:  []string{"SC-28"},
		SOC2Controls:  []string{"CC6.7"},
		PCIDSSReqs:    []string{"3.4"},
	},
	"COMMON007": {
		CheckID:       "COMMON007",
		CISControls:   []string{"5.3.2"},
		NSACISARef:    []string{"NET-4"},
		NISTControls:  []string{"SC-7", "AC-4"},
		SOC2Controls:  []string{"CC6.6"},
		PCIDSSReqs:    []string{"1.2"},
	},
}

type FrameworkInfo struct {
	ID          ComplianceFramework
	Name        string
	Version     string
	Description string
	URL         string
	Sections    []FrameworkSection
}

type FrameworkSection struct {
	ID          string
	Title       string
	Description string
	Controls    []ControlInfo
}

type ControlInfo struct {
	ID          string
	Title       string
	Description string
	Severity    string
}

var SupportedFrameworks = map[ComplianceFramework]FrameworkInfo{
	FrameworkCIS: {
		ID:          FrameworkCIS,
		Name:        "CIS Kubernetes Benchmark",
		Version:     "1.8.0",
		Description: "Center for Internet Security Kubernetes Benchmark",
		URL:         "https://www.cisecurity.org/benchmark/kubernetes",
		Sections: []FrameworkSection{
			{
				ID:          "5.1",
				Title:       "RBAC and Service Accounts",
				Description: "Controls for Role-Based Access Control configuration",
			},
			{
				ID:          "5.2",
				Title:       "Pod Security Standards",
				Description: "Controls for pod security configuration",
			},
			{
				ID:          "5.3",
				Title:       "Network Policies and CNI",
				Description: "Controls for network segmentation",
			},
			{
				ID:          "5.4",
				Title:       "Secrets Management",
				Description: "Controls for secrets handling",
			},
		},
	},
	FrameworkNSACISA: {
		ID:          FrameworkNSACISA,
		Name:        "NSA/CISA Kubernetes Hardening Guide",
		Version:     "1.2",
		Description: "NSA and CISA guidance for hardening Kubernetes",
		URL:         "https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF",
		Sections: []FrameworkSection{
			{
				ID:          "IAM",
				Title:       "Identity and Access Management",
				Description: "Authentication and authorization controls",
			},
			{
				ID:          "POD",
				Title:       "Pod Security",
				Description: "Pod-level security configurations",
			},
			{
				ID:          "NET",
				Title:       "Network Separation",
				Description: "Network policy and segmentation",
			},
			{
				ID:          "SEC",
				Title:       "Secrets Protection",
				Description: "Secrets and credential management",
			},
			{
				ID:          "CLOUD",
				Title:       "Cloud Identity",
				Description: "Cloud provider identity integration",
			},
		},
	},
	FrameworkNIST: {
		ID:          FrameworkNIST,
		Name:        "NIST 800-53",
		Version:     "Rev 5",
		Description: "NIST Security and Privacy Controls",
		URL:         "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
		Sections: []FrameworkSection{
			{
				ID:          "AC",
				Title:       "Access Control",
				Description: "Access control family controls",
			},
			{
				ID:          "SC",
				Title:       "System and Communications Protection",
				Description: "Protection of system communications",
			},
			{
				ID:          "CM",
				Title:       "Configuration Management",
				Description: "Configuration management controls",
			},
			{
				ID:          "IA",
				Title:       "Identification and Authentication",
				Description: "Identity management controls",
			},
		},
	},
	FrameworkSOC2: {
		ID:          FrameworkSOC2,
		Name:        "SOC 2 Type II",
		Version:     "2017",
		Description: "AICPA Service Organization Control 2",
		URL:         "https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aaborvoscmatrix.html",
		Sections: []FrameworkSection{
			{
				ID:          "CC6",
				Title:       "Logical and Physical Access Controls",
				Description: "Access control criteria",
			},
		},
	},
	FrameworkPCIDSS: {
		ID:          FrameworkPCIDSS,
		Name:        "PCI DSS",
		Version:     "4.0",
		Description: "Payment Card Industry Data Security Standard",
		URL:         "https://www.pcisecuritystandards.org/",
		Sections: []FrameworkSection{
			{
				ID:          "1",
				Title:       "Network Security Controls",
				Description: "Install and maintain network security controls",
			},
			{
				ID:          "2",
				Title:       "Secure Configurations",
				Description: "Apply secure configurations",
			},
			{
				ID:          "3",
				Title:       "Protect Stored Data",
				Description: "Protect stored account data",
			},
			{
				ID:          "7",
				Title:       "Restrict Access",
				Description: "Restrict access by business need to know",
			},
			{
				ID:          "8",
				Title:       "Identify Users",
				Description: "Identify users and authenticate access",
			},
		},
	},
}

func GetControlsForCheck(checkID string) *ControlMapping {
	if mapping, ok := CheckControlMappings[checkID]; ok {
		return &mapping
	}
	return nil
}

func GetAllFrameworks() []ComplianceFramework {
	return []ComplianceFramework{
		FrameworkCIS,
		FrameworkNSACISA,
		FrameworkNIST,
		FrameworkSOC2,
		FrameworkPCIDSS,
	}
}
