// Package finding defines the TATAR-Kuber Unified Finding Schema v1.
// Энэ бол бүх scanner-ийн гаралт хөрвөх ганц стандарт загвар.
package finding

// Severity — normalize хийсэн 5 түвшин.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Type — finding-ийн төрөл.
type Type string

const (
	TypeMisconfig      Type = "misconfiguration"
	TypeVulnerability  Type = "vulnerability"
	TypeSecret         Type = "secret"
	TypeRBAC           Type = "rbac"
	TypeNetwork        Type = "network"
	TypeHygiene        Type = "hygiene"
)

// Status — finding lifecycle. MVP-д бүх finding OPEN. Шилжилт нь Enterprise/v2.
type Status string

const (
	StatusOpen             Status = "OPEN"
	StatusAcknowledged     Status = "ACKNOWLEDGED"
	StatusMitigationPlan   Status = "MITIGATION_PLANNED"
	StatusFixed            Status = "FIXED"
	StatusVerified         Status = "VERIFIED"
	StatusClosed           Status = "CLOSED"
)

// Confidence — итгэлийн зэрэг (scanner corroboration).
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"   // 3+ scanner
	ConfidenceMedium Confidence = "MEDIUM" // 1 scanner
	ConfidenceLow    Confidence = "LOW"    // контекст/эвристик
)

// RawRef — raw scanner гаралт руу заасан лавлагаа.
type RawRef struct {
	Scanner string `json:"scanner"`
	RuleID  string `json:"rule_id"`
}

// Evidence — асуудал яг хаана байгааг харуулах нотолгоо (scanner бүрээр).
// Path: spec зам эсвэл файл:мөр. Value: ажиглагдсан/зөвлөмж утга.
// Detail: чөлөөт текст (message, pkg@ver, secret match).
type Evidence struct {
	Scanner string `json:"scanner"`
	Path    string `json:"path,omitempty"`
	Value   string `json:"value,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// Finding — атомын нэгж (Unified Schema §3).
type Finding struct {
	ID               string     `json:"id"`
	CanonicalControl string     `json:"canonical_control"`
	Resource         string     `json:"resource"`
	Namespace        string     `json:"namespace,omitempty"`
	Type             Type       `json:"type"`
	Category         string     `json:"category"`
	Severity         Severity   `json:"severity"`
	OriginalSeverity Severity   `json:"original_severity,omitempty"`
	Title            string     `json:"title"`
	Description      string     `json:"description"`
	Evidence         []Evidence `json:"evidence,omitempty"` // асуудал яг хаана (scanner бүрээр)
	Remediation      string     `json:"remediation"`
	FoundBy          []string   `json:"found_by"`
	Confidence       Confidence `json:"confidence"`
	BlindShot        bool       `json:"blind_shot"`
	BlindShotReason  string     `json:"blind_shot_reason,omitempty"`
	RiskContribution float64    `json:"risk_contribution,omitempty"`
	Status           Status     `json:"status"`
	Owner            string     `json:"owner,omitempty"`
	FirstSeen        string     `json:"first_seen"`
	LastSeen         string     `json:"last_seen"`
	References       []string   `json:"references,omitempty"`
	RawRefs          []RawRef   `json:"raw_refs,omitempty"`
}

// ScanResult — scan-result.json дээд түвшний бүтэц (§2).
type ScanResult struct {
	SchemaVersion string    `json:"schema_version"`
	Metadata      Metadata  `json:"metadata"`
	Summary       Summary   `json:"summary"`
	Findings      []Finding `json:"findings"`
}

type Metadata struct {
	ScanID          string            `json:"scan_id"`
	ClusterName     string            `json:"cluster_name"`
	ScanMode        string            `json:"scan_mode"` // local | remote
	Lang            string            `json:"lang,omitempty"` // тайлангийн хэл: en | mn
	TatarVersion    string            `json:"tatar_version"`
	ScannerVersions map[string]string `json:"scanner_versions"`
	StartedAt       string            `json:"started_at"`
	FinishedAt      string            `json:"finished_at"`
	ResultHash      string            `json:"result_hash"`
	Inventory       map[string]int    `json:"inventory,omitempty"` // cluster объектын тоо (сонголт)
}

type Summary struct {
	Counts        map[Severity]int `json:"counts"`
	BlindShot     int              `json:"blind_shot"`
	RiskScore     int              `json:"risk_score"`
	RiskBand      string           `json:"risk_band"`
	TotalFindings int              `json:"total_findings"`
}

// NormalizeSeverity — scanner severity string -> TATAR Severity. Хоосон/UNKNOWN -> "".
func NormalizeSeverity(s string) Severity {
	switch s {
	case "CRITICAL", "Critical", "critical":
		return SeverityCritical
	case "HIGH", "High", "high":
		return SeverityHigh
	case "MEDIUM", "Medium", "medium":
		return SeverityMedium
	case "LOW", "Low", "low":
		return SeverityLow
	case "INFO", "Info", "info", "INFORMATIONAL":
		return SeverityInfo
	default:
		return "" // тодорхойгүй — canonical default_severity ашиглана
	}
}
