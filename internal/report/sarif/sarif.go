// Package sarif renders findings as SARIF 2.1.0 (GitHub/GitLab/Azure DevOps).
// Тогтвортой canonical ruleId ашиглаж дедуп эвдэхгүй.
package sarif

import (
	"encoding/json"
	"io"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

const infoURI = "https://github.com/ochmunkh/tatar-kuber"

type sarifText struct {
	Text string `json:"text"`
}
type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}
type sarifArtifact struct {
	URI string `json:"uri"`
}
type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation sarifArtifact `json:"artifactLocation"`
	} `json:"physicalLocation"`
}
type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifText       `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	Properties map[string]any  `json:"properties,omitempty"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRun struct {
	Tool struct {
		Driver sarifDriver `json:"driver"`
	} `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

func level(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical, finding.SeverityHigh:
		return "error"
	case finding.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func securitySeverity(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return "9.5"
	case finding.SeverityHigh:
		return "8.0"
	case finding.SeverityMedium:
		return "5.0"
	case finding.SeverityLow:
		return "3.0"
	default:
		return "0.0"
	}
}

// Render — ScanResult -> SARIF 2.1.0 JSON.
func Render(w io.Writer, res finding.ScanResult) error {
	run := sarifRun{}
	run.Tool.Driver = sarifDriver{
		Name:           "TATAR-Kuber",
		Version:        res.Metadata.TatarVersion,
		InformationURI: infoURI,
	}

	seenRule := map[string]bool{}
	for _, f := range res.Findings {
		if !seenRule[f.CanonicalControl] {
			seenRule[f.CanonicalControl] = true
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
				ID:               f.CanonicalControl,
				Name:             f.Title,
				ShortDescription: sarifText{Text: f.Title},
				Properties: map[string]any{
					"security-severity": securitySeverity(f.Severity),
					"category":          f.Category,
				},
			})
		}
		loc := sarifLocation{}
		uri := f.Resource
		if f.Namespace != "" {
			uri = f.Namespace + "/" + f.Resource
		}
		loc.PhysicalLocation.ArtifactLocation = sarifArtifact{URI: uri}
		run.Results = append(run.Results, sarifResult{
			RuleID:    f.CanonicalControl,
			Level:     level(f.Severity),
			Message:   sarifText{Text: f.Title + " — " + f.Remediation},
			Locations: []sarifLocation{loc},
			Properties: map[string]any{
				"found_by":   f.FoundBy,
				"confidence": string(f.Confidence),
				"blind_shot": f.BlindShot,
				"tatar_id":   f.ID,
			},
		})
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
