// Package html renders a human-readable security dashboard.
package html

import (
	"html/template"
	"io"
	"sort"
	"strings"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

func isURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// refCodes — References дотроос compliance/ID кодуудыг (URL биш) буцаана.
func refCodes(refs []string) []string {
	var out []string
	for _, r := range refs {
		if !isURL(r) {
			out = append(out, r)
		}
	}
	return out
}

// refURLs — References дотроос URL-уудыг буцаана.
func refURLs(refs []string) []string {
	var out []string
	for _, r := range refs {
		if isURL(r) {
			out = append(out, r)
		}
	}
	return out
}

// linkLabel — URL-аас ойлгомжтой нэр гаргана.
func linkLabel(u string) string {
	h := u
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.Index(h, "/"); i >= 0 {
		h = h[:i]
	}
	switch {
	case strings.Contains(h, "aquasec"):
		return "Trivy Advisory"
	case strings.Contains(h, "bridgecrew"), strings.Contains(h, "checkov"):
		return "Checkov Docs"
	case strings.Contains(h, "kubernetes.io"):
		return "Kubernetes Docs"
	case strings.Contains(h, "mitre"):
		return "MITRE ATT&CK"
	case strings.Contains(h, "nsa"):
		return "NSA Hardening"
	default:
		return h
	}
}

var funcs = template.FuncMap{
	"count":     func(m map[finding.Severity]int, k string) int { return m[finding.Severity(k)] },
	"refCodes":  refCodes,
	"refURLs":   refURLs,
	"linkLabel": linkLabel,
}
var tmpl = template.Must(template.New("report").Funcs(funcs).Parse(dashboard))

// view — тайлангийн загварт дамжуулах өгөгдөл (ScanResult + тооцоолсон хэсгүүд).
type view struct {
	finding.ScanResult
	TopRisks        []finding.Finding
	Recommendations []string
}

// Render — ScanResult -> HTML dashboard.
func Render(w io.Writer, res finding.ScanResult) error {
	vm := view{ScanResult: res}

	// Top risks: penalty (risk_contribution) их нь эхэнд.
	sorted := append([]finding.Finding(nil), res.Findings...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].RiskContribution > sorted[j].RiskContribution
	})
	seenRem := map[string]bool{}
	for _, f := range sorted {
		if f.Severity == finding.SeverityInfo || f.RiskContribution <= 0 {
			continue
		}
		if len(vm.TopRisks) < 5 {
			vm.TopRisks = append(vm.TopRisks, f)
		}
		if f.Remediation != "" && !seenRem[f.Remediation] && len(vm.Recommendations) < 5 {
			seenRem[f.Remediation] = true
			vm.Recommendations = append(vm.Recommendations, f.Remediation)
		}
	}
	return tmpl.Execute(w, vm)
}

const dashboard = `<!DOCTYPE html>
<html lang="mn">
<head>
<meta charset="utf-8">
<title>TATAR-Kuber Security Report</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f4f6f8;color:#1a1a1a}
 header{background:#2A4D69;color:#fff;padding:20px 28px}
 header h1{margin:0;font-size:22px}
 header .sub{opacity:.8;font-size:13px;margin-top:4px}
 .wrap{padding:20px 28px}
 h2{font-size:17px;color:#2A4D69;border-bottom:2px solid #e1e8ee;padding-bottom:6px;margin:26px 0 14px}
 .cards{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:18px}
 .card{background:#fff;border-radius:8px;padding:14px 18px;min-width:96px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
 .card .n{font-size:26px;font-weight:700}
 .card .l{font-size:11px;color:#666;text-transform:uppercase;letter-spacing:.5px}
 .crit{color:#b3123b}.high{color:#d9480f}.med{color:#b8860b}.low{color:#2b7a3b}.info{color:#555}
 .score{background:#1F6F54;color:#fff}.score .n{color:#fff}.score .l{color:#dfeee8}
 .exec{display:flex;gap:22px;flex-wrap:wrap;background:#fff;border-radius:8px;padding:16px 20px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
 .exec .col{flex:1;min-width:280px}
 .exec h3{font-size:14px;margin:0 0 8px;color:#2A4D69}
 .exec ol,.exec ul{margin:0;padding-left:20px}
 .exec li{margin:5px 0;font-size:13px}
 .pen{color:#b3123b;font-weight:700}
 .cc{color:#888;font-size:11px}
 table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08)}
 th{background:#2A4D69;color:#fff;text-align:left;padding:9px 11px;font-size:11px;text-transform:uppercase}
 td{padding:8px 11px;border-top:1px solid #eee;font-size:13px;vertical-align:top}
 tr:nth-child(even) td{background:#f8fafb}
 .badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;color:#fff}
 .bC{background:#b3123b}.bH{background:#d9480f}.bM{background:#b8860b}.bL{background:#2b7a3b}.bI{background:#888}
 .bs{background:#6b46c1;color:#fff;padding:1px 6px;border-radius:8px;font-size:10px}
 .fb{color:#555;font-size:12px}
 .fix{color:#1F6F54;font-size:12px}
 .ev{font-size:11px;color:#333;max-width:320px}
 .evrow{margin:1px 0;word-break:break-all}
 .evrow code{font-family:Consolas,monospace;color:#1a1a1a}
 .evs{display:inline-block;background:#e6edf3;color:#2A4D69;border-radius:6px;padding:0 5px;font-size:10px;font-weight:700}
 .evv{color:#1F6F54}
 .fbb{display:inline-block;background:#2A4D69;color:#fff;border-radius:4px;padding:1px 6px;font-size:10px;font-weight:700;margin:1px 2px 1px 0;letter-spacing:.5px}
 .cmp{display:inline-block;background:#eef2f6;color:#42586b;border:1px solid #d5dee6;border-radius:4px;padding:0 5px;font-size:10px;margin:1px 2px 0 0}
 .ref{display:inline-block;margin:2px 6px 0 0;font-size:11px;color:#1a6fb5;text-decoration:none}
 .ref:hover{text-decoration:underline}
 footer{padding:18px 28px;color:#667;font-size:12px;border-top:1px solid #e1e8ee;margin-top:24px}
 footer .grid{display:flex;gap:34px;flex-wrap:wrap}
 footer b{color:#2A4D69}
</style>
</head>
<body>
<header>
 <h1>TATAR-Kuber Security Report</h1>
 <div class="sub">Cluster: {{.Metadata.ClusterName}} · Mode: {{.Metadata.ScanMode}} · {{.Metadata.FinishedAt}}</div>
</header>
<div class="wrap">

 <h2>Executive Summary</h2>
 <div class="cards">
  <div class="card score"><div class="n">{{.Summary.RiskScore}}/100</div><div class="l">{{.Summary.RiskBand}}</div></div>
  <div class="card"><div class="n crit">{{count .Summary.Counts "CRITICAL"}}</div><div class="l">Critical</div></div>
  <div class="card"><div class="n high">{{count .Summary.Counts "HIGH"}}</div><div class="l">High</div></div>
  <div class="card"><div class="n med">{{count .Summary.Counts "MEDIUM"}}</div><div class="l">Medium</div></div>
  <div class="card"><div class="n low">{{count .Summary.Counts "LOW"}}</div><div class="l">Low</div></div>
  <div class="card"><div class="n info">{{count .Summary.Counts "INFO"}}</div><div class="l">Info</div></div>
  <div class="card"><div class="n">{{.Summary.BlindShot}}</div><div class="l">Blind Shot</div></div>
 </div>
 <div class="exec">
  <div class="col">
   <h3>Гол эрсдэлүүд (Top Risks) — оноо задаргаа</h3>
   <ol>
   {{range .TopRisks}}<li>{{.Title}} <span class="pen">−{{.RiskContribution}}</span><br><span class="cc">{{.CanonicalControl}} · {{if .Namespace}}{{.Namespace}}/{{end}}{{.Resource}}</span></li>{{end}}
   {{if not .TopRisks}}<li class="cc">Эрсдэл илрээгүй</li>{{end}}
   </ol>
  </div>
  <div class="col">
   <h3>Зөвлөмж (Recommendations)</h3>
   <ul>
   {{range .Recommendations}}<li>{{.}}</li>{{end}}
   {{if not .Recommendations}}<li class="cc">—</li>{{end}}
   </ul>
  </div>
 </div>

{{if .Metadata.Inventory}}
 <h2>Cluster Inventory</h2>
 <div class="cards">
  {{range $k,$v := .Metadata.Inventory}}<div class="card"><div class="n">{{$v}}</div><div class="l">{{$k}}</div></div>{{end}}
 </div>
{{end}}

 <h2>Findings ({{.Summary.TotalFindings}})</h2>
 <table>
  <thead><tr><th>Severity</th><th>Control</th><th>Resource</th><th>Title</th><th>Evidence (нотолгоо)</th><th>Засвар (Fix)</th><th>Found by</th><th>Conf.</th></tr></thead>
  <tbody>
  {{range .Findings}}
   <tr>
    <td><span class="badge {{if eq (printf "%s" .Severity) "CRITICAL"}}bC{{else if eq (printf "%s" .Severity) "HIGH"}}bH{{else if eq (printf "%s" .Severity) "MEDIUM"}}bM{{else if eq (printf "%s" .Severity) "LOW"}}bL{{else}}bI{{end}}">{{.Severity}}</span>{{if .BlindShot}} <span class="bs">blind</span>{{end}}</td>
    <td>{{.CanonicalControl}}<br><span class="cc">{{.Category}}</span>{{with refCodes .References}}<br>{{range .}}<span class="cmp">{{.}}</span>{{end}}{{end}}</td>
    <td>{{if .Namespace}}{{.Namespace}}/{{end}}{{.Resource}}</td>
    <td>{{.Title}}{{if .BlindShot}}<br><span class="fb">{{.BlindShotReason}}</span>{{end}}{{with refURLs .References}}<br>{{range .}}<a class="ref" href="{{.}}" target="_blank" rel="noopener">{{linkLabel .}}</a>{{end}}{{end}}</td>
    <td class="ev">{{if .Evidence}}{{range .Evidence}}<div class="evrow"><span class="evs">{{.Scanner}}</span> {{if .Path}}<code>{{.Path}}</code>{{end}}{{if .Detail}}{{.Detail}}{{end}}{{if .Value}} <span class="evv">({{.Value}})</span>{{end}}</div>{{end}}{{else}}—{{end}}</td>
    <td class="fix">{{.Remediation}}</td>
    <td>{{range .FoundBy}}<span class="fbb">{{.}}</span>{{end}}</td>
    <td class="fb">{{.Confidence}}</td>
   </tr>
  {{end}}
  </tbody>
 </table>
</div>
<footer>
 <div class="grid">
  <div><b>Scanner Versions</b><br>{{range $k,$v := .Metadata.ScannerVersions}}{{$k}} {{$v}}<br>{{end}}</div>
  <div><b>Schema</b><br>Finding v{{.SchemaVersion}}</div>
  <div><b>Result Hash</b><br>{{.Metadata.ResultHash}}</div>
  <div><b>Generated By</b><br>TATAR-Kuber {{.Metadata.TatarVersion}}</div>
  <div><b>Scoring Bands</b><br>90-100 Excellent<br>70-89 Good<br>50-69 Fair<br>30-49 Poor<br>0-29 Critical</div>
 </div>
</footer>
</body>
</html>
`
