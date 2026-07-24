// Package html renders a human-readable security dashboard.
package html

import (
	"html/template"
	"io"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

var funcs = template.FuncMap{
	"count": func(m map[finding.Severity]int, k string) int { return m[finding.Severity(k)] },
}
var tmpl = template.Must(template.New("report").Funcs(funcs).Parse(dashboard))

// Render — ScanResult -> HTML dashboard.
func Render(w io.Writer, res finding.ScanResult) error {
	return tmpl.Execute(w, res)
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
 .wrap{padding:24px 28px}
 .cards{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:22px}
 .card{background:#fff;border-radius:8px;padding:16px 20px;min-width:110px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
 .card .n{font-size:28px;font-weight:700}
 .card .l{font-size:12px;color:#666;text-transform:uppercase;letter-spacing:.5px}
 .crit{color:#b3123b}.high{color:#d9480f}.med{color:#b8860b}.low{color:#2b7a3b}.info{color:#555}
 .score{background:#1F6F54;color:#fff}
 .score .n{color:#fff}.score .l{color:#dfeee8}
 table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08)}
 th{background:#2A4D69;color:#fff;text-align:left;padding:10px 12px;font-size:12px;text-transform:uppercase}
 td{padding:9px 12px;border-top:1px solid #eee;font-size:13px;vertical-align:top}
 tr:nth-child(even) td{background:#f8fafb}
 .badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;color:#fff}
 .bC{background:#b3123b}.bH{background:#d9480f}.bM{background:#b8860b}.bL{background:#2b7a3b}.bI{background:#888}
 .bs{background:#6b46c1;color:#fff;padding:1px 6px;border-radius:8px;font-size:10px}
 .fb{color:#555;font-size:12px}
 .fix{color:#1F6F54;font-size:12px}
 .ev{font-family:Consolas,monospace;font-size:11px;color:#333;word-break:break-all;max-width:280px}
</style>
</head>
<body>
<header>
 <h1>TATAR-Kuber Security Report</h1>
 <div class="sub">Cluster: {{.Metadata.ClusterName}} · Mode: {{.Metadata.ScanMode}} · {{.Metadata.FinishedAt}} · hash: {{.Metadata.ResultHash}}</div>
</header>
<div class="wrap">
 <div class="cards">
  <div class="card score"><div class="n">{{.Summary.RiskScore}}/100</div><div class="l">{{.Summary.RiskBand}}</div></div>
  <div class="card"><div class="n crit">{{count .Summary.Counts "CRITICAL"}}</div><div class="l">Critical</div></div>
  <div class="card"><div class="n high">{{count .Summary.Counts "HIGH"}}</div><div class="l">High</div></div>
  <div class="card"><div class="n med">{{count .Summary.Counts "MEDIUM"}}</div><div class="l">Medium</div></div>
  <div class="card"><div class="n low">{{count .Summary.Counts "LOW"}}</div><div class="l">Low</div></div>
  <div class="card"><div class="n info">{{count .Summary.Counts "INFO"}}</div><div class="l">Info</div></div>
  <div class="card"><div class="n">{{.Summary.BlindShot}}</div><div class="l">Blind Shot</div></div>
 </div>
 <table>
  <thead><tr><th>Severity</th><th>Control</th><th>Resource</th><th>Title</th><th>Evidence (нотолгоо)</th><th>Засвар (Fix)</th><th>Found by</th><th>Conf.</th></tr></thead>
  <tbody>
  {{range .Findings}}
   <tr>
    <td><span class="badge {{if eq (printf "%s" .Severity) "CRITICAL"}}bC{{else if eq (printf "%s" .Severity) "HIGH"}}bH{{else if eq (printf "%s" .Severity) "MEDIUM"}}bM{{else if eq (printf "%s" .Severity) "LOW"}}bL{{else}}bI{{end}}">{{.Severity}}</span>{{if .BlindShot}} <span class="bs">blind</span>{{end}}</td>
    <td>{{.CanonicalControl}}<br><span class="fb">{{.Category}}</span></td>
    <td>{{if .Namespace}}{{.Namespace}}/{{end}}{{.Resource}}</td>
    <td>{{.Title}}{{if .BlindShot}}<br><span class="fb">{{.BlindShotReason}}</span>{{end}}</td>
    <td class="ev">{{if .Evidence}}{{.Evidence}}{{else}}—{{end}}</td>
    <td class="fix">{{.Remediation}}</td>
    <td class="fb">{{range $i,$s := .FoundBy}}{{if $i}}, {{end}}{{$s}}{{end}}</td>
    <td class="fb">{{.Confidence}}</td>
   </tr>
  {{end}}
  </tbody>
 </table>
</div>
</body>
</html>
`
