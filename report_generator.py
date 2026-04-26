"""
Report Generator for ShadowTrace
Produces professional forensic reports in HTML and Plain Text formats.
"""

import os
import sys
from datetime import datetime
from html import escape

def get_asset_path(filename):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, "assets", filename)
    return os.path.join("assets", filename)

class ReportGenerator:
    MAX_DETAILED_FINDINGS = 500

    def __init__(self, case_name, examiner, image_path, analysis_time,
                 modules_analyzed, module_summaries, findings, log_text=""):
        self.case_name = case_name
        self.examiner = examiner
        self.image_path = image_path
        self.analysis_time = analysis_time
        self.modules_analyzed = modules_analyzed
        self.module_summaries = module_summaries
        self.findings = findings
        self.log_text = log_text

    # ------------------------------------------------------------------ #
    #  Computed metrics                                                    #
    # ------------------------------------------------------------------ #

    def _severity_counts(self):
        counts = {"High": 0, "Medium": 0, "Low": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def _module_finding_counts(self):
        counts = {}
        for f in self.findings:
            counts[f.module] = counts.get(f.module, 0) + 1
        return counts

    def _total_scanned(self):
        return sum(s.get("totalFilesScanned", 0) for s in self.module_summaries.values())

    def _total_suspicious(self):
        return sum(s.get("suspiciousFiles", 0) for s in self.module_summaries.values())

    def _risk_level(self):
        sc = self._severity_counts()
        if sc["High"] >= 5:
            return "CRITICAL"
        if sc["High"] >= 1:
            return "HIGH"
        if sc["Medium"] >= 3:
            return "ELEVATED"
        if self.findings:
            return "MODERATE"
        return "LOW"

    def _get_logo_base64(self):
        try:
            import base64
            logo_path = get_asset_path("shadowtrace_logo.png")
            with open(logo_path, "rb") as f:
                b64 = base64.b64encode(f.read()).decode("utf-8")
                return f"data:image/png;base64,{b64}"
        except Exception:
            return ""

    # ================================================================== #
    #  HTML REPORT                                                        #
    # ================================================================== #

    def generate_html(self, sections=None):
        s = sections or {}
        parts = [self._html_open()]
        if s.get("case_info", True):
            parts.append(self._html_case_info())
        if s.get("executive_summary", True):
            parts.append(self._html_executive_summary())
        if s.get("module_details", True):
            parts.append(self._html_module_details())
        if s.get("findings_table", True):
            parts.append(self._html_findings_table())
        if s.get("statistics", True):
            parts.append(self._html_statistics())
        if s.get("activity_log", True) and self.log_text.strip():
            parts.append(self._html_activity_log())
        parts.append(self._html_footer())
        return "\n".join(parts)

    def _html_open(self):
        logo_html = ""
        b64_logo = self._get_logo_base64()
        if b64_logo:
            logo_html = f'<img src="{b64_logo}" alt="Logo" style="height:70px;margin-right:20px;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,0.2);">'

        return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ShadowTrace Report — {escape(self.case_name)}</title>
<style>
:root{{--pr:#1F6FEB;--pd:#1558C0;--bg:#F4F6FA;--sf:#FFF;--tx:#1A1A2E;
--mu:#6C757D;--bd:#DEE2E6;--hi:#DC3545;--md:#FD7E14;--lo:#FFC107;--ok:#28A745;}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);
color:var(--tx);line-height:1.6;font-size:14px}}
.hdr{{background:linear-gradient(135deg,#0D1B3E 0%,#1A3A6E 50%,var(--pr) 100%);
color:#fff;padding:40px 48px;position:relative;overflow:hidden;display:flex;align-items:center;}}
.hdr::after{{content:'';position:absolute;top:-50%;right:-10%;width:400px;height:400px;
border-radius:50%;background:rgba(255,255,255,.04)}}
.hdr h1{{font-size:28px;font-weight:700;letter-spacing:-.5px;line-height:1.2}}
.hdr h2{{font-size:15px;font-weight:400;opacity:.8;margin-top:4px}}
.hdr .meta{{margin-top:12px;font-size:13px;opacity:.7}}
.wrap{{max-width:1100px;margin:0 auto;padding:24px 32px 48px}}
.card{{background:var(--sf);border:1px solid var(--bd);border-radius:10px;
padding:28px 32px;margin-bottom:24px;box-shadow:0 1px 3px rgba(0,0,0,.04)}}
.card h3{{font-size:17px;font-weight:700;margin-bottom:16px;padding-bottom:10px;
border-bottom:2px solid var(--pr);color:var(--pr)}}
.card h4{{font-size:14px;font-weight:600;margin:16px 0 8px}}
.kv{{display:grid;grid-template-columns:180px 1fr;gap:6px 16px;font-size:14px}}
.kv .k{{font-weight:600;color:var(--mu)}} .kv .v{{color:var(--tx)}}
table{{width:100%;border-collapse:collapse;font-size:13px;margin-top:10px}}
th{{background:#F0F3F8;font-weight:600;text-align:left;padding:10px 12px;
border-bottom:2px solid var(--bd);font-size:12px;text-transform:uppercase;
letter-spacing:.5px;color:var(--mu)}}
td{{padding:9px 12px;border-bottom:1px solid #F0F2F5}}
tr:hover td{{background:#F8FAFD}}
.sev{{display:inline-block;padding:2px 10px;border-radius:12px;font-size:12px;
font-weight:600;color:#fff;min-width:60px;text-align:center}}
.sev-High{{background:var(--hi)}} .sev-Medium{{background:var(--md);color:#333}}
.sev-Low{{background:var(--lo);color:#333}}
.bar-wrap{{background:#EBEEF3;border-radius:6px;height:22px;position:relative;
margin:4px 0;overflow:hidden}}
.bar{{height:100%;border-radius:6px;display:flex;align-items:center;
padding-left:8px;font-size:11px;font-weight:600;color:#fff;min-width:28px;
transition:width .5s ease}}
.risk{{display:inline-block;padding:4px 16px;border-radius:6px;font-weight:700;
font-size:14px;letter-spacing:.5px}}
.risk-CRITICAL,.risk-HIGH{{background:#FDECEA;color:var(--hi)}}
.risk-ELEVATED{{background:#FFF4E5;color:#E65100}}
.risk-MODERATE{{background:#FFF8E1;color:#F57F17}}
.risk-LOW{{background:#E8F5E9;color:var(--ok)}}
.log{{background:#1E1E2E;color:#D4D4D4;padding:20px;border-radius:8px;
font-family:'Cascadia Mono','Fira Code',monospace;font-size:12px;
white-space:pre-wrap;max-height:400px;overflow-y:auto}}
.ft{{text-align:center;padding:32px;font-size:12px;color:var(--mu);
border-top:1px solid var(--bd);margin-top:32px}}
.cols{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
@media(max-width:768px){{.cols{{grid-template-columns:1fr}}.wrap{{padding:16px}}}}
@media print{{body{{background:#fff}}.card{{box-shadow:none;break-inside:avoid}}
.hdr{{background:#1A3A6E!important;-webkit-print-color-adjust:exact}}}}
</style></head><body>
<div class="hdr">
{logo_html}
<div>
<h1>ShadowTrace</h1>
<h2>Forensic Analysis Report</h2>
<div class="meta">Generated {escape(self.analysis_time)} &bull; Case: {escape(self.case_name)}</div>
</div>
</div>
<div class="wrap">"""

    def _html_case_info(self):
        img = os.path.basename(self.image_path) if self.image_path else "N/A"
        mods = ", ".join(self.modules_analyzed) if self.modules_analyzed else "None"
        return f"""<div class="card"><h3>Case Information</h3>
<div class="kv">
<span class="k">Case Name</span><span class="v">{escape(self.case_name)}</span>
<span class="k">Examiner</span><span class="v">{escape(self.examiner)}</span>
<span class="k">Evidence File</span><span class="v">{escape(img)}</span>
<span class="k">Analysis Date</span><span class="v">{escape(self.analysis_time)}</span>
<span class="k">Modules Executed</span><span class="v">{escape(mods)}</span>
<span class="k">Total Modules</span><span class="v">{len(self.modules_analyzed)}</span>
</div></div>"""

    def _html_executive_summary(self):
        sc = self._severity_counts()
        total = self._total_scanned()
        susp = self._total_suspicious()
        risk = self._risk_level()
        return f"""<div class="card"><h3>Executive Summary</h3>
<div class="cols"><div>
<div class="kv">
<span class="k">Total Files Scanned</span><span class="v">{total:,}</span>
<span class="k">Suspicious Files</span><span class="v">{susp:,}</span>
<span class="k">Total Findings</span><span class="v">{len(self.findings):,}</span>
<span class="k">Risk Assessment</span><span class="v"><span class="risk risk-{risk}">{risk}</span></span>
</div></div><div>
<h4>Findings by Severity</h4>
<div class="kv">
<span class="k"><span class="sev sev-High">High</span></span><span class="v">{sc['High']}</span>
<span class="k"><span class="sev sev-Medium">Medium</span></span><span class="v">{sc['Medium']}</span>
<span class="k"><span class="sev sev-Low">Low</span></span><span class="v">{sc['Low']}</span>
</div></div></div></div>"""

    def _html_module_details(self):
        rows = []
        mc = self._module_finding_counts()
        for mod in self.modules_analyzed:
            s = self.module_summaries.get(mod, {})
            scanned = s.get("totalFilesScanned", 0)
            suspicious = s.get("suspiciousFiles", 0)
            findings = mc.get(mod, 0)
            rows.append(f"<tr><td>{escape(mod)}</td><td>{scanned:,}</td>"
                        f"<td>{suspicious:,}</td><td>{findings:,}</td></tr>")
        return f"""<div class="card"><h3>Module Analysis Results</h3>
<table><tr><th>Module</th><th>Files Scanned</th><th>Suspicious</th>
<th>Findings</th></tr>{''.join(rows)}</table></div>"""

    def _html_findings_table(self):
        if not self.findings:
            return '<div class="card"><h3>Detailed Findings</h3><p>No findings to report.</p></div>'
        display = self.findings[:self.MAX_DETAILED_FINDINGS]
        rows = []
        for i, f in enumerate(display, 1):
            rules = escape(", ".join(f.rules)) if f.rules else ""
            rows.append(
                f'<tr><td>{i}</td><td>{escape(f.module)}</td>'
                f'<td style="word-break:break-all">{escape(f.artifact)}</td>'
                f'<td><span class="sev sev-{f.severity}">{f.severity}</span></td>'
                f'<td>{f.confidence}%</td><td style="font-size:12px">{rules}</td></tr>'
            )
        note = ""
        if len(self.findings) > self.MAX_DETAILED_FINDINGS:
            omitted = len(self.findings) - self.MAX_DETAILED_FINDINGS
            note = f'<p style="color:var(--mu);margin-top:10px;font-size:13px">Showing {self.MAX_DETAILED_FINDINGS} of {len(self.findings)} findings ({omitted} omitted for brevity).</p>'
        return f"""<div class="card"><h3>Detailed Findings</h3>
<table><tr><th>#</th><th>Module</th><th>Artifact</th><th>Severity</th>
<th>Confidence</th><th>Rules Triggered</th></tr>{''.join(rows)}</table>{note}</div>"""

    def _html_statistics(self):
        mc = self._module_finding_counts()
        if not mc:
            return ""
        max_val = max(mc.values()) if mc else 1
        bars = []
        colors = ["#1F6FEB", "#6F42C1", "#20C997", "#FD7E14", "#E83E8C", "#17A2B8"]
        for i, (mod, cnt) in enumerate(mc.items()):
            pct = (cnt / max_val * 100) if max_val else 0
            c = colors[i % len(colors)]
            bars.append(f'<div style="margin-bottom:8px"><div style="font-size:13px;'
                        f'font-weight:600;margin-bottom:2px">{escape(mod)}</div>'
                        f'<div class="bar-wrap"><div class="bar" style="width:{pct}%;'
                        f'background:{c}">{cnt}</div></div></div>')
        return f"""<div class="card"><h3>Statistics &amp; Distribution</h3>
<h4>Findings per Module</h4>{''.join(bars)}</div>"""

    def _html_activity_log(self):
        return f"""<div class="card"><h3>Activity Log</h3>
<div class="log">{escape(self.log_text)}</div></div>"""

    def _html_footer(self):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return f"""<div class="ft">
<strong>ShadowTrace — Advanced Digital Forensics</strong><br>
Report generated on {now}<br>
This report was generated automatically. All findings should be independently
verified by a qualified forensic examiner before being used as evidence.<br>
&copy; 2026 ShadowTrace Project &bull; For authorized use only
</div></div></body></html>"""

    # ================================================================== #
    #  PLAIN TEXT REPORT                                                  #
    # ================================================================== #

    def generate_text(self, sections=None):
        s = sections or {}
        w = 80
        lines = []
        lines.append("=" * w)
        lines.append("SHADOWTRACE".center(w))
        lines.append("FORENSIC ANALYSIS REPORT".center(w))
        lines.append("=" * w)
        lines.append("")

        if s.get("case_info", True):
            lines.append(self._text_section("CASE INFORMATION"))
            img = os.path.basename(self.image_path) if self.image_path else "N/A"
            mods = ", ".join(self.modules_analyzed) if self.modules_analyzed else "None"
            lines.append(f"  Case Name      : {self.case_name}")
            lines.append(f"  Examiner       : {self.examiner}")
            lines.append(f"  Evidence File  : {img}")
            lines.append(f"  Analysis Date  : {self.analysis_time}")
            lines.append(f"  Modules Run    : {mods}")
            lines.append("")

        if s.get("executive_summary", True):
            lines.append(self._text_section("EXECUTIVE SUMMARY"))
            sc = self._severity_counts()
            lines.append(f"  Total Files Scanned : {self._total_scanned():,}")
            lines.append(f"  Suspicious Files    : {self._total_suspicious():,}")
            lines.append(f"  Total Findings      : {len(self.findings):,}")
            lines.append(f"  Risk Assessment     : {self._risk_level()}")
            lines.append("")
            lines.append(f"  Severity Breakdown:")
            lines.append(f"    High   : {sc['High']}")
            lines.append(f"    Medium : {sc['Medium']}")
            lines.append(f"    Low    : {sc['Low']}")
            lines.append("")

        if s.get("module_details", True):
            lines.append(self._text_section("MODULE RESULTS"))
            mc = self._module_finding_counts()
            for mod in self.modules_analyzed:
                sm = self.module_summaries.get(mod, {})
                lines.append(f"  {mod}")
                lines.append(f"    Files Scanned : {sm.get('totalFilesScanned', 0):,}")
                lines.append(f"    Suspicious    : {sm.get('suspiciousFiles', 0):,}")
                lines.append(f"    Findings      : {mc.get(mod, 0):,}")
                lines.append("")

        if s.get("findings_table", True) and self.findings:
            lines.append(self._text_section("DETAILED FINDINGS"))
            display = self.findings[:self.MAX_DETAILED_FINDINGS]
            hdr = f"  {'#':<5} {'Module':<28} {'Artifact':<30} {'Sev':<8} {'Conf':<6}"
            lines.append(hdr)
            lines.append("  " + "-" * (len(hdr) - 2))
            for i, f in enumerate(display, 1):
                art = f.artifact if len(f.artifact) <= 28 else "..." + f.artifact[-25:]
                mod = f.module if len(f.module) <= 26 else f.module[:24] + ".."
                lines.append(f"  {i:<5} {mod:<28} {art:<30} {f.severity:<8} {f.confidence}%")
            if len(self.findings) > self.MAX_DETAILED_FINDINGS:
                lines.append(f"\n  ... {len(self.findings) - self.MAX_DETAILED_FINDINGS} additional findings omitted ...")
            lines.append("")

        if s.get("activity_log", True) and self.log_text.strip():
            lines.append(self._text_section("ACTIVITY LOG"))
            for line in self.log_text.strip().splitlines():
                lines.append(f"  {line}")
            lines.append("")

        lines.append("=" * w)
        lines.append("Generated by ShadowTrace".center(w))
        lines.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".center(w))
        lines.append("This report should be verified by a qualified examiner.".center(w))
        lines.append("=" * w)
        return "\n".join(lines)

    def _text_section(self, title):
        return f"{title}\n{'─' * 80}"
