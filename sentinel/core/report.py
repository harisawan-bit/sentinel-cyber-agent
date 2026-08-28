"""Autonomous HTML report generation — dark, agency-grade, no third-party JS.

Builds a self-contained HTML report from a list of findings dicts: severity
heatmap, findings grouped by target and type, zero external dependencies.
"""
from __future__ import annotations
import html, json
from collections import Counter, defaultdict
from typing import Dict, List, Any

SEV_COLORS = {
    "critical": "#ff3b5c", "high": "#ff7a45", "medium": "#ffc14d",
    "low": "#5bc0ff", "info": "#8a93a6", "unknown": "#8a93a6",
}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def render(findings: List[Dict[str, Any]], title: str = "Sentinel Report") -> str:
    sev_counts = Counter(f.get("severity", "info") for f in findings)
    by_target = defaultdict(list)
    for f in findings:
        by_target[f.get("target", "?")].append(f)

    cards = ""
    for target, fs in sorted(by_target.items()):
        tcount = Counter(f.get("severity", "info") for f in fs)
        heat = "".join(
            f'<span class="pill" style="background:{SEV_COLORS.get(s, "#8a93a6")}">'
            f'{s}: {tcount.get(s,0)}</span>' for s in SEV_ORDER if tcount.get(s)
        )
        rows = ""
        for f in fs:
            meta = f.get("metadata") or {}
            metaline = " · ".join(f"{k}={v}" for k, v in meta.items() if v not in (None, ""))
            rows += (
                f'<tr><td><span class="sev" style="background:{SEV_COLORS.get(f.get("severity","info"))}">'
                f'{_esc(f.get("severity","info"))}</span></td>'
                f'<td>{_esc(f.get("tool",""))}</td>'
                f'<td>{_esc(f.get("finding_type",""))}</td>'
                f'<td>{_esc(f.get("value",""))}</td>'
                f'<td class="dim">{_esc(f.get("detail") or metaline)}</td></tr>'
            )
        cards += f"""
        <div class="card">
          <div class="card-h"><h2>{_esc(target)}</h2><div class="pills">{heat}</div></div>
          <table>
            <thead><tr><th>Sev</th><th>Tool</th><th>Type</th><th>Value</th><th>Detail</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </div>"""

    total = len(findings)
    summary_pills = " ".join(
        f'<span class="pill" style="background:{SEV_COLORS.get(s)}">{s}: {sev_counts.get(s,0)}</span>'
        for s in SEV_ORDER if sev_counts.get(s)
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title>
<style>
  :root {{ --bg:#0b0e14; --panel:#121723; --line:#1e2738; --fg:#e6ebf2; --dim:#8a93a6; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--fg);
    font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }}
  header {{ padding:28px 32px 18px; border-bottom:1px solid var(--line);
    background:linear-gradient(180deg,#10141d,#0b0e14); }}
  h1 {{ margin:0; font-size:22px; letter-spacing:.5px; }}
  .sub {{ color:var(--dim); margin-top:4px; }}
  .wrap {{ padding:24px 32px 60px; }}
  .summary {{ margin:18px 0 26px; display:flex; gap:10px; flex-wrap:wrap; align-items:center; }}
  .pill {{ color:#0b0e14; font-weight:700; padding:3px 10px; border-radius:999px; font-size:12px; }}
  .card {{ background:var(--panel); border:1px solid var(--line); border-radius:12px;
    margin-bottom:18px; overflow:hidden; }}
  .card-h {{ display:flex; justify-content:space-between; align-items:center;
    padding:14px 18px; border-bottom:1px solid var(--line); }}
  .card-h h2 {{ margin:0; font-size:16px; }}
  .pills {{ display:flex; gap:6px; flex-wrap:wrap; }}
  table {{ width:100%; border-collapse:collapse; }}
  th,td {{ text-align:left; padding:9px 14px; border-bottom:1px solid var(--line); vertical-align:top; }}
  th {{ color:var(--dim); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.04em; }}
  td.dim {{ color:var(--dim); font-size:13px; }}
  .sev {{ color:#0b0e14; font-weight:700; padding:2px 8px; border-radius:6px; font-size:11px; text-transform:uppercase; }}
  tr:last-child td {{ border-bottom:none; }}
</style></head>
<body>
  <header>
    <h1>SENTINEL // {_esc(title)}</h1>
    <div class="sub">Unified cyber-security agent — {total} findings across {len(by_target)} target(s)</div>
  </header>
  <div class="wrap">
    <div class="summary"><strong>Global severity:</strong>{summary_pills}</div>
    {cards}
  </div>
</body></html>"""
