"""Autonomous HTML report generation — executive charcoal, warm brown, and silver aesthetic.

Features a dedicated Open Ports & Services Matrix, proportional severity spectrum bar,
curved panels, silver accents, and zero external runtime dependencies.
"""
from __future__ import annotations
import html
from collections import Counter, defaultdict
from typing import Dict, List, Any

SEV_COLORS = {
    "critical": "#ff3b5c",
    "high": "#ff7a45",
    "medium": "#d4a359",
    "low": "#7a9ebb",
    "info": "#8a93a6",
    "unknown": "#8a93a6",
}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def render(findings: List[Dict[str, Any]], title: str = "Sentinel Homelab Report") -> str:
    sev_counts = Counter(f.get("severity", "info") for f in findings)
    total = len(findings)
    by_target = defaultdict(list)
    port_findings: List[Dict[str, Any]] = []

    for f in findings:
        by_target[f.get("target", "?")].append(f)
        if f.get("finding_type") == "port":
            port_findings.append(f)

    # Server 0-Day Mitigations & Exploit Defense Findings
    defense_findings = [
        f for f in findings
        if f.get("finding_type") in ("hardening", "anomaly", "threat_intel", "canary", "integrity", "deception", "remediation")
        or (f.get("metadata") or {}).get("cisa_kev")
        or (f.get("metadata") or {}).get("mitigation")
        or (f.get("metadata") or {}).get("threat_category")
        or (f.get("metadata") or {}).get("sigma_id")
    ]

    # Proportional segmented distribution bar
    bar_segments = ""
    if total > 0:
        for s in SEV_ORDER:
            cnt = sev_counts.get(s, 0)
            if cnt > 0:
                pct = (cnt / total) * 100
                bar_segments += (
                    f'<div class="dist-seg" style="width:{pct:.1f}%; background:{SEV_COLORS[s]};" '
                    f'title="{s.upper()}: {cnt} ({pct:.1f}%)"></div>'
                )
    else:
        bar_segments = '<div class="dist-seg" style="width:100%; background:var(--border);" title="No findings"></div>'

    # Dedicated Server 0-Day & Exploit Mitigations Matrix Section
    defense_section = ""
    if defense_findings:
        def_rows = ""
        for df in defense_findings:
            sev = str(df.get("severity", "info")).lower()
            color = SEV_COLORS.get(sev, "#8a93a6")
            meta = df.get("metadata") or {}
            tool = df.get("tool", "")
            cat = "Kernel Mitigation" if meta.get("mitigation") else (
                "CISA KEV Exploit" if meta.get("cisa_kev") else (
                    "Process Anomaly" if meta.get("threat_category") == "0day_rce_execution" else (
                        "Sigma Detection" if meta.get("sigma_id") else (
                            "File Integrity (FIM)" if "fim" in tool else (
                                "Deception Honeyport" if "honeyport" in tool else (
                                    "Deception Tripwire" if "canary" in tool else df.get("finding_type", "Defense")
                                )
                            )
                        )
                    )
                )
            )
            val = df.get("value", "")
            detail = df.get("detail", "")
            badges = ""
            if meta.get("cisa_kev"):
                badges += ' <span class="cat-pill" style="background:#ff3b5c; color:#fff; font-weight:700;">IN THE WILD</span>'
            if meta.get("epss_score") is not None:
                badges += f' <span class="cat-pill" style="background:#ff7a45; color:#fff;">EPSS {meta["epss_score"]*100:.1f}%</span>'
            if meta.get("mitre_technique"):
                badges += f' <span class="cat-pill" style="background:#5c7cfa; color:#fff; font-weight:700;">{meta["mitre_technique"]}</span>'

            def_rows += (
                f'<tr class="port-row" data-sev="{_esc(sev)}">'
                f'<td><span class="val-mono">{_esc(df.get("target", "localhost"))}</span></td>'
                f'<td><span class="port-badge">{_esc(cat)}</span>{badges}</td>'
                f'<td><span class="service-name">{_esc(val)}</span></td>'
                f'<td><span class="sev" style="background:{color}">{_esc(sev)}</span></td>'
                f'<td class="dim">{_esc(detail)}</td>'
                f'</tr>'
            )

        defense_section = f"""
        <section class="card ports-card" aria-label="Server 0-Day Mitigations and Threat Intelligence Matrix">
          <div class="card-h">
            <div class="card-h-title">
              <h2>🛡️ Server 0-Day &amp; Exploit Mitigations Matrix</h2>
              <span class="badge-subtle">{len(defense_findings)} control(s) audited</span>
            </div>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th style="width: 140px;">Target</th>
                  <th style="width: 200px;">Category</th>
                  <th style="width: 260px;">Mitigation / Control</th>
                  <th style="width: 90px;">Status</th>
                  <th>Security Impact &amp; Evidence</th>
                </tr>
              </thead>
              <tbody>{def_rows}</tbody>
            </table>
          </div>
        </section>"""

    # Dedicated Open Ports Matrix Section
    ports_section = ""
    if port_findings:
        port_rows = ""
        for pf in port_findings:
            sev = str(pf.get("severity", "info")).lower()
            color = SEV_COLORS.get(sev, "#8a93a6")
            meta = pf.get("metadata") or {}
            svc = meta.get("service", pf.get("detail", "Unknown"))
            cat = meta.get("category", "General")
            port_rows += (
                f'<tr class="port-row" data-sev="{_esc(sev)}" data-cat="{_esc(cat.lower())}">'
                f'<td><span class="val-mono">{_esc(pf.get("target", ""))}</span></td>'
                f'<td><span class="port-badge">{_esc(pf.get("value", ""))}</span></td>'
                f'<td><span class="service-name">{_esc(svc)}</span></td>'
                f'<td><span class="cat-pill">{_esc(cat)}</span></td>'
                f'<td><span class="sev" style="background:{color}">{_esc(sev)}</span></td>'
                f'<td class="dim">{_esc(pf.get("detail", ""))}</td>'
                f'</tr>'
            )

        ports_section = f"""
        <section class="card ports-card" aria-label="Homelab Open Ports and Services Matrix">
          <div class="card-h">
            <div class="card-h-title">
              <h2>🔌 Open Ports &amp; Services Matrix</h2>
              <span class="badge-subtle">{len(port_findings)} port(s) open</span>
            </div>
            <div class="port-filters">
              <button class="port-btn active" onclick="filterPorts('all', this)">All Ports</button>
              <button class="port-btn" onclick="filterPorts('high-crit', this)">High Risk Only</button>
              <button class="port-btn" onclick="filterPorts('containers', this)">Containers</button>
              <button class="port-btn" onclick="filterPorts('database', this)">Databases</button>
            </div>
          </div>
          <div class="table-wrap">
            <table id="portsTable">
              <thead>
                <tr>
                  <th style="width: 140px;">Host / IP</th>
                  <th style="width: 110px;">Port</th>
                  <th style="width: 180px;">Service</th>
                  <th style="width: 120px;">Category</th>
                  <th style="width: 90px;">Risk</th>
                  <th>Observation &amp; Detail</th>
                </tr>
              </thead>
              <tbody>{port_rows}</tbody>
            </table>
          </div>
        </section>"""

    # Target Cards
    cards = ""
    for target, fs in sorted(by_target.items()):
        tcount = Counter(f.get("severity", "info") for f in fs)
        heat = "".join(
            f'<span class="pill" style="background:{SEV_COLORS.get(s, "#8a93a6")}">'
            f'{s}: {tcount.get(s, 0)}</span>' for s in SEV_ORDER if tcount.get(s)
        )
        rows = ""
        for f in fs:
            meta = f.get("metadata") or {}
            metaline = " · ".join(f"{k}={v}" for k, v in meta.items() if v not in (None, ""))
            sev = str(f.get("severity", "info")).lower()
            color = SEV_COLORS.get(sev, "#8a93a6")
            badges = ""
            if meta.get("cisa_kev"):
                badges += ' <span style="background:#ff3b5c; color:#fff; font-size:10px; font-weight:700; padding:2px 6px; border-radius:3px; margin-left:6px;">CISA KEV</span>'
            if meta.get("epss_score") is not None:
                badges += f' <span style="background:#ff7a45; color:#fff; font-size:10px; font-weight:700; padding:2px 6px; border-radius:3px; margin-left:6px;">EPSS {meta["epss_score"]*100:.1f}%</span>'
            rows += (
                f'<tr data-sev="{_esc(sev)}">'
                f'<td><span class="sev" style="background:{color}">{_esc(sev)}</span></td>'
                f'<td><span class="tool-tag">{_esc(f.get("tool", ""))}</span></td>'
                f'<td><span class="type-tag">{_esc(f.get("finding_type", ""))}</span></td>'
                f'<td><span class="val-mono">{_esc(f.get("value", ""))}{badges}</span></td>'
                f'<td class="dim">{_esc(f.get("detail") or metaline)}</td>'
                f'</tr>'
            )
        cards += f"""
        <article class="card" data-target="{_esc(target)}">
          <div class="card-h">
            <div class="card-h-title">
              <h2>{_esc(target)}</h2>
              <span class="badge-subtle">{len(fs)} item(s)</span>
            </div>
            <div class="pills">{heat}</div>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th style="width: 88px;">Sev</th>
                  <th style="width: 120px;">Tool</th>
                  <th style="width: 136px;">Type</th>
                  <th>Discovered Value</th>
                  <th>Detail &amp; Evidence</th>
                </tr>
              </thead>
              <tbody>{rows}</tbody>
            </table>
          </div>
        </article>"""

    summary_pills = "".join(
        f'<button class="filter-btn pill" data-filter="{s}" style="background:{SEV_COLORS.get(s)}">'
        f'{s}: {sev_counts.get(s, 0)}</button>'
        for s in SEV_ORDER if sev_counts.get(s)
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SENTINEL // {_esc(title)}</title>
<style>
  :root {{
    --bg: #0e0e0e;
    --surface: #161616;
    --surface-raised: #1c1c1c;
    --surface-hover: #222222;
    --border: #2a2a2a;
    --border-strong: #3d3d3d;
    --border-silver: #4a4a4a;
    --border-focus: #666666;
    --text-primary: #e8e4dc;
    --text-secondary: #9a948c;
    --text-muted: #5e5a54;
    --silver: #c5cbd3;
    --silver-glow: rgba(197, 203, 211, 0.12);
    --accent: #8b3a3a;
    --accent-hover: #a14444;
    --accent-subtle: rgba(139, 58, 58, 0.18);
    --accent-glow: rgba(139, 58, 58, 0.28);
    --card-radius: 14px;
    --pill-radius: 999px;
    --font-serif: "Newsreader", Georgia, "Times New Roman", serif;
    --font-sans: "IBM Plex Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    --font-mono: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    --space-xs: 4px;
    --space-sm: 8px;
    --space-md: 16px;
    --space-lg: 24px;
    --space-xl: 32px;
    --space-xxl: 48px;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background-color: var(--bg);
    color: var(--text-primary);
    font-family: var(--font-sans);
    font-size: 14px;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
    min-height: 100vh;
  }}

  @media (prefers-reduced-motion: reduce) {{
    * {{ animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; }}
  }}

  /* Header */
  header {{
    background: linear-gradient(180deg, #141414 0%, var(--bg) 100%);
    border-bottom: 1px solid var(--border);
    padding: var(--space-xl) var(--space-lg) var(--space-lg);
  }}

  .header-container {{
    max-width: 1440px;
    margin: 0 auto;
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }}

  .brand-row {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: var(--space-md);
  }}

  .brand-group {{ display: flex; align-items: center; gap: var(--space-md); }}

  .brand-badge {{
    font-family: var(--font-mono);
    font-size: 11px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--silver);
    background: var(--surface-raised);
    border: 1px solid var(--border-strong);
    padding: 4px 10px;
    border-radius: var(--pill-radius);
  }}

  h1 {{
    font-family: var(--font-serif);
    font-size: 28px;
    font-weight: 500;
    letter-spacing: -0.01em;
    color: var(--text-primary);
  }}

  .header-subtitle {{
    color: var(--text-secondary);
    font-size: 13px;
    display: flex;
    gap: var(--space-sm);
    flex-wrap: wrap;
    align-items: center;
  }}

  .header-subtitle strong {{ color: var(--text-primary); }}

  /* Main Container */
  main.wrap {{
    max-width: 1440px;
    margin: 0 auto;
    padding: var(--space-xl) var(--space-lg) var(--space-xxl);
    display: flex;
    flex-direction: column;
    gap: var(--space-lg);
  }}

  /* Progress & Severity Distribution */
  .progress-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--card-radius);
    padding: var(--space-md) var(--space-lg);
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.03);
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }}

  .progress-card-top {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: var(--space-sm);
  }}

  .progress-title {{
    font-family: var(--font-mono);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--text-secondary);
  }}

  .progress-stats {{
    font-family: var(--font-mono);
    font-size: 13px;
    color: var(--text-primary);
  }}

  .progress-stats span {{ color: var(--silver); font-weight: 700; }}

  .progress-bar-bg {{
    width: 100%;
    height: 8px;
    background: var(--surface-raised);
    border: 1px solid var(--border);
    border-radius: 4px;
    overflow: hidden;
    display: flex;
  }}

  .dist-seg {{ height: 100%; transition: width 0.3s ease; }}

  /* Controls Bar */
  .controls-bar {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: var(--space-md);
    flex-wrap: wrap;
    background: var(--surface);
    border: 1px solid var(--border);
    padding: var(--space-sm) var(--space-md);
    border-radius: var(--card-radius);
  }}

  .filter-group {{ display: flex; gap: var(--space-sm); align-items: center; flex-wrap: wrap; }}

  .filter-label {{
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--text-secondary);
    margin-right: 4px;
    text-transform: uppercase;
  }}

  .pill {{
    font-family: var(--font-mono);
    color: #0e0e0e;
    font-weight: 700;
    padding: 3px 10px;
    border-radius: var(--pill-radius);
    font-size: 11px;
    border: 1px solid transparent;
    cursor: pointer;
    transition: all 0.15s ease;
  }}

  .pill:hover {{ opacity: 0.9; transform: translateY(-1px); }}
  .pill.active {{ outline: 2px solid var(--silver); box-shadow: 0 0 8px var(--silver-glow); }}
  .pill-all {{ background: var(--silver); color: #0e0e0e; }}

  .search-input {{
    background: var(--surface-raised);
    border: 1px solid var(--border);
    color: var(--text-primary);
    padding: 6px 14px;
    border-radius: var(--pill-radius);
    font-family: var(--font-sans);
    font-size: 13px;
    outline: none;
    width: 260px;
    transition: border-color 0.15s ease, box-shadow 0.15s ease;
  }}

  .search-input:focus {{
    border-color: var(--border-silver);
    box-shadow: 0 0 0 2px var(--silver-glow);
  }}

  /* Cards & Ports Panel */
  .card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--card-radius);
    overflow: hidden;
    box-shadow: 0 4px 24px rgba(0, 0, 0, 0.45), inset 0 1px 0 rgba(255, 255, 255, 0.04);
    transition: border-color 0.2s ease;
  }}

  .card:hover {{ border-color: var(--border-strong); }}

  .card-h {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: var(--space-md) var(--space-lg);
    border-bottom: 1px solid var(--border);
    background: linear-gradient(90deg, var(--surface) 0%, var(--surface-raised) 100%);
    flex-wrap: wrap;
    gap: var(--space-sm);
  }}

  .card-h-title {{ display: flex; align-items: baseline; gap: var(--space-sm); }}

  .card-h h2 {{
    font-family: var(--font-serif);
    font-size: 18px;
    font-weight: 500;
    color: var(--text-primary);
  }}

  .badge-subtle {{
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-muted);
    background: var(--surface);
    border: 1px solid var(--border);
    padding: 1px 6px;
    border-radius: 4px;
  }}

  .pills {{ display: flex; gap: var(--space-xs); flex-wrap: wrap; }}

  /* Ports Specific */
  .port-filters {{ display: flex; gap: 6px; flex-wrap: wrap; }}
  .port-btn {{
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text-secondary);
    font-family: var(--font-mono);
    font-size: 11px;
    padding: 3px 9px;
    border-radius: var(--pill-radius);
    cursor: pointer;
    transition: all 0.15s ease;
  }}
  .port-btn:hover {{ background: var(--surface-hover); color: var(--text-primary); }}
  .port-btn.active {{
    background: var(--accent-subtle);
    border-color: var(--accent);
    color: var(--text-primary);
    font-weight: 600;
  }}

  .port-badge {{
    font-family: var(--font-mono);
    font-size: 12px;
    font-weight: 600;
    color: var(--silver);
    background: var(--surface-raised);
    border: 1px solid var(--border-strong);
    padding: 2px 7px;
    border-radius: 4px;
    display: inline-block;
  }}

  .service-name {{ font-weight: 500; color: var(--text-primary); }}

  .cat-pill {{
    font-family: var(--font-mono);
    font-size: 10px;
    text-transform: uppercase;
    color: var(--text-muted);
    background: var(--surface-raised);
    padding: 2px 6px;
    border-radius: 3px;
    border: 1px solid var(--border);
  }}

  /* Table */
  .table-wrap {{ overflow-x: auto; }}

  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}

  th, td {{
    text-align: left;
    padding: 10px var(--space-lg);
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }}

  th {{
    color: var(--text-secondary);
    font-family: var(--font-mono);
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    background: var(--surface-raised);
    border-bottom: 1px solid var(--border-strong);
  }}

  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: var(--surface-hover); }}

  .sev {{
    color: #0e0e0e;
    font-family: var(--font-mono);
    font-weight: 700;
    padding: 2px 7px;
    border-radius: 4px;
    font-size: 10px;
    text-transform: uppercase;
    display: inline-block;
    letter-spacing: 0.04em;
  }}

  .tool-tag {{
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--silver);
    background: var(--surface-raised);
    border: 1px solid var(--border);
    padding: 2px 6px;
    border-radius: 4px;
    display: inline-block;
  }}

  .type-tag {{ font-family: var(--font-mono); font-size: 12px; color: var(--text-secondary); }}
  .val-mono {{ font-family: var(--font-mono); font-size: 12px; color: var(--text-primary); word-break: break-all; }}
  td.dim {{ color: var(--text-secondary); font-size: 12px; }}

  /* Footer */
  footer {{
    text-align: center;
    color: var(--text-muted);
    font-size: 12px;
    font-family: var(--font-mono);
    margin-top: var(--space-xl);
  }}
</style>
</head>
<body>
  <header>
    <div class="header-container">
      <div class="brand-row">
        <div class="brand-group">
          <h1>SENTINEL // {_esc(title)}</h1>
          <span class="brand-badge">Homelab Guardian</span>
        </div>
        <div class="header-subtitle">
          <span>Total events: <strong>{total}</strong></span>
          <span>&bull;</span>
          <span>Open ports: <strong>{len(port_findings)}</strong></span>
          <span>&bull;</span>
          <span>Target(s): <strong>{len(by_target)}</strong></span>
        </div>
      </div>
    </div>
  </header>

  <main class="wrap">
    <!-- Distribution Progress Bar -->
    <section class="progress-card" aria-label="Finding Severity Distribution">
      <div class="progress-card-top">
        <div class="progress-title">Severity Spectrum</div>
        <div class="progress-stats">
          <span>{total}</span> validated item(s) across systems
        </div>
      </div>
      <div class="progress-bar-bg">
        {bar_segments}
      </div>
    </section>

    <!-- Dedicated Open Ports Matrix -->
    {ports_section}

    <!-- Server 0-Day & Exploit Mitigations Matrix -->
    {defense_section}

    <!-- Interactive Filters & Search -->
    <section class="controls-bar" aria-label="Report Controls">
      <div class="filter-group">
        <span class="filter-label">Filter:</span>
        <button class="filter-btn pill pill-all active" data-filter="all">ALL: {total}</button>
        {summary_pills}
      </div>
      <div>
        <input type="text" id="searchInput" class="search-input" placeholder="Search host, tool, port, CVE..." oninput="handleSearch()">
      </div>
    </section>

    <!-- Target Cards -->
    <section class="target-container" id="targetContainer">
      {cards}
    </section>

    <footer>
      Autonomous assessment generated by Sentinel Cyber Agent &bull; Low-memory engine &bull; Zero external CDN dependencies
    </footer>
  </main>

  <script>
    let activeFilter = 'all';

    document.querySelectorAll('.filter-btn').forEach(btn => {{
      btn.addEventListener('click', (e) => {{
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        activeFilter = btn.getAttribute('data-filter');
        applyFilters();
      }});
    }});

    function filterPorts(category, btn) {{
      document.querySelectorAll('.port-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const rows = document.querySelectorAll('.port-row');

      rows.forEach(r => {{
        const sev = r.getAttribute('data-sev') || '';
        const cat = r.getAttribute('data-cat') || '';

        if (category === 'all') {{
          r.style.display = '';
        }} else if (category === 'high-crit') {{
          r.style.display = (sev === 'critical' || sev === 'high') ? '' : 'none';
        }} else if (category === 'containers') {{
          r.style.display = (cat.includes('container') || cat.includes('docker')) ? '' : 'none';
        }} else if (category === 'database') {{
          r.style.display = (cat.includes('database') || cat.includes('storage')) ? '' : 'none';
        }}
      }});
    }}

    function handleSearch() {{
      applyFilters();
    }}

    function applyFilters() {{
      const query = (document.getElementById('searchInput').value || '').toLowerCase().trim();
      const cards = document.querySelectorAll('.card:not(.ports-card)');

      cards.forEach(card => {{
        const rows = card.querySelectorAll('tbody tr');
        let visibleCount = 0;

        rows.forEach(row => {{
          const sev = (row.getAttribute('data-sev') || '').toLowerCase();
          const text = row.innerText.toLowerCase();

          const matchesFilter = (activeFilter === 'all' || sev === activeFilter);
          const matchesQuery = (!query || text.includes(query));

          if (matchesFilter && matchesQuery) {{
            row.style.display = '';
            visibleCount++;
          }} else {{
            row.style.display = 'none';
          }}
        }});

        card.style.display = (visibleCount > 0) ? '' : 'none';
      }});
    }}
  </script>
</body>
</html>"""
