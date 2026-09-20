<script lang="ts">
import { onMount, onDestroy } from 'svelte';

interface Finding {
  id: string;
  tool: string;
  finding_type: string;
  value: string;
  severity: string;
  detail?: string;
  timestamp: string;
}

interface SystemStatus {
  hostname: string;
  kernel: string;
  cpu: number;
  ram_percent: number;
  ram_total_gb: number;
}

let findings: Finding[] = [];
let status: SystemStatus | $state.raw<SystemStatus | null> = null;
let ws: WebSocket | null = null;
let connected = $state(false);
let scanTarget = $state('');
let scanning = $state(false);

onMount(() => {
  fetchStatus();
  connectWs();
});

onDestroy(() => {
  ws?.close();
});

async function fetchStatus() {
  try {
    const res = await fetch('/api/status');
    if (res.ok) {
      status = await res.json();
    }
  } catch (e) {
    console.error('Failed to fetch status:', e);
  }
}

function connectWs() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
  
  ws.onopen = () => { connected = true; };
  ws.onclose = () => {
    connected = false;
    setTimeout(connectWs, 3000);
  };
  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.type === 'finding' && data.payload) {
        findings = [data.payload, ...findings].slice(0, 1000);
      }
    } catch (e) {
      console.error('WebSocket message parse error:', e);
    }
  };
}

async function triggerScan() {
  if (!scanTarget.trim()) return;
  scanning = true;
  try {
    await fetch('/api/findings/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: scanTarget }),
    });
  } catch (e) {
    console.error('Scan failed:', e);
  } finally {
    scanning = false;
  }
}

const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
const severityColors: Record<string, string> = {
  critical: '#ff3b5c',
  high: '#ff7a45',
  medium: '#ffc14d',
  low: '#5bc0ff',
  info: '#8a93a6',
};

function severityCount(sev: string): number {
  return findings.filter(f => f.severity === sev).length;
}
</script>

<div class="app">
  <header>
    <div class="title-row">
      <h1>SENTINEL <span class="version">2.0</span></h1>
      <div class="tagline">Homelab Security Platform</div>
    </div>
    <div class="status-indicator" class:connected>
      {connected ? 'LIVE' : 'RECONNECTING...'}
    </div>
  </header>

  <main>
    <section class="scan-bar">
      <input
        type="text"
        placeholder="Enter domain or IP to scan..."
        bind:value={scanTarget}
        on:keydown={(e) => e.key === 'Enter' && triggerScan()}
      />
      <button on:click={triggerScan} disabled={scanning}>
        {scanning ? 'SCANNING...' : 'SCAN'}
      </button>
    </section>

    {#if status}
    <section class="cards">
      <div class="card">
        <div class="card-title">HOSTNAME</div>
        <div class="card-value">{status.hostname}</div>
        <div class="card-sub">{status.kernel}</div>
      </div>
      <div class="card">
        <div class="card-title">CPU</div>
        <div class="card-value">{status.cpu.toFixed(1)}%</div>
      </div>
      <div class="card">
        <div class="card-title">RAM</div>
        <div class="card-value">{status.ram_percent.toFixed(1)}%</div>
        <div class="card-sub">{status.ram_total_gb.toFixed(1)} GB total</div>
      </div>
      <div class="card">
        <div class="card-title">FINDINGS</div>
        <div class="card-value">{findings.length}</div>
        <div class="card-sub">active threats tracked</div>
      </div>
    </section>
    {/if}

    <section class="severity-heatmap">
      {#each severityOrder as sev}
        <div class="heat-pill" style="background: {severityColors[sev]}">
          {sev.toUpperCase()}: {severityCount(sev)}
        </div>
      {/each}
    </section>

    <section class="findings-table">
      <table>
        <thead>
          <tr>
            <th>SEVERITY</th>
            <th>TOOL</th>
            <th>TYPE</th>
            <th>VALUE</th>
            <th>DETAIL</th>
            <th>TIME</th>
            <th>ACTIONS</th>
          </tr>
        </thead>
        <tbody>
          {#each findings as f (f.id)}
            <tr>
              <td>
                <span class="sev-badge" style="background: {severityColors[f.severity]}">
                  {f.severity.toUpperCase()}
                </span>
              </td>
              <td>{f.tool}</td>
              <td>{f.finding_type}</td>
              <td class="value-cell" title={f.value}>{f.value}</td>
              <td class="detail-cell">{f.detail || '-'}</td>
              <td class="time-cell">{new Date(f.timestamp).toLocaleString()}</td>
              <td>
                <button class="action-btn" title="Block IP" disabled>BLOCK</button>
              </td>
            </tr>
          {:else}
            <tr>
              <td colspan="7" class="empty-row">No findings yet — the system is monitoring...</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>
  </main>

  <footer>
    <div>Sentinel 2.0 • Rust + eBPF + MCP + AI • MIT License</div>
  </footer>
</div>

<style>
  :global(body) {
    margin: 0;
    background: #0b0e14;
    color: #e6ebf2;
    font: 14px/1.5 ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
  }

  :global(*) {
    box-sizing: border-box;
  }

  .app {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
  }

  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 20px 32px;
    border-bottom: 1px solid #1e2738;
    background: linear-gradient(180deg, #10141d, #0b0e14);
  }

  .title-row {
    display: flex;
    align-items: baseline;
    gap: 16px;
  }

  h1 {
    margin: 0;
    font-size: 22px;
    letter-spacing: 1px;
    font-weight: 700;
  }

  .version {
    color: #5bc0ff;
    font-size: 14px;
    font-weight: 400;
  }

  .tagline {
    color: #8a93a6;
    font-size: 13px;
  }

  .status-indicator {
    padding: 6px 14px;
    border-radius: 999px;
    background: #ff3b5c;
    color: white;
    font-weight: 700;
    font-size: 12px;
    animation: pulse 2s infinite;
  }

  .status-indicator.connected {
    background: #2ecc71;
    animation: none;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.6; }
  }

  main {
    flex: 1;
    padding: 24px 32px;
  }

  .scan-bar {
    display: flex;
    gap: 12px;
    margin-bottom: 24px;
  }

  .scan-bar input {
    flex: 1;
    padding: 12px 16px;
    background: #121723;
    border: 1px solid #1e2738;
    border-radius: 8px;
    color: #e6ebf2;
    font-size: 14px;
    outline: none;
  }

  .scan-bar input:focus {
    border-color: #5bc0ff;
  }

  .scan-bar button {
    padding: 12px 24px;
    background: #5bc0ff;
    border: none;
    border-radius: 8px;
    color: #0b0e14;
    font-weight: 700;
    cursor: pointer;
    transition: background 0.2s;
  }

  .scan-bar button:hover:not(:disabled) {
    background: #4aa8e0;
  }

  .scan-bar button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
  }

  .card {
    background: #121723;
    border: 1px solid #1e2738;
    border-radius: 12px;
    padding: 20px;
  }

  .card-title {
    color: #8a93a6;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .card-value {
    font-size: 28px;
    font-weight: 700;
    margin-top: 8px;
  }

  .card-sub {
    color: #8a93a6;
    font-size: 12px;
    margin-top: 4px;
  }

  .severity-heatmap {
    display: flex;
    gap: 10px;
    margin-bottom: 24px;
    flex-wrap: wrap;
  }

  .heat-pill {
    padding: 6px 14px;
    border-radius: 999px;
    color: #0b0e14;
    font-weight: 700;
    font-size: 13px;
  }

  .findings-table {
    background: #121723;
    border: 1px solid #1e2738;
    border-radius: 12px;
    overflow: hidden;
  }

  table {
    width: 100%;
    border-collapse: collapse;
  }

  th, td {
    text-align: left;
    padding: 12px 16px;
    border-bottom: 1px solid #1e2738;
  }

  th {
    color: #8a93a6;
    font-weight: 600;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .value-cell {
    max-width: 300px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-family: ui-monospace, monospace;
    font-size: 13px;
  }

  .detail-cell {
    color: #8a93a6;
    font-size: 13px;
    max-width: 250px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .time-cell {
    color: #8a93a6;
    font-size: 12px;
    white-space: nowrap;
  }

  .sev-badge {
    padding: 3px 10px;
    border-radius: 6px;
    color: #0b0e14;
    font-weight: 700;
    font-size: 11px;
    text-transform: uppercase;
    display: inline-block;
  }

  .action-btn {
    padding: 4px 10px;
    background: transparent;
    border: 1px solid #ff3b5c;
    border-radius: 4px;
    color: #ff3b5c;
    font-size: 11px;
    font-weight: 700;
    cursor: pointer;
  }

  .action-btn:hover:not(:disabled) {
    background: #ff3b5c;
    color: white;
  }

  .action-btn:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }

  .empty-row {
    text-align: center;
    padding: 40px;
    color: #8a93a6;
  }

  footer {
    padding: 16px 32px;
    border-top: 1px solid #1e2738;
    text-align: center;
    color: #8a93a6;
    font-size: 12px;
  }
</style>
