/**
 * CyberShield AI — Dashboard JavaScript
 * Loads charts and stats via /api/stats
 */
let activityChart, moduleChart, riskChart;

async function loadDashboardData() {
  try {
    const data = typeof cyberShieldFetch === 'function' 
      ? await cyberShieldFetch('/api/stats')
      : await (await fetch('/api/stats', { headers: { 'Accept': 'application/json' } })).json();

    if (!data || data.status === 401 || data.error) {
      return;
    }

    // Update stat cards
    const fields = {
      's-total':    data.total_scans,
      's-threats':  data.threats_detected,
      's-phish':    data.phishing_count,
      's-net':      data.network_anomalies,
      's-malware':  data.malware_count,
      's-critical': data.critical_count,
    };
    Object.entries(fields).forEach(([id, val]) => {
      const el = document.getElementById(id);
      if (el) animateCount(el, 0, val || 0, 800);
    });

    // Activity Timeline Chart
    const tl = data.timeline_data || [];
    buildActivityChart(tl.map(x => x.date), tl.map(x => x.count));

    // Module Distribution Doughnut
    const md = data.module_distribution || {};
    buildModuleChart(Object.keys(md), Object.values(md));

    // Risk Level Bar Chart
    const rv = data.severity_distribution || {};
    buildRiskChart(rv);

    // Module Stats Table
    renderModuleStatsTable(md);

  } catch(e) {
    console.warn('Dashboard data load failed:', e.message);
  }
}

function animateCount(el, from, to, duration) {
  const start = performance.now();
  const diff  = to - from;
  function step(now) {
    const elapsed = now - start;
    const progress= Math.min(elapsed / duration, 1);
    el.textContent = Math.floor(from + diff * easeOut(progress));
    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function easeOut(t) { return 1 - Math.pow(1 - t, 3); }

function buildActivityChart(labels, data) {
  if (activityChart) activityChart.destroy();
  const ctx = document.getElementById('activityChart')?.getContext('2d');
  if (!ctx) return;
  activityChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Detections',
        data,
        borderColor:     '#00d4ff',
        backgroundColor: 'rgba(0,212,255,0.1)',
        tension: 0.4, fill: true,
        pointBackgroundColor: '#00d4ff',
        pointRadius: 4,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { color: '#94a3b8' } } },
      scales: {
        x: { ticks: { color: '#64748b' }, grid: { color: '#1e293b' } },
        y: { ticks: { color: '#64748b' }, grid: { color: '#1e293b' }, beginAtZero: true }
      }
    }
  });
}

function buildModuleChart(labels, data) {
  if (moduleChart) moduleChart.destroy();
  const ctx = document.getElementById('moduleChart')?.getContext('2d');
  if (!ctx) return;
  const palette = ['#00d4ff','#ff3366','#ff8800','#ffcc00','#00ff88','#0066ff'];
  moduleChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{ data, backgroundColor: palette, borderWidth: 2, borderColor: '#111827' }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { position: 'bottom', labels: { color: '#94a3b8', boxWidth: 12, font: { size: 11 } } }
      }
    }
  });
}

function buildRiskChart(rv) {
  if (riskChart) riskChart.destroy();
  const ctx = document.getElementById('riskChart')?.getContext('2d');
  if (!ctx) return;
  const riskOrder  = ['Very Low', 'Low', 'Medium', 'High', 'Critical'];
  const riskColors = ['#00ff88', '#00d4ff', '#ffcc00', '#ff8800', '#ff3366'];
  riskChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: riskOrder,
      datasets: [{
        label: 'Count',
        data: riskOrder.map(k => rv[k] || 0),
        backgroundColor: riskColors.map(c => c + '99'),
        borderColor: riskColors,
        borderWidth: 1.5,
        borderRadius: 6,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#94a3b8' }, grid: { color: '#1e293b' } },
        y: { ticks: { color: '#94a3b8' }, grid: { color: '#1e293b' }, beginAtZero: true }
      }
    }
  });
}

function renderModuleStatsTable(md) {
  const tbody = document.getElementById('moduleStatsBody');
  if (!tbody) return;
  const moduleLinks = {
    phishing:    '/phishing/',
    ip_spoofing: '/ip-spoofing/',
    dns_spoofing:'/dns-spoofing/',
    ddos:        '/ddos/',
    brute_force: '/brute-force/',
    malware:     '/malware/',
  };
  if (!Object.keys(md).length) {
    tbody.innerHTML = '<tr><td colspan="3" class="text-center text-muted py-3">No scans yet.</td></tr>';
    return;
  }
  tbody.innerHTML = Object.entries(md)
    .sort((a, b) => b[1] - a[1])
    .map(([mod, cnt]) => `
      <tr>
        <td><span class="badge bg-secondary">${mod}</span></td>
        <td style="font-family:'Rajdhani',sans-serif;font-size:1rem;color:var(--accent)">${cnt}</td>
        <td><a href="${moduleLinks[mod] || '#'}" class="btn btn-sm btn-cyber-outline">Open</a></td>
      </tr>`).join('');
}

// Auto-refresh every 30 seconds
document.addEventListener('DOMContentLoaded', () => {
  loadDashboardData();
  setInterval(loadDashboardData, 30000);
});
