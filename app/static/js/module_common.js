/**
 * CyberShield AI — Module Common JS
 * Shared utilities used by all detection module pages.
 */

// ── CSRF token helper ───────────────────────────────────────
function getCSRF() {
  return document.querySelector('meta[name=csrf-token]')?.content || '';
}

// ── Robust CyberShield Fetch Helper (prevents JSON <!doctype syntax errors) ──────
async function cyberShieldFetch(url, options = {}) {
  const defaultHeaders = {
    'X-Requested-With': 'XMLHttpRequest',
    'Accept': 'application/json'
  };

  const csrf = getCSRF();
  if (csrf) {
    defaultHeaders['X-CSRFToken'] = csrf;
  }

  const isFormData = options.body instanceof FormData;
  if (!isFormData && options.body && typeof options.body === 'string') {
    defaultHeaders['Content-Type'] = 'application/json';
  }

  options.headers = {
    ...defaultHeaders,
    ...(options.headers || {})
  };

  let response;
  try {
    response = await fetch(url, options);
  } catch (netErr) {
    return {
      success: false,
      error: 'Network error or server unreachable: ' + (netErr.message || 'Connection refused'),
      status: 0
    };
  }

  // Handle 401 Unauthorized
  if (response.status === 401) {
    showAlert('Session expired or authentication required. Please log in again.', 'warning');
    setTimeout(() => {
      window.location.href = '/auth/login?next=' + encodeURIComponent(window.location.pathname);
    }, 1800);
    return {
      success: false,
      error: 'Session expired. Redirecting to login...',
      status: 401
    };
  }

  // Safely parse JSON or handle HTML error pages gracefully
  const contentType = response.headers.get('content-type') || '';
  const text = await response.text();

  if (contentType.includes('application/json')) {
    try {
      const data = JSON.parse(text);
      data.status = response.status;
      return data;
    } catch (parseErr) {
      return {
        success: false,
        error: 'Invalid JSON payload received from server.',
        raw: text,
        status: response.status
      };
    }
  }

  // If received HTML or other non-JSON response
  if (!response.ok) {
    return {
      success: false,
      error: `Server returned status ${response.status} (${response.statusText || 'Error'}). Please check input or server logs.`,
      status: response.status
    };
  }

  // If text was returned with 200
  return {
    success: true,
    data: text,
    status: response.status
  };
}

// ── Copy to clipboard helper with toast feedback ───────────
function copyToClipboard(text, btnElement) {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(() => {
      showCopyFeedback(btnElement);
    }).catch(() => fallbackCopy(text, btnElement));
  } else {
    fallbackCopy(text, btnElement);
  }
}

function fallbackCopy(text, btnElement) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try {
    document.execCommand('copy');
    showCopyFeedback(btnElement);
  } catch(e) {
    showAlert('Failed to copy command', 'danger');
  }
  document.body.removeChild(ta);
}

function showCopyFeedback(btnElement) {
  if (!btnElement) {
    showAlert('Copied to clipboard!', 'success');
    return;
  }
  const origHtml = btnElement.innerHTML;
  btnElement.innerHTML = '<i class="fas fa-check text-success me-1"></i>Copied!';
  btnElement.classList.add('btn-success-soft');
  setTimeout(() => {
    btnElement.innerHTML = origHtml;
    btnElement.classList.remove('btn-success-soft');
  }, 2000);
}

// ── Risk level → color ───────────────────────────────────────
const RISK_COLORS = {
  'Very Low': '#00ff88',
  'Low':      '#00d4ff',
  'Medium':   '#ffcc00',
  'High':     '#ff8800',
  'Critical': '#ff3366',
};

function getRiskColor(level) {
  return RISK_COLORS[level] || '#94a3b8';
}

// ── Render a standard result card ──────────────────────────────
function renderStandardResult(containerId, data) {
  const col  = document.getElementById(containerId);
  if (!col) return;

  if (!data.success) {
    col.innerHTML = `
      <div class="cyber-card result-section">
        <div class="cyber-card-body text-danger">
          <i class="fas fa-times-circle me-2"></i>${data.error || 'Analysis failed.'}
        </div>
      </div>`;
    return;
  }

  const c    = getRiskColor(data.risk_level);
  const rl   = (data.risk_level || 'low').toLowerCase().replace(' ', '-');
  const inds = (data.indicators || []).map(i =>
    `<div class="indicator-item ${data.risk_score < 30 ? 'indicator-safe' : ''}">
       <i class="fas fa-${data.risk_score < 30 ? 'check-circle' : 'exclamation-circle'}"></i>
       <span>${i}</span>
     </div>`
  ).join('') || '<div class="text-muted">No indicators triggered.</div>';

  const recs = (data.recommended_actions || []).map(r =>
    `<li class="text-muted" style="font-size:0.82rem">${r}</li>`
  ).join('');

  col.innerHTML = `
    <div class="cyber-card result-section mb-3">
      <div class="cyber-card-header"><i class="fas fa-chart-pie"></i> Detection Result</div>
      <div class="cyber-card-body">
        <div class="d-flex align-items-center gap-4 mb-3">
          <div class="risk-score-circle"
               style="--score-color:${c};border-color:${c};box-shadow:0 0 20px ${c}">
            <div class="score-num" style="color:${c}">${data.risk_score}</div>
            <div class="score-label">/ 100</div>
          </div>
          <div>
            <h3 style="font-family:'Rajdhani',sans-serif;font-size:1.6rem;color:${c}">${data.result}</h3>
            <span class="badge badge-${rl} me-2">${data.risk_level}</span>
            <span class="badge bg-secondary">Confidence: ${((data.confidence||0)*100).toFixed(1)}%</span>
            <div class="text-muted mt-2" style="font-size:0.78rem">
              <i class="fas fa-cog me-1"></i>${data.model_used || 'N/A'}
            </div>
            <div class="text-muted" style="font-size:0.75rem">
              <i class="fas fa-clock me-1"></i>${data.timestamp ? new Date(data.timestamp).toLocaleString() : '—'}
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="cyber-card result-section mb-3">
      <div class="cyber-card-header"><i class="fas fa-exclamation-triangle"></i> Detection Indicators</div>
      <div class="cyber-card-body">${inds}</div>
    </div>

    ${recs ? `<div class="cyber-card result-section mb-3">
      <div class="cyber-card-header"><i class="fas fa-shield-halved"></i> Recommended Actions</div>
      <div class="cyber-card-body"><ul class="mb-0 ps-3">${recs}</ul></div>
    </div>` : ''}

    ${data.detection_id ? `
    <div class="d-flex gap-2">
      <a href="/reports/${data.detection_id}/pdf" class="btn btn-cyber-outline" target="_blank">
        <i class="fas fa-file-pdf me-1"></i>PDF Report
      </a>
      <a href="/reports/${data.detection_id}/csv" class="btn btn-cyber-outline" target="_blank">
        <i class="fas fa-file-csv me-1"></i>CSV Report
      </a>
    </div>` : ''}`;
}

// ── File drag-and-drop styling ──────────────────────────────────
document.querySelectorAll('.upload-zone').forEach(zone => {
  zone.addEventListener('dragover', e => {
    e.preventDefault();
    zone.classList.add('drag-over');
  });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.classList.remove('drag-over');
    const fi = zone.querySelector('input[type=file]');
    if (fi && e.dataTransfer.files.length) {
      fi.files = e.dataTransfer.files;
      fi.dispatchEvent(new Event('change', { bubbles: true }));
    }
  });
});

// ── Toast helper ────────────────────────────────────────────────
function showAlert(msg, type='danger') {
  const container = document.querySelector('.flash-container');
  if (!container) return;
  const div = document.createElement('div');
  div.className = `alert alert-${type} alert-dismissible fade show`;
  div.innerHTML = `<i class="fas fa-info-circle me-2"></i>${msg}
    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>`;
  container.appendChild(div);
  setTimeout(() => div.remove(), 5000);
}
