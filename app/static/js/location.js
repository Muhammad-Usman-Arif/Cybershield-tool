/* CyberShield AI - Browser Location Integration */
'use strict';

const CSRF_TOKEN = document.querySelector('meta[name="csrf-token"]')?.content || '';

async function postLocation(payload) {
  try {
    await fetch('/location/api/record', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': CSRF_TOKEN },
      body: JSON.stringify(payload)
    });
  } catch(e) { console.warn('Location record failed:', e); }
}

function updateLocationWidget(city, country, timezone) {
  const widget = document.getElementById('locWidget');
  const status = document.getElementById('locPermStatus');
  if (!widget) return;
  const tz = timezone ? `<small class="text-muted ms-2" style="font-size:0.7rem">TZ: ${timezone}</small>` : '';
  widget.innerHTML = `
    <i class="fas fa-map-marker-alt" style="color:var(--accent)"></i>
    <div>
      <span class="loc-city">${city || 'Unknown City'}</span>
      <span class="loc-country ms-1">${country || ''}</span>
      ${tz}
    </div>`;
  if (status) status.textContent = 'Location active';
}

function handleLocationError() {
  const widget = document.getElementById('locWidget');
  const status = document.getElementById('locPermStatus');
  fetch('http://ip-api.com/json/?fields=city,regionName,country,timezone')
    .then(r => r.json())
    .then(d => {
      if (d.city || d.country) {
        updateLocationWidget(d.city, d.country, d.timezone);
        postLocation({ event_type: 'login', city: d.city, region: d.regionName, country: d.country, timezone: d.timezone });
      } else {
        if (widget) widget.innerHTML = '<i class="fas fa-map-marker-slash"></i><span class="text-muted">Location unavailable</span>';
        if (status) status.textContent = 'Unavailable';
      }
    })
    .catch(() => {
      if (widget) widget.innerHTML = '<i class="fas fa-map-marker-slash"></i><span class="text-muted">Location unavailable</span>';
      if (status) status.textContent = 'Denied';
    });
}

function initLocation() {
  const widget = document.getElementById('locWidget');
  if (!widget) return;
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  if (!navigator.geolocation) { handleLocationError(); return; }
  navigator.geolocation.getCurrentPosition(
    (pos) => {
      const { latitude, longitude, accuracy } = pos.coords;
      postLocation({ event_type: 'login', latitude, longitude, accuracy, timezone: tz });
      fetch('http://ip-api.com/json/?fields=city,regionName,country,timezone')
        .then(r => r.json())
        .then(d => updateLocationWidget(d.city, d.country, tz))
        .catch(() => updateLocationWidget(null, null, tz));
    },
    () => handleLocationError(),
    { timeout: 8000, maximumAge: 300000 }
  );
  setInterval(() => {
    fetch('/location/api/update-session', { method: 'POST', headers: { 'X-CSRFToken': CSRF_TOKEN } }).catch(() => {});
  }, 300000);
}

document.addEventListener('DOMContentLoaded', initLocation);
