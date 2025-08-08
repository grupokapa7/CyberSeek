async function Session() {
    const res = await fetch('/session');
    if (res.status === 401) {
        window.location.href = '/login';
    }
}

function sanitizeText(str) {
    return typeof str === 'string' ? str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;') : '';
}

let map = null;
function show_map(lat, lon) {
    if (map) map.remove();
    map = L.map('whois_map', { zoomControl: false, attributionControl: false }).setView([lat, lon], 8);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', { maxZoom: 19 }).addTo(map);
    const pulseIcon = L.divIcon({ className: '', html: '<div class="pulse-marker"></div>', iconSize: [20, 20] });
    L.marker([lat, lon], { icon: pulseIcon }).addTo(map);
    map.invalidateSize();
}

async function dataLocation(query, csrf_token) {
    const smap = document.getElementById('whois_map');
    const ip = document.getElementById('ipinfo');
    const topcard = document.getElementById('topcard');
    const mapcard = document.getElementById('map-content-card');

    [smap, ip, topcard, mapcard].forEach(el => el.style.display = 'none');

    const res = await fetch('/api/ipinfo/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf_token },
        body: JSON.stringify({ query })
    });

    if (!res.ok) return;

    let data;
    try {
        data = await res.json();
    } catch {
        return;
    }

    if (data?.success !== "True") return;

    const [lat, lon] = data.loc?.split(',').map(Number);
    if (!lat || !lon) return;

    document.getElementById('ipCity').textContent = `${sanitizeText(data.country || '--')} | ${sanitizeText(data.city || '--')}`;
    document.getElementById('ipOrg').textContent = `Org: ${sanitizeText(data.org || '--')}`;
    document.getElementById('ipRegion').textContent = `Region: ${sanitizeText(data.region || '--')}`;
    document.getElementById('ipAddr').textContent = `IP: ${sanitizeText(data.ip || '--')}`;

    ip.style.display = 'block';
    topcard.style.display = 'flex';
    mapcard.style.display = 'flex';
    smap.style.display = 'block';

    show_map(lat, lon);
}

async function whois_query(query, csrf_token) {
    const whois_card = document.getElementById('whois-card');
    const whois_result = document.getElementById('whois-query-result');
    const msg = document.getElementById('msg');

    [whois_card, msg].forEach(el => el.style.display = 'none');

    const res = await fetch('/api/whois/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf_token },
        body: JSON.stringify({ query })
    });

    if (!res.ok) return;

    let data;
    try {
        data = await res.json();
    } catch {
        return;
    }

    if (data?.success === "False") {
        msg.textContent = sanitizeText(data.result || 'Error');
        msg.className = 'error';
        msg.style.display = 'block';
    } else {
        whois_result.textContent = sanitizeText(data.result || '');
        whois_card.style.display = 'block';
    }
}
