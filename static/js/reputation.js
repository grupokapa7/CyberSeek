async function Session(){
    const res = await fetch('/session');
    if (res.status === 401) {
        window.location.href = '/login';
    }
}


async function KasperskyLookup(query, csrf_token) {
    const status = document.getElementById('verdict');
    const desc = document.getElementById('dsKaspersky');
    const kasBox = document.getElementById('KasperskyBox');
    const KasCat = document.getElementById('catKaspersky');

    const verdict = {
        Red:    {class:"hud-box danger", zone:"Dangerous",     desc:"Malicious activity confirmed."},
        Orange: {class:"hud-box danger", zone:"Not trusted",   desc:"Suspicious or abusive behavior."},
        Grey:   {class:"hud-box neutral", zone:"Not categorized", desc:"Not classified yet."},
        Yellow: {class:"hud-box danger", zone:"Adware and other", desc:"PUPs or adware found."},
        Green:  {class:"hud-box good", zone:"Good",            desc:"Clean, no threats detected."}
    };

    status.textContent = "";
    desc.textContent = "Loading...";
    KasCat.style.display = "none";
    kasBox.className = "hud-box neutral";
    kasBox.style.display = "block";

    try {
        const res = await fetch('/api/kaspersky/reputation', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrf_token
            },
            body: JSON.stringify({ query })
        });

        const data = await res.json();
        let info = data?.GeneralInfo?.Ip || data?.GeneralInfo?.Host || data?.GeneralInfo?.Url;
        let zone = sanitizeText(info?.Zone || data?.GeneralInfo?.Hash?.Zone || data?.GeneralInfo?.Hash_Report?.HashGeneralInfo?.Zone);
        let v = verdict[zone];

        if (!v) throw new Error("Invalid or unknown verdict.");

        status.textContent = v.zone;
        desc.textContent = v.desc;
        kasBox.className = v.class;

        let cat = info?.Categories?.[0]?.Name || data?.GeneralInfo?.Hash?.Status;
        if (cat) {
            KasCat.textContent = "Category: " + sanitizeText(cat);
            KasCat.style.display = "block";
        }

    } catch (err) {
        desc.textContent = "Error: " + (err.message || "Unable to fetch verdict.");
        kasBox.className = "hud-box danger";
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
async function show_map(_lat, _lon) {
    const mapContainer = document.getElementById('map');

    if (map) {
        map.remove();
        map = null;
    }

    map = L.map('map', { zoomControl: false, attributionControl: false }).setView([_lat, _lon], 8);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', { maxZoom: 19 }).addTo(map);

    const pulseIcon = L.divIcon({
        className: '',
        html: '<div class="pulse-marker"></div>',
        iconSize: [20, 20]
    });

    L.marker([_lat, _lon], { icon: pulseIcon }).addTo(map);

    map.invalidateSize();
}

async function dataLocation(query, csrf_token) {
  try {
    const res = await fetch('/api/ipinfo/lookup', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrf_token
      },
      body: JSON.stringify({ query })
    });

    if (!res.ok) throw new Error('Network response was not ok');

    const data = await res.json();

    if (data?.success === "True") {
      const [lat, lon] = (data.loc || '').split(',');

      document.getElementById('map').style.display = 'block';
      document.getElementById('topcard').style.display = 'flex';
      document.getElementById('map-content-card').style.display = 'flex';
      document.getElementById('ipinfo').style.display = 'block';

      document.getElementById('ipCity').textContent = (sanitizeText(data.country) || '--') + ' : ' + (sanitizeText(data.city) || '--');
      document.getElementById('ipOrg').textContent = 'Org: ' + (sanitizeText(data.org) || '--');
      document.getElementById('ipRegion').textContent = 'Region: ' + (sanitizeText(data.region) || '--');
      document.getElementById('ipAddr').textContent = 'IP: ' + (sanitizeText(data.ip) || '--');

      show_map(lat, lon);
    }
  } catch (e) {
    console.error('Error fetching location:', e);
  }
}

async function CiscoTalos_lookup(query, csrf_token) {
  const status = document.getElementById('ct-verdict');
  const desc = document.getElementById('dsCiscoTalos');
  const CiscoBox = document.getElementById('CiscoBox');
  const CiscoCat = document.getElementById('catCiscoTalos');

  status.textContent = "";
  desc.textContent = "Loading...";
  CiscoCat.style.display = "none";
  CiscoBox.className = "hud-box neutral";
  CiscoBox.style.display = "block";

  const verdict = {
    untrusted: {class:"hud-box danger", zone:"Dangerous", desc:"Known to host or distribute malicious content, such as malware, phishing, or other threats. Connections are strongly discouraged."},
    poor: {class:"hud-box danger", zone:"Dangerous", desc:"Associated with suspicious or malicious behavior, spam, or compromised infrastructure. Consider blocking or exercising extreme caution."},
    unknown: {class:"hud-box neutral", zone:"Unknown", desc:"No reliable information is available for this entity. Proceed with caution as it could represent a newly observed or unclassified."},
    neutral: {class:"hud-box neutral", zone:"Neutral", desc:"No known malicious or suspicious activity observed. Considered average reputation with no immediate indicators of risk."},
    favorable: {class:"hud-box good", zone:"Good", desc:"Positively identified as a trusted or reputable entity. Considered safe for communication and interaction."}
  };

  try {
    const res = await fetch('/api/ct/reputation', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrf_token
      },
      body: JSON.stringify({ query })
    });

    if (!res.ok) throw new Error('Network error');

    const data = await res.json();

    if (data.success === "True") {
      const zoneRaw = data?.reputation?.threat_level_mnemonic || "unknown";
      const zone = sanitizeText(zoneRaw.toLowerCase());

      const info = verdict[zone] || verdict.unknown;

      status.textContent = info.zone;
      CiscoBox.className = info.class;
      desc.textContent = info.desc;
    } else {
      desc.textContent = "Invalid query!";
    }
  } catch (e) {
    desc.textContent = "Error fetching data";
    console.error(e);
  }
}

async function vt_lookup(query, csrf_token) {
  const cards = [
    'VtStats', 'radar', 'vt-engines-card', 'vt-passive-dns-resolution-card',
    'vt-subdomains-card', 'vt-comunication-files-card', 'vt-referrer-files-card',
    'vt-siblings-card', 'vt-contacted-domain-card', 'vt-contacted-ip-card',
    'vt-dropped-files-card', 'vt-categories-card', 'vt-html-meta-card',
    'vt-outgoing-links-card'
  ].map(id => document.getElementById(id));

  const msg = document.getElementById('msg');
  cards.forEach(card => { if(card) card.style.display = 'none'; });

  const res = await fetch('/api/vt/reputation', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf_token },
    body: JSON.stringify({ query })
  });

  const data = await res.json();

  if (data?.success === "False") {
    renderStats({ harmless:0, malicious:0, suspicious:0, timeout:0, undetected:0 }, 'No data found yet');
    return;
  }

  const firstData = Array.isArray(data?.data) ? data.data[0] : data?.data;
  const results = firstData?.attributes?.last_analysis_results;
  const stats = firstData?.attributes?.last_analysis_stats;
  const type = firstData?.type;

  if (!results) {
    renderStats({ harmless:0, malicious:0, suspicious:0, timeout:0, undetected:0 }, 'No data found yet');
    renderRadar({ harmless:0, malicious:0, suspicious:0, timeout:0, undetected:0 }, 'No data found yet');
    if(msg) msg.textContent = 'No reputation yet';
    return;
  }

  renderStats(stats, 'VT Reputation');
  renderRadar(stats, 'Reputation');
  renderHostTable(Object.values(results), type);

  const engines = document.getElementById('vt-engines-card');
  if(engines) engines.style.display = 'block';

  if (type === 'domain') {
    renderSubdomainsTable(query, csrf_token);
    renderPassiveDnsResolutionTable(query, csrf_token);
    renderComunicationFilesTable(query, csrf_token);
    renderReferrerFilesTable(query, csrf_token);
    renderSiblingsTable(query, csrf_token);
  } else if (type === 'ip_address') {
    renderPassiveDnsResolutionTable(query, csrf_token);
    renderComunicationFilesTable(query, csrf_token);
    renderReferrerFilesTable(query, csrf_token);
  } else if (type === 'file') {
    renderContactedDomainTable(query, csrf_token);
    renderContactedIpTable(query, csrf_token);
    renderDroppedFilesTable(query, csrf_token);
  } else if (type === 'url') {
    const attrs = firstData?.attributes || {};
    if (attrs.categories) renderCategoriesTable(attrs.categories);
    if (attrs.outgoing_links) renderOutgoingLinksTable(attrs.outgoing_links);
    if (attrs.html_meta) renderHtmlMetaTable(attrs.html_meta);
  }
}

async function renderSiblingsTable(query, csrf_token) {
  const res = await fetch('/api/vt/reputation', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf_token },
    body: JSON.stringify({ query, action: 'siblings' })
  });

  const data = await res.json();
  if (data?.success !== "True" || !Array.isArray(data.data) || data.data.length === 0) return;

  const card = document.getElementById("vt-siblings-card");
  const container = document.getElementById("vt-siblings-table-container");
  if (!card || !container) return;

  card.style.display = "block";
  container.innerHTML = ''; 
  const table = document.createElement('table');
  const tbody = document.createElement('tbody');

  data.data.forEach(sa => {
    const tr = document.createElement('tr');

    const idTd = document.createElement('td');
    idTd.textContent = sa?.id || "N/A";
    tr.appendChild(idTd);

    const stats = sa?.attributes?.last_analysis_stats || {};
    const totalDetections = (stats.malicious || 0) + (stats.suspicious || 0);
    const totalEngines = (stats.harmless || 0) + (stats.malicious || 0) + (stats.suspicious || 0) + (stats.timeout || 0) + (stats.undetected || 0);
    const detectionRatio = `${totalDetections}/${totalEngines}`;

    const ratioTd = document.createElement('td');
    ratioTd.textContent = detectionRatio;
    tr.appendChild(ratioTd);

    const dnsRecords = sa?.attributes?.last_dns_records || [];
    const aRecords = dnsRecords.filter(r => r?.type === "A").map(r => r.value).join(' ');

    const dnsTd = document.createElement('td');
    dnsTd.textContent = aRecords;
    tr.appendChild(dnsTd);

    tbody.appendChild(tr);
  });

  table.appendChild(tbody);
  container.appendChild(table);
}

async function renderReferrerFilesTable(query, csrf_token) {
  const res = await fetch('/api/vt/reputation', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf_token },
    body: JSON.stringify({ query, action: "referrer_files" })
  });

  const data = await res.json();
  if (data?.success !== "True" || !Array.isArray(data.data) || data.data.length === 0) return;

  const card = document.getElementById("vt-referrer-files-card");
  const container = document.getElementById("vt-referrer-files-table-container");
  if (!card || !container) return;

  card.style.display = "block";
  container.innerHTML = '';

  const table = document.createElement('table');
  const tbody = document.createElement('tbody');

  data.data.forEach(sa => {
    const attrs = sa?.attributes || {};

    const name = attrs.meaningful_name || 'Unnamed File';
    const type = attrs.type_description || 'Unknown';

    const stats = attrs.last_analysis_stats || {};
    const totalDetections = (stats.malicious || 0) + (stats.suspicious || 0);
    const totalEngines = (stats.harmless || 0) + (stats.malicious || 0) + (stats.suspicious || 0) + (stats.timeout || 0) + (stats.undetected || 0);
    const detectionRatio = `${totalDetections}/${totalEngines || '0'}`;

    const timestamp = attrs.last_analysis_date;
    const scanDate = timestamp
      ? new Date(timestamp * 1000).toLocaleDateString('en-GB', {
          day: '2-digit',
          month: 'short',
          year: 'numeric'
        })
      : 'Unknown';

    const tr = document.createElement('tr');

    const tdName = document.createElement('td');
    tdName.textContent = name;
    tr.appendChild(tdName);

    const tdRatio = document.createElement('td');
    tdRatio.textContent = detectionRatio;
    tr.appendChild(tdRatio);

    const tdType = document.createElement('td');
    tdType.textContent = type;
    tr.appendChild(tdType);

    const tdDate = document.createElement('td');
    tdDate.textContent = scanDate;
    tr.appendChild(tdDate);

    tbody.appendChild(tr);
  });

  table.appendChild(tbody);
  container.appendChild(table);
}

async function renderSubdomainsTable(query, csrf_token) {
  const res = await fetch('/api/vt/reputation', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf_token },
    body: JSON.stringify({ query, action: "subdomains" })
  });

  const data = await res.json();
  if (data?.success !== "True" || !Array.isArray(data.data) || data.data.length === 0) return;

  const card = document.getElementById("vt-subdomains-card");
  const container = document.getElementById("vt-subdomains-table-container");
  if (!card || !container) return;

  card.style.display = "block";
  container.innerHTML = '';

  const table = document.createElement('table');
  const tbody = document.createElement('tbody');

  data.data.forEach(sa => {
    const tr = document.createElement('tr');

    const idTd = document.createElement('td');
    idTd.textContent = sa?.id || 'Unknown';
    tr.appendChild(idTd);

    const stats = sa?.attributes?.last_analysis_stats || {};
    const totalMalicious = stats.malicious || 0;
    const totalSuspicious = stats.suspicious || 0;
    const totalEngines = (stats.harmless || 0) + totalMalicious + totalSuspicious + (stats.timeout || 0) + (stats.undetected || 0);
    const detectionRatio = `${totalMalicious + totalSuspicious}/${totalEngines || '0'}`;

    const ratioTd = document.createElement('td');
    ratioTd.textContent = detectionRatio;
    tr.appendChild(ratioTd);

    tbody.appendChild(tr);
  });

  table.appendChild(tbody);
  container.appendChild(table);
}

async function renderPassiveDnsResolutionTable(query, csrf_token) {
  const res = await fetch('/api/vt/reputation', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf_token },
    body: JSON.stringify({ query, action: "resolutions" })
  });

  const data = await res.json();
  if (data?.success !== "True" || !Array.isArray(data.data) || data.data.length === 0) return;

  const card = document.getElementById("vt-passive-dns-resolution-card");
  const container = document.getElementById("vt-passive-dns-resolution-table-container");
  if (!card || !container) return;

  card.style.display = "block";
  container.innerHTML = '';

  const table = document.createElement('table');
  const tbody = document.createElement('tbody');

  data.data.forEach(sa => {
    const tr = document.createElement('tr');
    const attrs = sa?.attributes || {};

    const ip = attrs.ip_address || 'N/A';
    const resolver = attrs.resolver || 'N/A';

    const stats = attrs.ip_address_last_analysis_stats || {};
    const totalMalicious = stats.malicious || 0;
    const totalSuspicious = stats.suspicious || 0;
    const totalEngines = (stats.harmless || 0) + totalMalicious + totalSuspicious + (stats.timeout || 0) + (stats.undetected || 0);
    const detectionRatio = `${totalMalicious + totalSuspicious}/${totalEngines || '0'}`;

    const resolverDate = attrs.date
      ? new Date(attrs.date * 1000).toLocaleDateString('en-GB', {
          day: '2-digit',
          month: 'short',
          year: 'numeric'
        })
      : 'Unknown';

    const tdIp = document.createElement('td');
    tdIp.textContent = ip;
    tr.appendChild(tdIp);

    const tdRatio = document.createElement('td');
    tdRatio.textContent = detectionRatio;
    tr.appendChild(tdRatio);

    const tdResolver = document.createElement('td');
    tdResolver.textContent = resolver;
    tr.appendChild(tdResolver);

    const tdDate = document.createElement('td');
    tdDate.textContent = resolverDate;
    tr.appendChild(tdDate);

    tbody.appendChild(tr);
  });

  table.appendChild(tbody);
  container.appendChild(table);
}

async function renderComunicationFilesTable(query, csrf_token) {
  const res = await fetch('/api/vt/reputation', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf_token },
    body: JSON.stringify({ query, action: "communicating_files" })
  });

  const data = await res.json();
  if (data?.success !== "True" || !Array.isArray(data.data) || data.data.length === 0) return;

  const card = document.getElementById("vt-comunication-files-card");
  const container = document.getElementById("vt-comunication-files-table-container");
  if (!card || !container) return;

  card.style.display = "block";
  container.innerHTML = '';

  const table = document.createElement('table');
  const tbody = document.createElement('tbody');

  data.data.forEach(sa => {
    const attrs = sa?.attributes || {};

    const stats = attrs.last_analysis_stats || {};
    const totalDetections = (stats.malicious || 0) + (stats.suspicious || 0);
    const totalEngines = (stats.harmless || 0) + totalDetections + (stats.timeout || 0) + (stats.undetected || 0);
    const detectionRatio = `${totalDetections}/${totalEngines || '0'}`;

    const timestamp = attrs.last_analysis_date;
    const formattedDate = timestamp
      ? new Date(timestamp * 1000).toLocaleDateString('en-GB', {
          day: '2-digit',
          month: 'short',
          year: 'numeric'
        })
      : 'Unknown';

    const name = attrs.meaningful_name || 'Unnamed File';
    const type = attrs.type_description || 'Unknown';

    const tr = document.createElement('tr');

    const tdName = document.createElement('td');
    tdName.textContent = name;
    tr.appendChild(tdName);

    const tdRatio = document.createElement('td');
    tdRatio.textContent = detectionRatio;
    tr.appendChild(tdRatio);

    const tdType = document.createElement('td');
    tdType.textContent = type;
    tr.appendChild(tdType);

    const tdDate = document.createElement('td');
    tdDate.textContent = formattedDate;
    tr.appendChild(tdDate);

    tbody.appendChild(tr);
  });

  table.appendChild(tbody);
  container.appendChild(table);
}

async function renderContactedDomainTable(query, csrf_token) {
  const res = await fetch('/api/vt/reputation', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf_token },
    body: JSON.stringify({ query, action: "contacted_domain" })
  });

  const data = await res.json();
  if (data?.success !== "True" || !Array.isArray(data.data) || data.data.length === 0) return;

  const card = document.getElementById("vt-contacted-domain-card");
  const container = document.getElementById("vt-contacted-domains-table-container");
  if (!card || !container) return;

  card.style.display = "block";
  container.innerHTML = '';

  const table = document.createElement('table');
  const tbody = document.createElement('tbody');

  data.data.forEach(sa => {
    const tr = document.createElement('tr');
    const attrs = sa?.attributes || {};
    const stats = attrs.last_analysis_stats || {};

    const domain = sa?.id || 'Unknown';
    const registrar = attrs.registrar || 'N/A';

    const totalMalicious = stats.malicious || 0;
    const totalSuspicious = stats.suspicious || 0;
    const totalEngines = (stats.harmless || 0) + totalMalicious + totalSuspicious + (stats.timeout || 0) + (stats.undetected || 0);
    const detectionRatio = `${totalMalicious + totalSuspicious}/${totalEngines || '0'}`;

    const creationDate = attrs.creation_date
      ? new Date(attrs.creation_date * 1000).toLocaleDateString('en-GB', {
          day: '2-digit',
          month: 'short',
          year: 'numeric'
        })
      : 'Unknown';

    const tdDomain = document.createElement('td');
    tdDomain.textContent = domain;
    tr.appendChild(tdDomain);

    const tdRatio = document.createElement('td');
    tdRatio.textContent = detectionRatio;
    tr.appendChild(tdRatio);

    const tdDate = document.createElement('td');
    tdDate.textContent = creationDate;
    tr.appendChild(tdDate);

    const tdRegistrar = document.createElement('td');
    tdRegistrar.textContent = registrar;
    tr.appendChild(tdRegistrar);

    tbody.appendChild(tr);
  });

  table.appendChild(tbody);
  container.appendChild(table);
}
          
async function renderContactedIpTable(query, csrf_token) {
  const res = await fetch('/api/vt/reputation', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf_token },
    body: JSON.stringify({ query, action: "contacted_ip" })
  });

  const data = await res.json();
  if (data?.success !== "True" || !Array.isArray(data.data) || data.data.length === 0) return;

  const card = document.getElementById("vt-contacted-ip-card");
  const container = document.getElementById("vt-contacted-ip-table-container");
  if (!card || !container) return;

  card.style.display = "block";
  container.innerHTML = '';

  const table = document.createElement('table');
  const tbody = document.createElement('tbody');

  data.data.forEach(sa => {
    const tr = document.createElement('tr');
    const attrs = sa?.attributes || {};
    const stats = attrs.last_analysis_stats || {};

    const ip = sa?.id || 'N/A';
    const asn = String(attrs.asn || 'N/A');
    const country = attrs.country || 'N/A';

    const totalMalicious = stats.malicious || 0;
    const totalSuspicious = stats.suspicious || 0;
    const totalEngines = (stats.harmless || 0) + totalMalicious + totalSuspicious + (stats.timeout || 0) + (stats.undetected || 0);
    const detectionRatio = `${totalMalicious + totalSuspicious}/${totalEngines || '0'}`;

    [ip, detectionRatio, asn, country].forEach(text => {
      const td = document.createElement('td');
      td.textContent = text;
      tr.appendChild(td);
    });

    tbody.appendChild(tr);
  });

  table.appendChild(tbody);
  container.appendChild(table);
}

async function renderDroppedFilesTable(query, csrf_token) {
  const res = await fetch('/api/vt/reputation', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf_token },
    body: JSON.stringify({ query, action: "dropped_files" })
  });

  const data = await res.json();
  if (data?.success !== "True" || !Array.isArray(data.data) || data.data.length === 0) return;

  const card = document.getElementById("vt-dropped-files-card");
  const container = document.getElementById("vt-dropped-files-table-container");
  if (!card || !container) return;

  card.style.display = "block";
  container.innerHTML = '';

  const table = document.createElement('table');
  const tbody = document.createElement('tbody');

  data.data.forEach(sa => {
    const tr = document.createElement('tr');
    const attrs = sa?.attributes || {};
    const stats = attrs.last_analysis_stats || {};

    const name = attrs.meaningful_name || 'N/A';
    if (name === 'N/A') return;
    const type = attrs.type_description || 'Unknown';

    const totalMalicious = stats.malicious || 0;
    const totalSuspicious = stats.suspicious || 0;
    const totalEngines = (stats.harmless || 0) + totalMalicious + totalSuspicious + (stats.timeout || 0) + (stats.undetected || 0);
    const detectionRatio = `${totalMalicious + totalSuspicious}/${totalEngines || '0'}`;

    const scanned = attrs.first_submission_date
      ? new Date(attrs.first_submission_date * 1000).toLocaleDateString('en-GB', {
          day: '2-digit',
          month: 'short',
          year: 'numeric'
        })
      : 'Unknown';

    [name, detectionRatio, type, scanned].forEach(text => {
      const td = document.createElement('td');
      td.textContent = text;
      tr.appendChild(td);
    });

    tbody.appendChild(tr);
  });

  table.appendChild(tbody);
  container.appendChild(table);
}


async function renderOutgoingLinksTable(links) {
    let html = `<table>
        <thead>
        </thead><tbody>`;

    if (Object.keys(links).length > 0){
        links.forEach((link, index) => {
            html += `<tr>
                <td>${index + 1}</td>
                <td>${sanitizeText(link)}</td>
                </tr>`;
            });

        html += `</tbody></table>`;
        document.getElementById("vt-outgoing-links-table-container").innerHTML = html;
        document.getElementById("vt-outgoing-links-card").style.display = "block";
    }
}


function renderHtmlMetaTable(meta) {
  if (!meta || typeof meta !== 'object' || Object.keys(meta).length === 0) return;

  const container = document.getElementById("vt-html-meta-table-container");
  container.innerHTML = ""; 

  const table = document.createElement("table");
  const tbody = document.createElement("tbody");

  for (const [name, category] of Object.entries(meta)) {
    const tr = document.createElement("tr");

    const tdName = document.createElement("td");
    tdName.textContent = name;
    tr.appendChild(tdName);

    const tdCategory = document.createElement("td");
    tdCategory.textContent = category;
    tr.appendChild(tdCategory);

    tbody.appendChild(tr);
  }

  table.appendChild(tbody);
  container.appendChild(table);

  const card = document.getElementById("vt-html-meta-card");
  if (card) card.style.display = "block";
}



function renderCategoriesTable(categories) {
  if (!categories || typeof categories !== 'object' || Object.keys(categories).length === 0) return;

  const container = document.getElementById('vt-categories-table-container');
  container.innerHTML = '';  
  const table = document.createElement('table');
  const tbody = document.createElement('tbody');

  for (const [name, category] of Object.entries(categories)) {
    const tr = document.createElement('tr');

    const tdName = document.createElement('td');
    tdName.textContent = name; 
    tr.appendChild(tdName);

    const tdCategory = document.createElement('td');
    tdCategory.textContent = category;
    tr.appendChild(tdCategory);

    tbody.appendChild(tr);
  }

  table.appendChild(tbody);
  container.appendChild(table);

  document.getElementById('vt-categories-card').style.display = 'block';
}



let vtChart = null;

function renderStats(stats, title = '') {
  if (!stats || typeof stats !== 'object' || Array.isArray(stats)) {
    console.error('Invalid stats object');
    return;
  }
  title = String(title);

  const labels = Object.keys(stats);
  const values = Object.values(stats);
  const container = document.getElementById('VtStats');
  container.style.display = 'flex';

  const ctx = document.getElementById('VTChart').getContext('2d');
  if (vtChart) vtChart.destroy();

  vtChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: title,
        data: values,
        borderColor: '#00fff7',
        backgroundColor: 'rgba(0,255,247,0.2)',
        tension: 0.4,
        fill: true,
        pointBackgroundColor: '#00fff7',
        pointBorderColor: '#00fff7'
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: { labels: { color: '#00fff7' } }
      },
      scales: {
        x: { ticks: { color: '#00fff7' }, grid: { color: 'rgba(0,255,247,0.1)' } },
        y: { ticks: { color: '#00fff7' }, grid: { color: 'rgba(0,255,247,0.1)' } }
      }
    }
  });
}

let vtRadar = null;

function renderRadar(stats, title = '') {
  if (!stats || typeof stats !== 'object' || Array.isArray(stats)) {
    console.error('Invalid stats object');
    return;
  }
  title = String(title);

  const labels = Object.keys(stats);
  const values = Object.values(stats);
  const radarEl = document.getElementById('radar');
  radarEl.style.display = 'block';

  const ctx = document.getElementById('radarCanvas').getContext('2d');
  if (vtRadar) vtRadar.destroy();

  vtRadar = new Chart(ctx, {
    type: 'radar',
    data: { labels, datasets: [{ label: title, data: values, borderColor: '#00fff7', backgroundColor: 'rgba(0,255,247,0.2)', fill: true, pointBackgroundColor: '#00fff7', pointBorderColor: '#00fff7' }] },
    options: {
      responsive: true,
      scales: {
        r: {
          angleLines: { color: '#00fff7', lineWidth: 0.2 },
          grid: { color: '#333', lineWidth: 1.1 },
          pointLabels: { color: '#00fff7', font: { size: 10 } },
          ticks: { color: '#00fff7', backdropColor: 'rgba(0,255,247,0.1)', stepSize: 10, display: false }
        }
      },
      plugins: { legend: { labels: { color: '#00fff7', font: { size: 10 } } } }
    }
  });
}

function renderHostTable(subactions, type) {
  const severityOrder = {
    malicious: 1, malware: 2, suspicious: 3, phishing: 4,
    clean: 5, undetected: 6, "type-unsupported": 7,
    failure: 8, timeout: 9, unrated: 10
  };

  subactions.sort((a, b) => {
    const aSeverity = severityOrder[(type === "file" ? a?.category : a?.result || '').toLowerCase()] || 99;
    const bSeverity = severityOrder[(type === "file" ? b?.category : b?.result || '').toLowerCase()] || 99;
    return aSeverity - bSeverity;
  });

  const statusMap = {
    clean: ['clean', 'Good'],
    unrated: ['unrate', 'Unrated'],
    phishing: ['phishing', 'Phishing'],
    suspicious: ['phishing', 'Suspicious'],
    malicious: ['malicious', 'Malicious'],
    malware: ['malicious', 'Malware']
  };

  const table = document.createElement('table');
  const tbody = document.createElement('tbody');

  subactions.forEach(sa => {
    const tr = document.createElement('tr');

    const tdEngine = document.createElement('td');
    tdEngine.textContent = sa?.engine_name || 'Unknown';
    tr.appendChild(tdEngine);

    const resultRaw = type === "file" ? sa?.category : sa?.result || '';
    const result = resultRaw.toLowerCase();
    const [cls, label] = statusMap[result] || ['unrate', 'Unrated'];

    if (type === "file") {
      const tdResult = document.createElement('td');
      tdResult.textContent = sa?.result || '';
      tr.appendChild(tdResult);

      const tdStatus = document.createElement('td');
      const spanStatus = document.createElement('span');
      spanStatus.className = cls;
      spanStatus.textContent = label;
      tdStatus.appendChild(spanStatus);
      tr.appendChild(tdStatus);
    } else {
      const tdStatus = document.createElement('td');
      const spanStatus = document.createElement('span');
      spanStatus.className = cls;
      spanStatus.textContent = label;
      tdStatus.appendChild(spanStatus);
      tr.appendChild(tdStatus);
    }

    tbody.appendChild(tr);
  });

  table.appendChild(tbody);

  const container = document.getElementById("vt-engines-table-container");
  container.innerHTML = "";
  container.appendChild(table);
}
