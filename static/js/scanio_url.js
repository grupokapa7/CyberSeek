
async function Session(){
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

async function scanio_url(query, csrf_token) {
  const ids = [
    'analyzing', 'msg', 'mitre', 'other-card', 'snapshot', 'requests-card',
    'mitre-verdict-text', 'urls-table-container', 'domains-table-container',
    'ip-table-container', 'certificates-table-container', 'ioc-card'
  ].map(id => document.getElementById(id));

  const [
    analyzing, error, mitre, otherCard, snapshot, requestTable,
    mitreVerdictText, urlsTable, domainsTable, ipTable,
    certificatesTable, iocCard
  ] = ids;

  [mitre, snapshot, otherCard, requestTable, urlsTable, domainsTable, ipTable, certificatesTable, iocCard].forEach(el => el.style.display = 'none');
  analyzing.style.display = 'flex';
  mitreVerdictText.textContent = '';
  error.textContent = '';
  error.className = '';

  try {
    const res = await fetch("/api/filescanio/url", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": csrf_token
      },
      body: JSON.stringify({ query })
    });

    if (!res.ok){
        console.log(`Server error: ${res.status}`);
    }

    const data = await res.json();

    if (data?.success === "False" || data?.detail === "URL is invalid") {
      error.textContent = "Error when trying to create task on filescan.io";
      error.className = "error";
      return;
    }

    if (data?.flow_id) {
      checkstatus(data.flow_id, csrf_token);
    }
  } catch (e) {
    error.textContent = "Network or server error occurred";
    error.className = "error";
    console.error(e);
  } 
}

async function get_url_report(flow_id, csrf_token) {
    const error = document.getElementById("msg");
    const verdict = document.getElementById('verdict');
    const verdictText = document.getElementById('verdictText');
    const snapshot = document.getElementById('snapshot');
    const iocCard = document.getElementById('ioc-card');

    verdict.className = 'verdict-neutral';
    verdictText.textContent = '--';
    snapshot.style.display = 'none';
    snapshot.src = '';
    iocCard.style.display = 'none';

    const verdict_class = {
        "MALICIOUS": {class: "verdict-danger", status: "MALICIOUS", hud: "hud-box danger"},
        "UNKNOWN": {class: "verdict-neutral", status: "NEUTRAL", hud: "hud-box neutral"},
        "LIKELY_MALICIOUS": {class: "verdict-suspicious", status: "LIKELY MALICIOUS", hud: "hud-box suspicious", textClass: "phishing"},
        "SUSPICIOUS": {class: "verdict-suspicious", status: "SUSPICIOUS", hud: "hud-box suspicious"},
        "NO_THREAT": {class: "verdict-good", status: "NO THREATS", hud: "hud-box good"},
        "BENIGN": {class: "verdict-good", status: "NO THREATS", hud: "hud-box good", textClass: "clean"}
    };

    try {
        const response = await fetch("/api/filescanio/url_report", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRFToken": csrf_token
            },
            body: JSON.stringify({ query: flow_id })
        });

        if (!response.ok) {
            console.log(`Server error: ${response.status}`);
        }

        const data = await response.json();

        if (data?.success === "True" && data?.reports && Object.keys(data.reports).length > 0) {
            for (const reportDetails of Object.values(data.reports)) {
                if (!reportDetails?.resources) continue;

                for (const resource of Object.values(reportDetails.resources)) {
                    const finalReport = resource?.renderResults;
                    if (!finalReport) continue;

                    const finalVerdict = finalReport?.verdict?.verdict || 'UNKNOWN';
                    const verdictInfo = verdict_class[finalVerdict] || verdict_class['UNKNOWN'];

                    verdict.className = verdictInfo.class;
                    verdictText.textContent = verdictInfo.status;

                    const firstRenderResult = Array.isArray(finalReport.renderResults) ? finalReport.renderResults[0] : null;
                    if (firstRenderResult?.urlRenderData) {
                        const urlRenderData = firstRenderResult.urlRenderData;
                        const base64snapshot = urlRenderData.snapshot || '';

                        const lists = urlRenderData?.result?.lists || {};
                        const certificates = Array.isArray(lists.certificates) ? lists.certificates : [];
                        const domains = Array.isArray(lists.domains) ? lists.domains : [];
                        const urls = Array.isArray(lists.urls) ? lists.urls : [];
                        const ips = Array.isArray(lists.ips) ? lists.ips : [];
                        const requests = Array.isArray(urlRenderData?.result?.data?.requests) ? urlRenderData.result.data.requests : [];

                        iocCard.style.display = 'block';
                        renderCertificatesTable(certificates);
                        renderDomainTable(domains);
                        renderIpsTable(ips);
                        renderUrlsTable(urls);
                        renderRequestsTable(requests);

                        if (base64snapshot) {
                            snapshot.src = "data:image/png;base64," + base64snapshot;
                            snapshot.style.display = 'block';
                        } else {
                            snapshot.style.display = 'none';
                        }
                    }
                }
            }
        }
    } catch (err) {
        error.textContent('Error fetching URL report');
        error.classList = 'error';
        error.style.display = 'block';
        verdict.className = 'verdict-neutral';
        verdictText.textContent = '--';
        snapshot.style.display = 'none';
        iocCard.style.display = 'none';
    }
}


function createBox(verdictBox = "Loading...", hubClass="",tacticBox="", artefactBox = "",verdictDesBox="",tecniqueBox="") {
  const box = document.createElement("div");
  box.classList = hubClass;
  box.style.display='block';

  const tactic = document.createElement("h2");
  tactic.textContent = "Tactic: " + tacticBox;

  const tecnique = document.createElement("h4");
  tecnique.textContent = "Technique: " + tecniqueBox;

  const scanLines = document.createElement("div");
  scanLines.classList = "scan-lines";

  const p1 = document.createElement("p");
  const verdict = document.createElement("strong");
  verdict.textContent = verdictBox;

  const verdictDesc = document.createElement("span");
  verdictDesc.textContent = verdictDesBox;
  p1.appendChild(verdict);
  p1.appendChild(document.createTextNode(" "));
  p1.appendChild(verdictDesc);

  const artefact = document.createElement("p");
  artefact.style.display = "block";
  artefact.textContent = artefactBox;

  box.appendChild(tactic);
  box.appendChild(scanLines);
  box.appendChild(tecnique);
  box.appendChild(p1);
  box.appendChild(artefact);

  return box;
}

async function get_url_mitre_report(flow_id, csrf_token) {
    const error = document.getElementById("msg");
    const mitre = document.getElementById('mitre');
    const otherCard = document.getElementById('other-card');
    const verdict_class = {
        "MALICIOUS": {class:"verdict-danger",status:"MALICIOUS",hud:"hud-box danger",textClass:"malicious"},
        "UNKNOWN": {class:"verdict-neutral",status:"NEUTRAL",hud:"hud-box neutral",textClass:"unrate"},
        "SUSPICIOUS": {class:"verdict-suspicious",status:"SUSPICIOUS",hud:"hud-box suspicious",textClass:"phishing"},
        "LIKELY_MALICIOUS":{class:"verdict-suspicious",status:"LIKELY MALICIOUS",hud:"hud-box suspicious",textClass:"phishing"},
        "NO_THREAT": {class:"verdict-good",status:"NO THREATS",hud:"hud-box good",textClass:"clean"},
        "BENIGN": {class:"verdict-good",status:"NO THREATS",hud:"hud-box good",textClass:"clean"}
    };

    try {
        const response = await fetch("/api/filescanio/mitre_report", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRFToken": csrf_token
            },
            body: JSON.stringify({ query: flow_id })
        });

        if (!response.ok) {
            console.log(`Server error: ${response.status}`);
        }

        const data = await response.json();

        if (data?.success === "True" && data?.reports && Object.keys(data.reports).length > 0) {
            const mitreDiv = document.querySelector('.mitre-details');
            mitre.style.display = 'block';
            mitreDiv.textContent = '';

            for (const [_, reportDetails] of Object.entries(data.reports)) {
                if (reportDetails?.allSignalGroups && Array.isArray(reportDetails.allSignalGroups)) {
                    let mitreVerdict = reportDetails.finalVerdict?.verdict || 'UNKNOWN';
                    if (!verdict_class[mitreVerdict]) mitreVerdict = 'UNKNOWN';

                    const mitreVerdictText = document.getElementById('mitre-verdict-text');
                    mitreVerdictText.textContent = verdict_class[mitreVerdict].status;
                    mitreVerdictText.className = verdict_class[mitreVerdict].textClass;

                    const allSignalGroups = reportDetails.allSignalGroups;

                    const table = document.createElement('table');
                    const thead = document.createElement('thead');
                    const headerRow = document.createElement('tr');
                    [
                        { text: 'ID', style: 'width: 120px;' },
                        { text: 'Description' },
                        { text: 'Verdict', style: 'width: 180px;' }
                    ].forEach(({text, style}) => {
                        const th = document.createElement('th');
                        th.textContent = text;
                        if (style) th.style.cssText = style;
                        headerRow.appendChild(th);
                    });
                    thead.appendChild(headerRow);
                    table.appendChild(thead);

                    const tbody = document.createElement('tbody');

                    allSignalGroups.forEach(sa => {
                        const tr = document.createElement('tr');

                        const itemVerdict = sa?.verdict?.verdict || 'UNKNOWN';
                        const verdictInfo = verdict_class[itemVerdict] || verdict_class['UNKNOWN'];

                        const identifier = sa?.identifier || '';
                        const description = sa?.description || '';

                        const tdId = document.createElement('td');
                        tdId.textContent = sanitizeText(identifier);
                        tr.appendChild(tdId);

                        const tdDescription = document.createElement('td');
                        tdDescription.textContent = sanitizeText(description);
                        tr.appendChild(tdDescription);

                        const tdVerdict = document.createElement('td');
                        tdVerdict.textContent = verdictInfo.status;
                        tdVerdict.className = verdictInfo.textClass;
                        tr.appendChild(tdVerdict);

                        tbody.appendChild(tr);

                        if (sa?.allMitreTechniques && Array.isArray(sa.allMitreTechniques) && sa.allMitreTechniques.length > 0) {
                            const technique = sa.allMitreTechniques[0];
                            const techniqueID = sanitizeText(technique.ID || '');
                            const techniqueName = sanitizeText(technique.name || '');
                            const relatedTacticID = sanitizeText(technique.relatedTactic?.ID || '');
                            const relatedTacticName = sanitizeText(technique.relatedTactic?.name || '');
                            const signalReadable = sa.signals?.[0]?.signalReadable || '';

                            const box = createBox(
                                verdictInfo.status,
                                verdictInfo.hud,
                                relatedTacticName,
                                signalReadable,
                                sanitizeText(description),
                                `${relatedTacticID} - ${techniqueName}`
                            );
                            mitreDiv.appendChild(box);
                        }
                    });

                    table.appendChild(tbody);

                    otherCard.style.display = 'block';
                    const otherTableContainer = document.getElementById("other-table-container");
                    otherTableContainer.textContent = '';
                    otherTableContainer.appendChild(table);
                }
                break; 
            }
        }
    } catch (err) {
        error.textContent('Error loading MITRE report');
        error.classList = 'error';
        error.style.display = 'block';
    }
}

async function checkstatus(flow_id,csrf_token,interval = 9000,maxAttempts = 30) {
    const error = document.getElementById("msg");
    const analyzing = document.getElementById('analyzing');

    let attempts = 0;
    while (attempts < maxAttempts) {
        try {
            const response = await fetch("/api/filescanio/status", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": csrf_token
                    },
                body: JSON.stringify({ query: flow_id })
            });

            if (!response.ok) {
                error.textContent = `Filescan.io Server responded with status ${response.status}`;
                error.classList = "error";
            }

            const data = await response.json();
            if (data?.state === "finished") {
                analyzing.style.display="none";
                break;
            }
            
            attempts++;
            await new Promise(resolve => setTimeout(resolve, interval));

        } catch (err) {
            analyzing.style.display="none";
            error.textContent = "Error when try to recover task status on filescan.io";
            error.classList = "error";
            return;
        }
    }

    if (attempts >= maxAttempts) {
        analyzing.style.display = "none";
        error.textContent = "Timeout: Unable to retrieve task status after multiple attempts.";
        error.className = "error";
        return;
    }

    get_url_report(flow_id,csrf_token);
    get_url_mitre_report(flow_id,csrf_token)

}

async function renderRequestsTable(data) {
    if (!Array.isArray(data)) return;

    const requestsCard = document.getElementById("requests-card");
    const requestsTableContainer = document.getElementById("requests-table-container");

    requestsCard.style.display = "block";
    requestsTableContainer.innerHTML = '';
    const table = document.createElement('table');
    const thead = document.createElement('thead');
    const headerRow = document.createElement('tr');

    const headers = [
        { text: 'Method', style: 'width: 90px;' },
        { text: 'Status', style: 'width: 90px;' },
        { text: 'Url' },
        { text: 'Type', style: 'width: 180px;' },
        { text: 'IP Address', style: 'width: 180px;' }
    ];

    headers.forEach(({ text, style }) => {
        const th = document.createElement('th');
        th.textContent = text;
        if (style) th.style.cssText = style;
        headerRow.appendChild(th);
    });

    thead.appendChild(headerRow);
    table.appendChild(thead);
    const tbody = document.createElement('tbody');

    data.forEach(sa => {
        const tr = document.createElement('tr');
        const method = sa?.request?.request?.method ?? '';
        const protocol = sa?.response?.response?.protocol ?? '';
        const status = sa?.response?.response?.status ?? '';
        const url = sa?.request?.request?.url ?? '';
        const type = sa?.response?.type ?? '';
        const mimeType = sa?.response?.response?.mimeType ?? '';
        const remoteIPAddress = sa?.response?.response?.remoteIPAddress ?? '';
        const server = sa?.response?.response?.headers?.server ?? '';
        function createTd(lines) {
            const td = document.createElement('td');
            lines.forEach((line, index) => {
                td.appendChild(document.createTextNode(line));
                if (index < lines.length - 1) {
                    td.appendChild(document.createElement('br'));
                }
            });
            return td;
        }

        tr.appendChild(createTd([method, protocol]));
        tr.appendChild(createTd([String(status)]));
        tr.appendChild(createTd([url]));
        tr.appendChild(createTd([type, mimeType]));
        tr.appendChild(createTd([remoteIPAddress, server]));

        tbody.appendChild(tr);
    });

    table.appendChild(tbody);
    requestsTableContainer.appendChild(table);
}

async function renderDomainTable(data) {
    if (!Array.isArray(data)) return;

    const domainTable = document.getElementById("domains-table-container");
    domainTable.style.display = 'block';
    domainTable.innerHTML = '';

    const table = document.createElement('table');

    const thead = document.createElement('thead');
    const headerRow = document.createElement('tr');
    const th = document.createElement('th');
    th.textContent = 'Domains';
    headerRow.appendChild(th);
    thead.appendChild(headerRow);
    table.appendChild(thead);
    const tbody = document.createElement('tbody');

    data.forEach(domain => {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.textContent = domain;
        tr.appendChild(td);
        tbody.appendChild(tr);
    });

    table.appendChild(tbody);
    domainTable.appendChild(table);
}


async function renderIpsTable(data) {
    if (!Array.isArray(data)) return;

    const ipTable = document.getElementById("ip-table-container");
    ipTable.style.display = 'block';
    ipTable.innerHTML = '';
    const table = document.createElement('table');

    const thead = document.createElement('thead');
    const headerRow = document.createElement('tr');
    const th = document.createElement('th');
    th.textContent = 'IP';
    headerRow.appendChild(th);
    thead.appendChild(headerRow);
    table.appendChild(thead);
    const tbody = document.createElement('tbody');

    data.forEach(ip => {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.textContent = ip; 
        tr.appendChild(td);
        tbody.appendChild(tr);
    });

    table.appendChild(tbody);
    ipTable.appendChild(table);
}

async function renderCertificatesTable(data) {
    if (!Array.isArray(data)) return;

    const certificatesTable = document.getElementById("certificates-table-container");
    certificatesTable.style.display = 'block';
    certificatesTable.innerHTML = '';
    const table = document.createElement('table');

    const thead = document.createElement('thead');
    const headerRow = document.createElement('tr');

    ['Cert Issuer', 'Subject Name', 'Valid From', 'Valid To'].forEach(text => {
        const th = document.createElement('th');
        th.textContent = text;
        headerRow.appendChild(th);
    });

    thead.appendChild(headerRow);
    table.appendChild(thead);
    const tbody = document.createElement('tbody');

    const options = { month: 'short', day: 'numeric', year: 'numeric' };

    data.forEach(sa => {
        const tr = document.createElement('tr');
        const issuer = sa?.issuer ?? '';
        const subjectName = sa?.subjectName ?? '';

        const validFrom = sa?.validFrom ? new Date(sa.validFrom * 1000) : null;
        const validTo = sa?.validTo ? new Date(sa.validTo * 1000) : null;

        const validFromDateFormat = validFrom ? validFrom.toLocaleDateString('en-US', options) : '';
        const validToDateFormat = validTo ? validTo.toLocaleDateString('en-US', options) : '';

        [issuer, subjectName, validFromDateFormat, validToDateFormat].forEach(text => {
            const td = document.createElement('td');
            td.textContent = text;
            tr.appendChild(td);
        });

        tbody.appendChild(tr);
    });

    table.appendChild(tbody);
    certificatesTable.appendChild(table);
}


async function renderUrlsTable(data) {
  if (!Array.isArray(data)) return;

  const urlsTable = document.getElementById("urls-table-container");
  urlsTable.style.display = 'block';
  urlsTable.innerHTML = '';

  const table = document.createElement('table');

  const thead = document.createElement('thead');
  const headerRow = document.createElement('tr');
  const th = document.createElement('th');
  th.textContent = 'Url';
  headerRow.appendChild(th);
  thead.appendChild(headerRow);
  table.appendChild(thead);

  const tbody = document.createElement('tbody');

  data.forEach(item => {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.textContent = item;
    
    tr.appendChild(td);
    tbody.appendChild(tr);
  });

  table.appendChild(tbody);
  urlsTable.appendChild(table);
}
