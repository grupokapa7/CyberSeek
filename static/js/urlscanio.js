
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
        .replace(/"/g, '')
        .replace(/'/g, '') : '';
}

async function getQuote(){
    const error = document.getElementById('msg');
    const quote = document.getElementById('quote');
    const res = await fetch("/api/urlscanio/quote",{
        headers: {
            "Content-Type": "application/json"
        }
    });
    
    if (!res.ok){
        console.log(`Server error: ${res.status}`);
        error.textContent = "Error when try to get quote"
        error.className = "error";
        return
    }

    const data = await res.json();

    if(data.success==='False'){
        error.textContent = sanitizeText(data?.result)
        error.className = "error";
        return
    }

    if(data?.limits?.public){
        quote.textContent = ("Used daily quota: " + sanitizeText(String(data?.limits?.public?.day?.used)) + "/" + sanitizeText(String(data?.limits?.public?.day?.limit)) || '0/0' )
    }

}

async function urlscanio_submit(query, csrf_token) {
    const ids = [
        'analyzing','other-card','requests-stats','verdict','msg','verdictBox', 'page-details', 'snapshot', 'requests-card',
        'urls-table-container', 'domains-table-container',
        'ip-table-container', 'certificates-table-container', 'ioc-card', 'hashes-table-container'
    ].map(id => document.getElementById(id));

    const [
        analyzing,otherCard,requestsStats,verdict, error,verdictBox, page_details, snapshot, requestTable,
        urlsTable, domainsTable, ipTable,
        certificatesTable, iocCard, hashesTable
    ] = ids;

    [page_details, otherCard,snapshot,requestsStats, requestTable, urlsTable, domainsTable, ipTable, certificatesTable, iocCard,verdictBox,hashesTable].forEach(el => el.style.display = 'none');
    analyzing.style.display = 'flex';
    error.textContent = '';
    error.className = '';
    snapshot.src='';
    verdictBox.className = 'verdict-neutral';
    verdict.textContent = '--';

    const res = await fetch('/api/urlscanio/url',{
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrf_token
        },
        body: JSON.stringify({ query })
    });

    if (!res.ok){
        console.log(`Server error: ${res.status}`);
        error.textContent = "Error when try to get result"
        error.className = "error";
        analyzing.style.display = 'none';
        return
    }

    const data = await res.json();

    if(data.success==='False'){
        error.textContent = sanitizeText(data?.result)
        error.className = "error";
        analyzing.style.display = 'none';
        return
    }else{
        api_result = data?.api
        uuid = data?.uuid 
        message = data?.message
        urlscanio_status(uuid,csrf_token)
    }

}

async function urlscanio_status(uuid,csrf_token,interval = 9000,maxAttempts = 30) {
    const error = document.getElementById("msg");
    const analyzing = document.getElementById('analyzing');

    let attempts = 0;
    while (attempts < maxAttempts) {
        try {
            const response = await fetch("/api/urlscanio/report", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": csrf_token
                    },
                body: JSON.stringify({ query: uuid })
            });

            const data = await response.json();
            if (data.status !== 404 ) {
                analyzing.style.display="none";
                break;
            }

            attempts++;
            await new Promise(resolve => setTimeout(resolve, interval));

        } catch (err) {
            analyzing.style.display="none";
            error.textContent = "Error when try to recover task status on urlscan.io";
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

    getReport(uuid,csrf_token);

}

async function getReport(uuid,csrf_token) {
    const ioc = document.getElementById('ioc-card');
    const response = await fetch("/api/urlscanio/report", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrf_token
        },
        body: JSON.stringify({ query: uuid })
    });

    if (!response.ok){
        console.log(`Server error: ${res.status}`);
        error.textContent = "Error when try to get results from urlscan.io"
        error.className = "error";
        return
    }

    const data = await response.json();

    if(data.success==='False'){
        error.textContent = sanitizeText(data?.result)
        error.className = "error";
        return
    }

    if(data?.task?.screenshotURL){
        renderScreenshotURL(data?.task?.screenshotURL)
    }

    if(data?.stats?.ipStats){
        renderStats(data?.stats?.ipStats)
    }
    
    if(data?.page){
        renderPageData(data?.page)
    }
    if(data?.task?.domain){
        getFinalVerdict(data?.task?.domain,csrf_token)
    }
    if(data?.data?.requests){
        renderRequestsTable(data?.data?.requests)
    }
    if(data?.data?.console){
        getConsole(data?.data?.console);
    }
    if(data?.lists){
        renderDomainTable(data?.lists?.domains)
        renderIpsTable(data?.lists.ips)
        renderCertificatesTable(data?.lists?.certificates)
        renderUrlsTable(data?.lists?.urls)
        renderHashes(data?.lists?.hashes)
        ioc.style.display = 'block'
    }
}


let rqChart = null;

function renderStats(stats) {
  if (!Array.isArray(stats)) return;

  const ipRequestDict = {};
  stats.forEach(item => {
    ipRequestDict[item.ip] = item.requests;
  });

  const labels = Object.keys(ipRequestDict);
  const values = Object.values(ipRequestDict);
  const container = document.getElementById('requests-stats');
  container.style.display = 'flex';

  const ctx = document.getElementById('requestsCanvas').getContext('2d');
  if (rqChart) rqChart.destroy();

  rqChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Requests stats',
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
      plugins: {
        legend: { labels: { color: '#00fff7' } },
      },
      scales: {
        x: { ticks: { color: '#00fff7' }, grid: { color: 'rgba(0,255,247,0.1)' } },
        y: { ticks: { color: '#00fff7' }, grid: { color: 'rgba(0,255,247,0.1)' } }
      }
    }
  });
}

function getConsole(data){
    if (!Array.isArray(data)) return;
    const consoleCard = document.getElementById("other-table-container");
    const otherCard = document.getElementById('other-card');
    consoleCard.innerHTML = '';
    consoleCard.style.display = "block";

    const table = document.createElement('table');
    const thead = document.createElement('thead');
    const headerRow = document.createElement('tr');

    const headers = [
        { text: 'source', style: 'width: 180px;' },
        { text: 'text' },
        { text: 'level', style: 'width: 180px;' }
    ];

    headers.forEach(({ text, style }) => {
        const th = document.createElement('th');
        if (style) th.style.cssText = style;
        headerRow.appendChild(th);
    });

    thead.appendChild(headerRow);
    table.appendChild(thead);
    const tbody = document.createElement('tbody');

    data.forEach(sa => {
        const tr = document.createElement('tr');
        const source = sa?.message?.source ?? '';
        const text = sa?.message?.text ?? '';
        const level = sa?.message?.level ?? '';

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

        tr.appendChild(createTd([source]));
        tr.appendChild(createTd([text]));
        tr.appendChild(createTd([level]));

        tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    otherCard.style.display='block'
    consoleCard.appendChild(table);

}

async function getFinalVerdict(query,csrf_token){

    const status = document.getElementById('verdict');
    const dsVerdict = document.getElementById('dsVerdict');
    const verdictBox = document.getElementById('verdictBox');
    const verdictDetails = document.getElementById('verdict-details');

    const verdict = {
        malicious:    {class:"hud-box danger", zone:"Dangerous", desc:"Malicious activity confirmed."},
        neutral:   {class:"hud-box neutral", zone:"Not categorized", desc:"Not classified yet."},
        unknown: {class:"hud-box neutral", zone:"Not categorized", desc:"Not classified yet."},
        clean:  {class:"hud-box good", zone:"Good",desc:"Clean, no threats detected."}
    };

    const response = await fetch("/api/urlscanio/final_verdict", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrf_token
        },
        body: JSON.stringify({ query: query })
    });
    const data = await response.json()

    let v = verdict['unknown']

    if(data?.gsb?.verdict){
        dangerous = data?.gsb?.verdict?.dangerous || false
        malware = data?.gsb?.verdict?.malware || false
        phishing = data?.gsb?.verdict?.phishing || false
        pua = data?.gsb?.verdict?.pua || false

        const vd = `Malicious: ${sanitizeText(String(dangerous))} <br> Malware: ${sanitizeText(String(malware))} <br>Phishing: ${sanitizeText(String(phishing))} <br>PUA: ${sanitizeText(String(pua))}`

        if(dangerous || malware || phishing || pua){
            v = verdict['malicious']
        }else{
            v = verdict['neutral']
        }
        verdictDetails.innerHTML = vd
    }else{
        v = verdict['unknown']
    }

    verdictBox.className = v.class;
    status.textContent = v.zone;
    dsVerdict.textContent = v.desc;
    verdictBox.style.display = 'block'
}

function renderRequestsTable(data){
    if (!Array.isArray(data)) return;
    const requestsCard = document.getElementById("requests-card");
    const requestsTableContainer = document.getElementById("requests-table-container");
    requestsTableContainer.innerHTML = '';
    requestsCard.style.display = "block";

    const table = document.createElement('table');
    const thead = document.createElement('thead');
    const headerRow = document.createElement('tr');

    const headers = [
        { text: 'Method', style: 'width: 80px;' },
        { text: 'Status', style: 'width: 80px;' },
        { text: 'Url' },
        { text: 'Type', style: 'width: 180px;' },
        { text: 'IP Address', style: 'width: 180px;' }
    ];

    headers.forEach(({ text, style }) => {
        const th = document.createElement('th');
        //th.textContent = text;
        if (style) th.style.cssText = style;
        headerRow.appendChild(th);
    });

    thead.appendChild(headerRow);
    table.appendChild(thead);
    const tbody = document.createElement('tbody');

    data.forEach(sa => {
        const requests = sa?.request;
        const response = sa?.response;

        const tr = document.createElement('tr');
        const method = requests?.request?.method ?? '';
        const protocol = response?.response?.protocol ?? '';
        const status = response?.response?.status ?? '';
        const url = requests?.request?.url ?? '';
        const type = response?.type ?? '';
        const mimeType = response?.response?.mimeType ?? '';
        const remoteIPAddress = response?.response?.remoteIPAddress ?? '';
        const server = response?.response?.headers?.server ?? '';

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

function renderScreenshotURL(screenshotURL){
    const img = document.getElementById('snapshot');
    img.src = screenshotURL
    img.style.display = 'block';
}

function renderPageData(data){
    const pageDiv = document.getElementById('page-details')
    pageDiv.textContent = '';
    for (const [key, value] of Object.entries(data)) {
        const pKey = document.createElement('p');
        const spanValue = document.createElement('span');
        pKey.textContent = `${sanitizeText(key).toUpperCase()}: ` || '-- : ';
        spanValue.textContent = sanitizeText(String(value)) || '--';
        pKey.append(spanValue);
        pageDiv.appendChild(pKey);
    }
    pageDiv.style.display='block';
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

async function renderHashes(data) {
    if (!Array.isArray(data)) return;

    const hashesTable = document.getElementById("hashes-table-container");
    hashesTable.style.display = 'block';
    hashesTable.innerHTML = '';
    const table = document.createElement('table');

    const thead = document.createElement('thead');
    const headerRow = document.createElement('tr');
    const th = document.createElement('th');
    th.textContent = 'Hash';
    headerRow.appendChild(th);
    thead.appendChild(headerRow);
    table.appendChild(thead);
    const tbody = document.createElement('tbody');

    data.forEach(hash => {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.textContent = hash; 
        tr.appendChild(td);
        tbody.appendChild(tr);
    });

    table.appendChild(tbody);
    hashesTable.appendChild(table);
}