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

function isSafeUrl(url) {
    try {
        const parsed = new URL(url, location.origin);
        return ['http:', 'https:'].includes(parsed.protocol);
    } catch { return false; }
}

async function blacklist_query(query,csrf_token) {
    const msg = document.getElementById('msg');
    const blacklist_card = document.getElementById('blacklist-card');
    const blacklist_container = document.getElementById('blacklist-container');
    msg.style.display = 'none';
    blacklist_card.style.display='none';

    const res = await fetch('/api/blacklist/check',{
        method: 'POST',
        headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrf_token
            },
        body: JSON.stringify({ query: query }),
        credentials: "same-origin",
        referrerPolicy: "strict-origin-when-cross-origin"
    });

    const data = await res.json()
    if(data?.success==="False"){
        msg.textContent = sanitizeText(data.result);
        msg.className='error'
        msg.style.display = 'block'
        return
    }else{
        const table = renderBlacklistTable(data?.ResultDS?.SubActions);
        blacklist_container.innerHTML = '';
        blacklist_container.appendChild(table);
        blacklist_card.style.display = 'block';
    }
}


function renderBlacklistTable(subactions = []) {
    const table = document.createElement('table');
    const thead = document.createElement('thead');
    const headerRow = document.createElement('tr');
    ['Name', 'Status', 'Delist'].forEach(text => {
        const th = document.createElement('th');
        th.textContent = text;
        headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);
    table.appendChild(thead);

    const tbody = document.createElement('tbody');
    subactions.forEach(({ Name, Status, DelistUrl }) => {
        const tr = document.createElement('tr');

        const nameTd = document.createElement('td');
        nameTd.textContent = sanitizeText(Name);

        const statusTd = document.createElement('td');
        const span = document.createElement('span');
        span.className = Status === "0" ? 'ok' : Status === "1" ? 'warning' : 'error';
        span.textContent = Status === "0" ? 'Clean' : Status === "1" ? 'TimeOut' : 'Listed';
        statusTd.appendChild(span);

        const urlTd = document.createElement('td');
        if (typeof DelistUrl === 'string' && isSafeUrl(DelistUrl)) {
            const a = document.createElement('a');
            a.href = DelistUrl;
            a.textContent = 'Delist';
            a.target = '_blank';
            a.rel = 'noopener noreferrer';
            a.className = 'link';
            urlTd.appendChild(a);
        }

        [nameTd, statusTd, urlTd].forEach(td => tr.appendChild(td));
        tbody.appendChild(tr);
    });

    table.appendChild(tbody);
    return table;
}
