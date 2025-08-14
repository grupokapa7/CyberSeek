async function Session() {
    const res = await fetch('/session');
    if (res.status === 401) window.location.href = '/login';
}

function sanitizeText(str) {
    return typeof str === 'string' ? str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '')
        .replace(/'/g, '') : '';
}

function renderSPFTable(subactions) {
    const container = document.getElementById("spf-container");
    const card = document.getElementById("spf-card");
    container.innerHTML = '';
    card.style.display = "none";

    if (!Array.isArray(subactions)) return;

    const table = document.createElement('table');
    const thead = document.createElement('thead');
    const tbody = document.createElement('tbody');

    const headRow = document.createElement('tr');
    ['Name', 'Response', 'Status'].forEach(text => {
        const th = document.createElement('th');
        th.textContent = text;
        headRow.appendChild(th);
    });
    thead.appendChild(headRow);

    let validCount = 0;

    subactions.forEach(sa => {
        const rawName = sa?.Name?.trim();
        if (!rawName || rawName.toUpperCase() === 'N/A') return;

        const tr = document.createElement('tr');

        const nameTd = document.createElement('td');
        nameTd.textContent = rawName;

        const responseTd = document.createElement('td');
        responseTd.textContent = sa?.Response || '--';

        const statusTd = document.createElement('td');
        const span = document.createElement('span');

        if (sa?.Status === "0") {
            span.className = "ok";
            span.textContent = "Good";
        } else if (sa?.Status === "1") {
            span.className = "warning";
            span.textContent = "Warning";
        } else {
            span.className = "error";
            span.textContent = "Fail";
        }

        statusTd.appendChild(span);
        [nameTd, responseTd, statusTd].forEach(td => tr.appendChild(td));
        tbody.appendChild(tr);
        validCount++;
    });

    if (validCount === 0) return;

    table.appendChild(thead);
    table.appendChild(tbody);
    container.appendChild(table);
    card.style.display = "block";
}


async function spf_query(query, csrf_token) {
    const msg = document.getElementById('msg');
    const spf_transcript = document.getElementById('spf-transcript-card');
    const spf_card = document.getElementById('spf-card');
    msg.style.display = spf_transcript.style.display = spf_card.style.display = 'none';

    const res = await fetch('/api/spf/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf_token },
        body: JSON.stringify({ query })
    });

    if (!res.ok) {
        msg.textContent = 'Server error. Please try again.';
        msg.className = 'error';
        msg.style.display = 'block';
        return;
    }

    let data;
    try {
        data = await res.json();
    } catch {
        msg.textContent = 'Invalid response.';
        msg.className = 'error';
        msg.style.display = 'block';
        return;
    }

    if (data?.success === "False") {
        msg.textContent = sanitizeText(data?.result || 'Unknown error');
        msg.className = 'error';
        msg.style.display = 'block';
        return;
    }

    const transcript = data?.ResultDS?.Transcript?.[0]?.Transcript || 'No transcript available';
    document.getElementById('spf-transcript-container').innerText = sanitizeText(transcript);

    renderSPFTable(data?.ResultDS?.SubActions);
    spf_transcript.style.display = 'block';
}
