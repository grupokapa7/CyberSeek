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


async function dns_query(query, type, csrf_token) {
    const error = document.getElementById('msg');
    error.textContent='';
    const records = ['A', 'TXT', 'PTR', 'MX', 'NS', 'CNAME', 'AAAA', 'SOA', 'DS'];

    records.forEach(r => {
        document.getElementById(`${r}-record-card`).style.display = 'none';
    });

    const res = await fetch('/api/dns/query', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrf_token
        },
        body: JSON.stringify({ query, type })
    });

    const data = await res.json();

    if(data?.success==='False'){
        error.textContent = sanitizeText(data?.result)
        error.className='error'
        error.style.display='block'
        return
    }

    if (!Array.isArray(data)) return;

    data.forEach(({ type, result, success }) => {
        if (success === "True" && records.includes(type)) {
            const card = document.getElementById(`${type}-record-card`);
            const container = document.getElementById(`${type}-record-container`);
            card.style.display = 'block';
            container.textContent = sanitizeText(result);
        }
    });
}
