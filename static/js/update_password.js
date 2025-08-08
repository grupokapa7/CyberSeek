function sanitizeText(str) {
    return typeof str === 'string' ? str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;') : '';
}

async function upd_password(current_pass, new_pass, confirm_pass, csrf_token) {
    try {
        const res = await fetch("/api/update_password", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRFToken": csrf_token
            },
            body: JSON.stringify({
                current_password: current_pass,
                new_password: new_pass,
                confirm_password: confirm_pass
            })
        }).then(r => r.json());

        const msgElem = document.getElementById('msg');
        msgElem.textContent = sanitizeText(res?.result || 'Unknown error');
        msgElem.className = res?.success === "True" ? 'ok' : 'error';
    } catch (err) {
        const msgElem = document.getElementById('msg');
        msgElem.textContent = 'Unexpected error';
        msgElem.className = 'error';
    }
}
