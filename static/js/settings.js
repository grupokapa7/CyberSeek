function sanitizeText(str) {
    if (typeof str !== 'string') return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

async function save_tokens(token,csrf_token) {
    const response = await fetch("/api/settings", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrf_token
            },
        body: JSON.stringify({ token_scanurl: token })
    });

    const result = await response.json();
    if(result?.success=="True"){
        document.getElementById('msg').textContent = "Saved success."
        document.getElementById('msg').className = 'ok'
    }else{
        document.getElementById('msg').textContent = "Error trying to save data."
        document.getElementById('msg').className = 'error'
    }
}

async function set_tokens(tokens_data) {
    const urlscanio = document.getElementById('token_scanurl');
    urlscanio.value = sanitizeText(tokens_data?.Scanurl?.token_scanurl)
}
