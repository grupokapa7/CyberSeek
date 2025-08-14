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
async function submit_file(formData,csrf_token) {
    try {
        const analyzing = document.getElementById('analyzing');
        const info = document.getElementById('info');
        const otherCard = document.getElementById("other-card");
        const stringsCard = document.getElementById('strings-card');
        const filescanDetails = document.getElementById('filescan-details');
        const mitre = document.getElementById('mitre');
        const verdict = document.getElementById('verdict');
        const verdictText = document.getElementById('verdictText');
        analyzing.style.display="flex";
        stringsCard.style.display="none";
        filescanDetails.style.display="none";
        otherCard.style.display="none";
        mitre.style.display='none';
        const error = document.getElementById("msg");
        error.textContent = "";
        verdict.classList='verdict-neutral';
        verdictText.textContent='--';
        info.textContent = "Click a process to see details.";

        const response = await fetch('/api/filescanio/file', {
                method: 'POST',
                headers: { 
                    "X-CSRFToken": csrf_token
                },
                body: formData
            });

        const data = await response.json();
        if (data?.success === "False"){
            error.textContent = "Error when try to create task on filescan.io";
            error.classList = "error";
            analyzing.style.display="none";
            return
        }

        if(data?.success === "True" &&  data?.fileData ){
            document.getElementById('filename').textContent = 'Filename: ' + sanitizeText(data?.fileData?.filename)
            document.getElementById('size').textContent = 'Size: ' + sanitizeText(data?.fileData?.size)
            document.getElementById('mimeType').textContent = 'MimeType: ' + sanitizeText(data?.fileData?.mimetype)
            document.getElementById('md5').textContent = 'MD5: ' + sanitizeText(data?.fileData?.md5)
            document.getElementById('sha1').textContent = 'SHA1: ' + sanitizeText(data?.fileData?.sha1)
            document.getElementById('sha256').textContent = 'SHA256: ' + sanitizeText(data?.fileData?.sha256)

        }

        if(data?.flow_id){
            checkstatus(data?.flow_id,csrf_token)
        }
    } catch (err) {
        console.log('Error de red: ' + err);
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

    get_file_report(flow_id,csrf_token);
    get_file_mitre_report(flow_id,csrf_token)

}

async function get_file_report(flow_id,csrf_token) {
    const response = await fetch("/api/filescanio/file_report", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrf_token
            },
        body: JSON.stringify({ query: flow_id })
    });

    const data = await response.json();
    if(data?.success === "True" && Object.values(data?.reports)){
        for (const [reportId, reportDetails] of Object.entries(data.reports)) {
            for (const [reportId2, reportDetails2] of Object.entries(reportDetails.resources)) {
                if(reportDetails2?.emulationData){
                    emulationData = reportDetails2?.emulationData
                    processChain(emulationData);
                }

                if(reportDetails2.extractedUrls){
                    extractedUrls = reportDetails2.extractedUrls
                }

                if(reportDetails2.strings){
                    strings = reportDetails2.strings
                    renderStrings(strings);
                }
                
            }
        }
    }
}

async function renderStrings(data) {
  const stringsCard = document.getElementById('strings-card');
  const stringsContainer = document.getElementById('strings-container');

  if (!stringsCard || !stringsContainer) {
    console.error("Missing required DOM elements");
    return;
  }

  if (Array.isArray(data)) {
    const fragment = document.createDocumentFragment();

    data.forEach(sa => {
      if (sa?.references && Array.isArray(sa.references)) {
        sa.references.forEach(ref => {
          if (typeof ref?.str === "string") {
            const line = document.createElement('div');
            line.textContent = ref.str;
            fragment.appendChild(line);
          }
        });
      }
    });

    stringsContainer.textContent = '';
    stringsContainer.appendChild(fragment);
    stringsCard.style.display = 'block';
  }
}


async function processChain(data) {
  const treeContainer = document.getElementById('tree-container');
  const filescanDetails = document.getElementById('filescan-details');
  if (!treeContainer || !filescanDetails) {
    console.error("Required DOM elements missing");
    return;
  }
  treeContainer.textContent = '';

  if (Array.isArray(data) && data.length > 0) {
    const ul = document.createElement('ul');
    ul.classList.add('tree');

    data.forEach(sa => {
      const action = sa?.action ? String(sa.action) : '';
      const description = sa?.description ? String(sa.description) : '';
      
      let additionalInformation = '';
      if (sa?.additionalInformation && typeof sa.additionalInformation === 'object') {
        for (const [key, value] of Object.entries(sa.additionalInformation)) {
          const safeKey = sanitizeText(String(key));
          const safeValue = sanitizeText(String(value));
          additionalInformation += `${safeKey}: ${safeValue}\n`;
        }
      }

      const li = document.createElement('li');
      const span = document.createElement('span');

      span.textContent = action;
      span.dataset.description = description;
      span.dataset.details = additionalInformation;

      span.classList.add('process', 'green');

      li.appendChild(span);
      ul.appendChild(li);
    });

    filescanDetails.style.display = 'block';
    treeContainer.appendChild(ul);
  }
}


async function get_file_mitre_report(flow_id, csrf_token) {
  if (typeof flow_id !== "string" || !flow_id.trim()) {
    console.error("Invalid flow_id");
    return;
  }
  if (typeof csrf_token !== "string" || !csrf_token.trim()) {
    console.error("Invalid CSRF token");
    return;
  }

  const mitre = document.getElementById("mitre");
  const otherCard = document.getElementById("other-card");
  const mitreDiv = document.querySelector(".mitre-details");
  const verdict = document.getElementById("verdict");
  const verdictText = document.getElementById("verdictText");
  const otherTableContainer = document.getElementById("other-table-container");

  if (!mitre || !otherCard || !mitreDiv || !verdict || !verdictText || !otherTableContainer) {
    console.error("Missing one or more required DOM elements");
    return;
  }

  const verdict_class = {
    MALICIOUS: { class: "verdict-danger", status: "MALICIOUS", hud: "hud-box danger", textClass: "malicious" },
    UNKNOWN: { class: "verdict-neutral", status: "NEUTRAL", hud: "hud-box neutral", textClass: "unrate" },
    SUSPICIOUS: { class: "verdict-suspicious", status: "SUSPICIOUS", hud: "hud-box suspicious", textClass: "phishing" },
    LIKELY_MALICIOUS: { class: "verdict-suspicious", status: "LIKELY MALICIOUS", hud: "hud-box suspicious", textClass: "phishing" },
    NO_THREAT: { class: "verdict-good", status: "NO THREATS", hud: "hud-box good", textClass: "clean" },
    BENIGN: { class: "verdict-good", status: "NO THREATS", hud: "hud-box good", textClass: "clean" },
  };

  try {
    const response = await fetch("/api/filescanio/mitre_report", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": csrf_token,
      },
      body: JSON.stringify({ query: flow_id }),
      credentials: "same-origin",
    });

    if (!response.ok) {
      console.error("Network error:", response.status, response.statusText);
      return;
    }

    const data = await response.json();

    if (data?.success !== "True" || typeof data.reports !== "object") {
      console.warn("No valid reports found");
      return;
    }

    mitre.style.display = "block";
    mitreDiv.textContent = "";
    otherCard.style.display = "none";
    otherTableContainer.textContent = "";

    for (const reportDetails of Object.values(data.reports)) {
      let finalVerdict = reportDetails?.finalVerdict?.verdict ?? "UNKNOWN";
      if (!verdict_class.hasOwnProperty(finalVerdict)) finalVerdict = "UNKNOWN";

      verdict.className = verdict_class[finalVerdict].class;
      verdictText.textContent = verdict_class[finalVerdict].status;

      if (Array.isArray(reportDetails.allSignalGroups) && reportDetails.allSignalGroups.length > 0) {
        const table = document.createElement("table");

        const thead = document.createElement("thead");
        thead.innerHTML = `
          <tr>
            <th style="width: 120px;">ID</th>
            <th>URL</th>
            <th style="width: 180px;">Verdict</th>
          </tr>
        `;
        table.appendChild(thead);

        const tbody = document.createElement("tbody");

        reportDetails.allSignalGroups.forEach((sa) => {
          if (!sa || typeof sa !== "object") return;

          const identifier = sanitizeText(sa.identifier);
          const description = sanitizeText(sa.description);
          const itemVerdictRaw = sa?.verdict?.verdict ?? "UNKNOWN";
          const itemVerdict = verdict_class[itemVerdictRaw] ? itemVerdictRaw : "UNKNOWN";
          const tr = document.createElement("tr");

          const tdId = document.createElement("td");
          tdId.textContent = identifier;
          tr.appendChild(tdId);

          const tdUrl = document.createElement("td");
          tdUrl.textContent = description;
          tr.appendChild(tdUrl);

          const tdVerdict = document.createElement("td");
          tdVerdict.textContent = verdict_class[itemVerdict].status;
          tdVerdict.className = verdict_class[itemVerdict].textClass;
          tr.appendChild(tdVerdict);

          tbody.appendChild(tr);

          if (Array.isArray(sa.allMitreTechniques) && sa.allMitreTechniques.length > 0) {
            const tech = sa.allMitreTechniques[0];

            const techniqueID = sanitizeText(tech.ID ?? "");
            const techniqueName = sanitizeText(tech.name ?? "");
            const relatedTacticID = sanitizeText(tech.relatedTactic?.ID ?? "");
            const relatedTacticName = sanitizeText(tech.relatedTactic?.name ?? "");
            const signalReadable = sanitizeText(sa.signals?.[0]?.signalReadable ?? "");

            const hubClass = verdict_class[itemVerdict].hud;
            const text = verdict_class[itemVerdict].status;

            mitreDiv.appendChild(
              createBox(text, hubClass, relatedTacticName, signalReadable, description, `${relatedTacticID} - ${techniqueName}`)
            );
          }
        });

        table.appendChild(tbody);
        otherCard.style.display = "block";
        otherTableContainer.textContent = "";
        otherTableContainer.appendChild(table);
      }
      break;
    }
  } catch (error) {
    console.error("Error fetching or processing Mitre report:", error);
  }
}
