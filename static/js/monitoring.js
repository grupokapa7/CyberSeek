async function updateStats() {
      const res = await fetch('/api/stats');
      const data = await res.json();
      document.getElementById('cpu').innerText = data.cpu;
      document.getElementById("disk").innerText = data.disk;
      document.getElementById("memory-percent").innerText = data.memory.percent;
      document.getElementById('net-sent').innerText = data.network.sent;
      document.getElementById('net-recv').innerText = data.network.recv;
    }
setInterval(updateStats, 3000);
window.onload = updateStats;