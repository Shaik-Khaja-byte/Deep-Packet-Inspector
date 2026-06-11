let latest = null;

document.getElementById("analyzeForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const status = document.getElementById("status");
  status.textContent = "Running dpi_engine.exe...";
  const body = new FormData(form);
  const response = await fetch("/api/analyze", { method: "POST", body });
  const data = await response.json();
  if (!response.ok && data.error) {
    status.textContent = data.error;
    return;
  }
  latest = data;
  localStorage.setItem("latestAnalysisId", data.id);
  renderDashboard(data);
  status.textContent = response.ok ? "Analysis complete" : "Engine returned an error; partial results are shown.";
});

function renderDashboard(data) {
  document.getElementById("results").classList.remove("hidden");
  renderStats(data.statistics);
  renderApps(data.applications);
  renderTables(data);
  renderSummary(data.block_summary);
  renderLogs(data.logs);
  document.getElementById("downloadPcap").href = data.downloads.pcap;
  document.getElementById("downloadJson").href = data.downloads.json;
}

function renderStats(stats) {
  const labels = [
    ["Total Packets", stats.total_packets],
    ["Forwarded", stats.forwarded],
    ["Dropped", stats.dropped],
    ["TCP Packets", stats.tcp_packets],
    ["UDP Packets", stats.udp_packets],
    ["Processing Time", `${stats.processing_time_ms} ms`],
  ];
  document.getElementById("statsGrid").innerHTML = labels
    .map(([label, value]) => `<article class="stat-card"><span>${label}</span><strong>${value}</strong></article>`)
    .join("");
}

function renderApps(apps) {
  const max = Math.max(...apps.map((a) => a.count), 1);
  document.getElementById("appBars").innerHTML = apps
    .map((app) => `
      <div class="bar-row">
        <strong>${app.app}</strong>
        <div class="bar-track"><div class="bar-fill" style="width:${(app.count / max) * 100}%"></div></div>
        <span>${app.count} (${app.percentage.toFixed(1)}%)</span>
      </div>`)
    .join("");

  drawBarChart(document.getElementById("barChart"), apps);
  drawPieChart(document.getElementById("pieChart"), apps);
}

function fitCanvas(canvas) {
  const ratio = window.devicePixelRatio || 1;
  const width = Math.max(canvas.clientWidth, 1);
  const height = Math.max(canvas.clientHeight, 1);
  canvas.width = Math.round(width * ratio);
  canvas.height = Math.round(height * ratio);
  const context = canvas.getContext("2d");
  context.setTransform(ratio, 0, 0, ratio, 0, 0);
  context.clearRect(0, 0, width, height);
  return { context, width, height };
}

function drawBarChart(canvas, apps) {
  const { context, width, height } = fitCanvas(canvas);
  const padding = { top: 22, right: 18, bottom: 48, left: 48 };
  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;
  context.fillStyle = "#ffffff";
  context.fillRect(0, 0, width, height);

  if (!apps.length) {
    context.fillStyle = "#667085";
    context.font = "14px Segoe UI, Arial, sans-serif";
    context.fillText("No application data", padding.left, height / 2);
    return;
  }

  const maxValue = Math.max(...apps.map((app) => app.count), 1);
  const barGap = 10;
  const barWidth = Math.max((plotWidth - barGap * (apps.length - 1)) / apps.length, 18);

  context.strokeStyle = "#e4e9f0";
  context.lineWidth = 1;
  for (let i = 0; i <= 4; i += 1) {
    const y = padding.top + (plotHeight * i) / 4;
    context.beginPath();
    context.moveTo(padding.left, y);
    context.lineTo(width - padding.right, y);
    context.stroke();
  }

  apps.forEach((app, index) => {
    const x = padding.left + index * (barWidth + barGap);
    const barHeight = (app.count / maxValue) * plotHeight;
    const y = padding.top + plotHeight - barHeight;

    context.fillStyle = index % 2 === 0 ? "#126b6f" : "#0f5b5f";
    roundRect(context, x, y, barWidth, barHeight, 6);
    context.fill();

    context.fillStyle = "#344054";
    context.font = "12px Segoe UI, Arial, sans-serif";
    context.textAlign = "center";
    context.fillText(app.count.toString(), x + barWidth / 2, y - 6);

    const label = truncateLabel(app.app, 12);
    context.save();
    context.translate(x + barWidth / 2, height - 16);
    context.rotate(-Math.PI / 6);
    context.fillStyle = "#667085";
    context.fillText(label, 0, 0);
    context.restore();
  });
}

function drawPieChart(canvas, apps) {
  const { context, width, height } = fitCanvas(canvas);
  const total = apps.reduce((sum, app) => sum + app.count, 0);
  context.fillStyle = "#ffffff";
  context.fillRect(0, 0, width, height);

  if (!apps.length || total === 0) {
    context.fillStyle = "#667085";
    context.font = "14px Segoe UI, Arial, sans-serif";
    context.fillText("No application data", 18, height / 2);
    return;
  }

  const colors = ["#126b6f", "#2d7fd3", "#8a4b12", "#c2410c", "#0f9d58", "#7c3aed", "#b42318", "#475467"];
  const radius = Math.min(width, height) * 0.28;
  const cx = width * 0.38;
  const cy = height / 2;
  let start = -Math.PI / 2;

  apps.forEach((app, index) => {
    const slice = (app.count / total) * Math.PI * 2;
    const end = start + slice;
    context.beginPath();
    context.moveTo(cx, cy);
    context.arc(cx, cy, radius, start, end);
    context.closePath();
    context.fillStyle = colors[index % colors.length];
    context.fill();
    start = end;
  });

  const legendX = Math.max(width * 0.7, cx + radius + 18);
  const legendTop = 26;
  context.font = "13px Segoe UI, Arial, sans-serif";
  context.textAlign = "left";
  apps.slice(0, 7).forEach((app, index) => {
    const y = legendTop + index * 24;
    context.fillStyle = colors[index % colors.length];
    context.fillRect(legendX, y - 10, 10, 10);
    context.fillStyle = "#344054";
    context.fillText(`${truncateLabel(app.app, 14)} ${app.percentage.toFixed(1)}%`, legendX + 16, y);
  });
}

function truncateLabel(text, maxLength) {
  return text.length > maxLength ? `${text.slice(0, maxLength - 1)}…` : text;
}

function roundRect(context, x, y, width, height, radius) {
  const corner = Math.min(radius, width / 2, height / 2);
  context.beginPath();
  context.moveTo(x + corner, y);
  context.lineTo(x + width - corner, y);
  context.quadraticCurveTo(x + width, y, x + width, y + corner);
  context.lineTo(x + width, y + height - corner);
  context.quadraticCurveTo(x + width, y + height, x + width - corner, y + height);
  context.lineTo(x + corner, y + height);
  context.quadraticCurveTo(x, y + height, x, y + height - corner);
  context.lineTo(x, y + corner);
  context.quadraticCurveTo(x, y, x + corner, y);
  context.closePath();
}

function renderTables(data) {
  const domainBody = document.querySelector("#domainsTable tbody");
  const packetBody = document.querySelector("#packetTable tbody");
  const drawDomains = () => {
    const q = document.getElementById("domainSearch").value.toLowerCase();
    domainBody.innerHTML = data.domains
      .filter((row) => `${row.hostname} ${row.app}`.toLowerCase().includes(q))
      .map((row) => `<tr><td>${row.hostname}</td><td>${row.app}</td></tr>`)
      .join("");
  };
  const drawPackets = () => {
    const q = document.getElementById("packetSearch").value.toLowerCase();
    packetBody.innerHTML = data.packets
      .filter((row) => `${row.hostname} ${row.detected_application} ${row.reason}`.toLowerCase().includes(q))
      .slice(0, 250)
      .map((row) => `<tr><td>${row.packet_number}</td><td>${row.hostname || "-"}</td><td>${row.detected_application}</td><td>${row.blocked ? "Dropped" : "Forwarded"}</td></tr>`)
      .join("");
  };
  document.getElementById("domainSearch").oninput = drawDomains;
  document.getElementById("packetSearch").oninput = drawPackets;
  document.querySelectorAll("#domainsTable th").forEach((th) => {
    th.onclick = () => {
      const key = th.dataset.sort;
      data.domains.sort((a, b) => `${a[key]}`.localeCompare(`${b[key]}`));
      drawDomains();
    };
  });
  drawDomains();
  drawPackets();
}

function renderSummary(summary) {
  document.getElementById("blockSummary").innerHTML = `
    <div><span>Blocked Application</span><strong>${summary.blocked_application}</strong></div>
    <div><span>Packets Removed</span><strong>${summary.packets_removed}</strong></div>
    <div><span>Remaining Packets</span><strong>${summary.remaining_packets}</strong></div>`;
}

function renderLogs(logs) {
  const log = document.getElementById("logWindow");
  log.textContent = logs.join("\n");
  log.scrollTop = log.scrollHeight;
}
