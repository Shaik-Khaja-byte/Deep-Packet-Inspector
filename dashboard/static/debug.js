async function loadDebug() {
  const id = localStorage.getItem("latestAnalysisId");
  const status = document.getElementById("debugStatus");
  if (!id) {
    status.textContent = "Run an analysis from the Dashboard first.";
    return;
  }
  const response = await fetch(`/api/results/${id}`);
  if (!response.ok) {
    status.textContent = "Latest analysis was not found. Run a new analysis.";
    return;
  }
  const data = await response.json();
  status.textContent = `Loaded ${data.input_file}`;
  renderPackets(data.packets);
  renderDns(data.dns);
  renderQuic(data.quic);
  renderFlows(data.flows);
}

function renderPackets(rows) {
  const tbody = document.querySelector("#debugPackets tbody");
  const filter = document.getElementById("packetFilter");
  const draw = () => {
    const q = filter.value.toLowerCase();
    tbody.innerHTML = rows
      .filter((row) => JSON.stringify(row).toLowerCase().includes(q))
      .slice(0, 1000)
      .map((row) => `
        <tr>
          <td>${row.packet_number}</td>
          <td>${row.protocol}</td>
          <td>${row.hostname || "-"}</td>
          <td>${row.sni}</td>
          <td>${row.detected_application}</td>
          <td>${pill(row.blocked)}</td>
          <td>${row.reason}</td>
        </tr>`)
      .join("");
  };
  filter.oninput = draw;
  draw();
}

function renderDns(rows) {
  document.querySelector("#dnsTable tbody").innerHTML = rows
    .map((row) => `<tr><td>${row.hostname}</td><td>${row.type}</td><td>${pill(row.blocked)}</td><td>${row.reason}</td></tr>`)
    .join("");
}

function renderQuic(rows) {
  document.querySelector("#quicTable tbody").innerHTML = rows
    .map((row) => `<tr><td>${row.packet_number}</td><td>${row.hostname}</td><td>${pill(row.blocked)}</td><td>${row.flow_id}</td></tr>`)
    .join("");
}

function renderFlows(rows) {
  document.querySelector("#flowTable tbody").innerHTML = rows
    .map((row) => `<tr><td>${row.flow_id}</td><td>${row.client}</td><td>${row.server}</td><td>${row.application}</td><td>${pill(row.blocked)}</td><td>${row.packet_count}</td><td>${row.reason}</td></tr>`)
    .join("");
}

function pill(value) {
  return value ? '<span class="pill bad">YES</span>' : '<span class="pill ok">NO</span>';
}

loadDebug();
