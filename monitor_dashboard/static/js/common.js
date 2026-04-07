let zeekEvents = [];
let alertEvents = [];
let machineStates = {};
let lastShownAlertId = 0;
let uiWs = null;

function pageName() {
  const path = location.pathname.split("/").pop();
  return path || "index.html";
}

function sidebar(active) {
  return `
  <div class="sidebar">
    <h2>Dashboard</h2>
    <a href="/logs.html"><button class="menu-btn ${active==='logs'?'active':''}">Nhật ký  </button></a>
    <a href="/charts.html"><button class="menu-btn ${active==='charts'?'active':''}">Phân tích</button></a>
    <a href="/alerts.html"><button class="menu-btn ${active==='alerts'?'active':''}">Cảnh báo</button></a>
    <a href="/monitor.html"><button class="menu-btn ${active==='monitor'?'active':''}">Theo dõi thiết bị</button></a>
    <a href="/guide.html"><button class="menu-btn ${active==='guide'?'active':''}">Hướng dẫn cài đặt</button></a>
  </div>`;
}

function layout(active, innerHtml) {
  document.body.innerHTML = `
    ${sidebar(active)}
    <div class="main">
      ${innerHtml}
    </div>
    <div id="alert-popup"></div>
  `;
}

function formatTimestamp(ts) {
  const num = Number(ts);
  if (Number.isNaN(num)) return ts;
  const d = new Date(num * 1000);
  if (isNaN(d.getTime())) return ts;

  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  const ms = String(d.getMilliseconds()).padStart(3, "0");
  return `${dd}/${mm}/${yyyy} ${hh}:${mi}:${ss}.${ms}`;
}

function formatSecondLabel(sec) {
  const d = new Date(Number(sec) * 1000);
  if (isNaN(d.getTime())) return sec;
  return d.toLocaleTimeString();
}

function parseUpdatedTime(updatedAt) {
  if (!updatedAt) return null;
  const t = new Date(updatedAt.replace(" ", "T"));
  if (isNaN(t.getTime())) return null;
  return t;
}

async function initialLoadCommon() {
  const [eventsRes, alertsRes, machinesRes] = await Promise.all([
    fetch("/zeek-events"),
    fetch("/alerts"),
    fetch("/machines")
  ]);

  zeekEvents = await eventsRes.json();
  alertEvents = await alertsRes.json();

  const machineArr = await machinesRes.json();
  machineStates = {};
  machineArr.forEach(m => {
    machineStates[m.machine_id] = m;
  });
}

function showRedPopup(alert) {
  const enabled = document.getElementById("enable-popup");
  if (enabled && !enabled.checked) return;

  const box = document.getElementById("alert-popup");
  if (!box) return;

  box.innerHTML = `
    <div style="font-weight:bold;font-size:18px;margin-bottom:8px;">CẢNH BÁO AI</div>
    <div><b>Machine ID:</b> ${alert.machine_id || "-"}</div>
    <div><b>Thời gian:</b> ${formatTimestamp(alert.timestamp)}</div>
    <div><b>Flow:</b> ${alert.src_ip}:${alert.src_port} -> ${alert.dest_ip}:${alert.dest_port}</div>
    <div><b>Proto:</b> ${alert.proto}</div>
    <div><b>Service:</b> ${alert.service}</div>
    <div><b>State:</b> ${alert.conn_state}</div>
    <div><b>Packets:</b> ${Number(alert.orig_pkts || 0) + Number(alert.resp_pkts || 0)}</div>
    <div><b>Bytes:</b> ${Number(alert.orig_bytes || 0) + Number(alert.resp_bytes || 0)}</div>
    <div><b>Confidence:</b> ${Number(alert.confidence).toFixed(6)}</div>
    <div><b>Threshold:</b> ${alert.threshold}</div>
    <div><b>Prediction:</b> ${alert.prediction}</div>
  `;
  box.style.display = "block";
  setTimeout(() => { box.style.display = "none"; }, 6000);
}

function connectUIWebSocket(onUpdate) {
  const wsProtocol = location.protocol === "https:" ? "wss" : "ws";
  uiWs = new WebSocket(`${wsProtocol}://${location.host}/ws/ui`);

  uiWs.onopen = () => {
    setInterval(() => {
      if (uiWs && uiWs.readyState === WebSocket.OPEN) uiWs.send("ping");
    }, 15000);
  };

  uiWs.onmessage = (event) => {
    const msg = JSON.parse(event.data);

    if (msg.type === "system_info") {
      const m = msg.data;
      machineStates[m.machine_id] = m;
      if (onUpdate) onUpdate("system_info", m);
    } else if (msg.type === "zeek_event") {
      zeekEvents.unshift(msg.data);
      if (onUpdate) onUpdate("zeek_event", msg.data);
    } else if (msg.type === "alert_event") {
      alertEvents.unshift(msg.data);
      if (onUpdate) onUpdate("alert_event", msg.data);
    }
  };

  uiWs.onclose = () => {
    setTimeout(() => connectUIWebSocket(onUpdate), 1000);
  };
}