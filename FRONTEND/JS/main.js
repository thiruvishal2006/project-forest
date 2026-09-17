const form = document.getElementById("device-form");
const resultsBody = document.getElementById("results-body");
const statusPill = document.getElementById("status-pill");
const detailPanel = document.getElementById("detail-panel");
const detailJson = document.getElementById("detail-json");

function setStatus(text, mode = "idle") {
  statusPill.textContent = text;
  statusPill.className = `pill pill--${mode}`;
}

function riskClass(score) {
  if (score >= 70) return "risk-high";
  if (score >= 30) return "risk-medium";
  return "risk-low";
}

function renderRow(device) {
  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td>${device.deviceName}</td>
    <td>${device.vendorId}:${device.productId}</td>
    <td class="${riskClass(device.riskScore)}">${device.riskScore}</td>
    <td>${device.verdict}</td>
    <td>${new Date(device.scannedAt).toLocaleString()}</td>
  `;
  tr.addEventListener("click", () => showDetail(device.id));
  resultsBody.prepend(tr);
}

async function showDetail(id) {
  try {
    const report = await fetchDeviceReport(id);
    detailPanel.hidden = false;
    detailJson.textContent = JSON.stringify(report, null, 2);
  } catch (err) {
    console.error(err);
  }
}

async function loadExistingDevices() {
  try {
    const devices = await fetchAllDevices();
    devices.forEach(renderRow);
  } catch (err) {
    console.error("Could not load devices:", err);
  }
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  setStatus("Analyzing…", "busy");

  const payload = {
    deviceName: document.getElementById("deviceName").value.trim(),
    vendorId: document.getElementById("vendorId").value.trim(),
    productId: document.getElementById("productId").value.trim(),
    serial: document.getElementById("serial").value.trim()
  };

  try {
    const result = await analyzeDevice(payload);
    renderRow(result);
    setStatus("Idle", "idle");
    form.reset();
  } catch (err) {
    console.error(err);
    setStatus("Error", "error");
  }
});

loadExistingDevices();
