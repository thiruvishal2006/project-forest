const API_BASE = "http://localhost:5000/api"; // adjust to match backend

async function analyzeDevice(payload) {
  const res = await fetch(`${API_BASE}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (!res.ok) throw new Error(`Analyze failed: ${res.status}`);
  return res.json();
}

async function fetchAllDevices() {
  const res = await fetch(`${API_BASE}/devices`);
  if (!res.ok) throw new Error(`Fetch devices failed: ${res.status}`);
  return res.json();
}

async function fetchDeviceReport(id) {
  const res = await fetch(`${API_BASE}/reports/${id}`);
  if (!res.ok) throw new Error(`Fetch report failed: ${res.status}`);
  return res.json();
}
