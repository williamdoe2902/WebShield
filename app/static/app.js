const form = document.querySelector("#scan-form");
const scanList = document.querySelector("#scan-list");
const message = document.querySelector("#form-message");
const button = document.querySelector("#scan-button");
const monitorForm = document.querySelector("#monitor-form");
const monitorList = document.querySelector("#monitor-list");
const monitorMessage = document.querySelector("#monitor-message");
const monitorButton = document.querySelector("#monitor-button");

function makeCell(value, className = "") {
  const cell = document.createElement("td");
  cell.textContent = value;
  if (className) cell.className = className;
  return cell;
}

function renderScan(scan) {
  document.querySelector(".empty-row")?.remove();
  let row = scanList.querySelector(`[data-id="${CSS.escape(scan.id)}"]`);
  if (!row) {
    row = document.createElement("tr");
    row.dataset.id = scan.id;
    scanList.prepend(row);
  }
  row.replaceChildren();
  row.append(makeCell(scan.target, "target-cell"));
  row.append(makeCell((scan.created_at || "").slice(0, 16).replace("T", " ")));
  const pageCount = scan.status === "running" ? `${scan.pages_scanned || 0} / ${scan.pages_visited || 0}` : String(scan.pages_scanned || 0);
  row.append(makeCell(pageCount));
  row.append(makeCell(String((scan.findings || []).length)));
  const status = document.createElement("td");
  const badge = document.createElement("span");
  badge.className = `state state-${scan.status}`;
  badge.textContent = scan.status;
  status.append(badge);
  row.append(status);
  const action = document.createElement("td");
  if (scan.status === "complete") {
    const link = document.createElement("a");
    link.className = "report-link";
    link.href = `/reports/${encodeURIComponent(scan.id)}`;
    link.target = "_blank";
    link.rel = "noopener";
    link.textContent = "Report ↗";
    action.append(link);
  }
  row.append(action);
  document.querySelector("#scan-count").textContent = `${scanList.querySelectorAll("tr[data-id]").length} RECORDS`;
}

function renderMonitors(monitors) {
  monitorList.replaceChildren();
  if (!monitors.length) {
    const row = document.createElement("tr");
    row.className = "empty-row";
    const cell = makeCell("");
    cell.colSpan = 6;
    const title = document.createElement("span");
    title.textContent = "No monitors configured";
    const hint = document.createElement("small");
    hint.textContent = "Add an authorized local app above.";
    cell.append(title, hint);
    row.append(cell);
    monitorList.append(row);
    return;
  }
  for (const monitor of monitors) {
    const row = document.createElement("tr");
    row.dataset.id = monitor.id;
    row.append(makeCell(monitor.target, "target-cell"));
    row.append(makeCell((monitor.last_checked_at || "Not checked").slice(0, 16).replace("T", " ")));
    row.append(makeCell(String(monitor.finding_count || 0)));
    const status = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `state state-${monitor.status}`;
    badge.textContent = monitor.status;
    status.append(badge);
    row.append(status);
    const alert = monitor.new_findings?.length
      ? `${monitor.new_findings.length} new finding${monitor.new_findings.length === 1 ? "" : "s"}`
      : "No new findings";
    row.append(makeCell(alert));
    const action = document.createElement("td");
    const remove = document.createElement("button");
    remove.className = "report-link";
    remove.type = "button";
    remove.dataset.removeMonitor = monitor.id;
    remove.textContent = "Remove";
    action.append(remove);
    row.append(action);
    monitorList.append(row);
  }
}

async function refreshMonitors() {
  const response = await fetch("/api/monitors");
  if (!response.ok) throw new Error("Unable to load local monitors.");
  renderMonitors(await response.json());
}

async function watchScan(id) {
  while (true) {
    const response = await fetch(`/api/scans/${encodeURIComponent(id)}`);
    const scan = await response.json();
    renderScan(scan);
    if (["complete", "failed"].includes(scan.status)) {
      message.textContent = scan.status === "complete" ? "Scan complete. Open the report from Recent scans." : `Scan failed: ${scan.error || "request could not be completed"}`;
      button.disabled = false;
      button.innerHTML = "<span aria-hidden=\"true\">▶</span> Start scan";
      return;
    }
    await new Promise((resolve) => window.setTimeout(resolve, 900));
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  message.textContent = "Validating local target…";
  button.disabled = true;
  button.textContent = "Starting…";
  try {
    const response = await fetch("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target: document.querySelector("#target").value,
        authorized: document.querySelector("#authorized").checked,
      }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail || "Unable to start scan.");
    message.textContent = "Scan queued. Checking progress…";
    await watchScan(result.id);
  } catch (error) {
    message.textContent = error.message;
    button.disabled = false;
    button.innerHTML = "<span aria-hidden=\"true\">▶</span> Start scan";
  }
});

monitorForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  monitorMessage.textContent = "Validating local target…";
  monitorButton.disabled = true;
  try {
    const response = await fetch("/api/monitors", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target: document.querySelector("#monitor-target").value,
        authorized: document.querySelector("#monitor-authorized").checked,
      }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail || "Unable to add monitor.");
    monitorMessage.textContent = "Monitor added. The initial local scan has started.";
    await refreshMonitors();
  } catch (error) {
    monitorMessage.textContent = error.message;
  } finally {
    monitorButton.disabled = false;
  }
});

monitorList.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-remove-monitor]");
  if (!button) return;
  try {
    const response = await fetch(`/api/monitors/${encodeURIComponent(button.dataset.removeMonitor)}`, {
      method: "DELETE",
    });
    if (!response.ok) {
      const result = await response.json();
      throw new Error(result.detail || "Unable to remove monitor.");
    }
    await refreshMonitors();
  } catch (error) {
    monitorMessage.textContent = error.message;
  }
});

window.setInterval(async () => {
  try {
    const response = await fetch("/api/scans");
    if (response.ok) (await response.json()).forEach(renderScan);
  } catch {
    message.textContent = "Could not refresh recent scans.";
  }
}, 5000);

window.setInterval(() => {
  refreshMonitors().catch((error) => {
    monitorMessage.textContent = error.message;
  });
}, 5000);

refreshMonitors().catch((error) => {
  monitorMessage.textContent = error.message;
});