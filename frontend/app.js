const state = { apiUrl: localStorage.getItem("cybersec_api_url") || "http://localhost:8000", operator: localStorage.getItem("cybersec_operator") || "" };
const $ = (selector) => document.querySelector(selector);

function escapeHtml(value = "") { return String(value).replace(/[&<>'"]/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[char])); }
function shortId(id) { return id ? `${id.slice(0, 8)}…` : "—"; }
function date(value) { return value ? new Date(value).toLocaleString() : "—"; }
function tag(value) { return `<span class="tag ${escapeHtml(value || "")}">${escapeHtml(value || "—")}</span>`; }
function toast(message, type = "success") { const box = $("#toast"); box.textContent = message; box.className = `toast ${type}`; setTimeout(() => box.className = "toast hidden", 4500); }
function setConnection(text, type = "neutral") { const element = $("#connection-status"); element.textContent = text; element.className = `status ${type}`; }
async function api(path, options = {}) {
  if (!state.apiUrl) throw new Error("Enter the API endpoint first.");
  const response = await fetch(`${state.apiUrl.replace(/\/$/, "")}${path}`, { headers: { "Content-Type": "application/json", ...(options.headers || {}) }, ...options });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail || data));
  return data;
}
function showView(view) { document.querySelectorAll(".view").forEach((item) => item.classList.toggle("active", item.id === view)); document.querySelectorAll(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === view)); $("#page-title").textContent = ({terminal:"Audit command terminal",dashboard:"Command dashboard",findings:"Analyze finding",decisions:"Decision register",reviews:"Human reviews",audits:"Audit plans"})[view]; if (view === "dashboard") loadDashboard(); if (view === "decisions") loadDecisions(); if (view === "reviews") loadReviews(); if (view === "terminal") $("#terminal-command").focus(); }
function renderDecisionRows(items, target) { target.innerHTML = items.length ? items.map((item) => `<tr><td title="${escapeHtml(item.id)}">${shortId(item.id)}</td><td>${tag(item.final_decision)}</td><td>${tag(item.severity_assessed)}</td><td>${item.confidence_score ?? "—"}</td><td>${date(item.created_at)}</td></tr>`).join("") : `<tr><td colspan="5" class="empty">No records found.</td></tr>`; }
async function loadDashboard() {
  try { const [health, decisions, findings, reviews, usage] = await Promise.all([api("/health"), api("/api/v1/decisions/?limit=5"), api("/api/v1/findings/?limit=5"), api("/api/v1/audit/reviews?limit=5"), api("/api/v1/decisions/usage")]);
    setConnection("● Connected", "good"); $("#health-status").textContent = `● ${health.status}`; $("#health-status").style.color = health.status === "healthy" ? "var(--green)" : "var(--yellow)"; $("#health-details").innerHTML = `<dt>Database</dt><dd>${escapeHtml(health.database)}</dd><dt>LLM provider</dt><dd>${escapeHtml(health.llm_provider)}</dd><dt>Environment</dt><dd>${escapeHtml(health.environment)}</dd>`;
    $("#metric-tokens").textContent = Number(usage.total_tokens).toLocaleString(); $("#metric-decisions").textContent = Number(usage.analyzed_decisions).toLocaleString(); $("#metric-findings").textContent = findings.length; $("#metric-reviews").textContent = reviews.length;
    $("#terminal-output").innerHTML = `$ cybersec-agent dashboard\n<span class="muted">API</span>      ${escapeHtml(health.status)}\n<span class="muted">DATABASE</span> ${escapeHtml(health.database)}\n<span class="muted">TOKENS</span>   ${Number(usage.total_tokens).toLocaleString()} total\n<span class="muted">READY</span>    submit or review an audit finding`;
    renderDecisionRows(decisions, $("#dashboard-decisions"));
  } catch (error) { setConnection("● Connection failed", "bad"); $("#terminal-output").textContent = `$ connection error\n${error.message}`; }
}
async function loadDecisions() { try { const decisions = await api("/api/v1/decisions/?limit=50"); $("#decisions-table").innerHTML = decisions.length ? decisions.map((item) => `<tr><td title="${escapeHtml(item.id)}">${shortId(item.id)}</td><td>${tag(item.final_decision)}</td><td>${tag(item.severity_assessed)}</td><td>${item.confidence_score ?? "—"}</td><td>${item.total_tokens ?? 0}</td><td><button class="text-button" data-decision="${item.id}">Inspect →</button></td></tr>`).join("") : `<tr><td colspan="6" class="empty">No decisions yet.</td></tr>`; } catch (error) { toast(error.message, "error"); } }
async function showDecision(id) { try { const item = await api(`/api/v1/decisions/${id}`); const detail = $("#decision-detail"); detail.classList.remove("hidden"); detail.innerHTML = `<div class="section-heading"><div><p class="eyebrow">AUDITABLE DECISION</p><h2>${tag(item.final_decision)} ${tag(item.severity_assessed)}</h2></div></div><dl class="detail-grid"><dt>Decision ID</dt><dd>${escapeHtml(item.id)}</dd><dt>Confidence</dt><dd>${item.confidence_score ?? "—"}</dd><dt>Token usage</dt><dd>${item.total_tokens || 0} total · ${item.prompt_tokens || 0} input · ${item.completion_tokens || 0} output</dd><dt>Analysis</dt><dd>${escapeHtml(item.analysis_summary)}</dd><dt>Suggested action</dt><dd>${escapeHtml(item.suggested_action || "—")}</dd></dl>`; detail.scrollIntoView({behavior:"smooth"}); } catch (error) { toast(error.message, "error"); } }
async function loadReviews() { try { const reviews = await api("/api/v1/audit/reviews?limit=50"); $("#reviews-table").innerHTML = reviews.length ? reviews.map((item) => `<tr><td>${escapeHtml(item.reviewed_by || "—")}</td><td>${tag(item.review_verdict)}</td><td>${escapeHtml(item.review_comment || "—")}</td><td>${date(item.reviewed_at)}</td></tr>`).join("") : `<tr><td colspan="4" class="empty">No reviews recorded yet.</td></tr>`; } catch (error) { toast(error.message, "error"); } }
function renderResult(target, data, title) { target.classList.remove("hidden"); target.innerHTML = `<p class="eyebrow">${title}</p><dl class="detail-grid">${Object.entries(data).filter(([key]) => !["prompt_used","finding","raw_response"].includes(key)).map(([key,value]) => `<dt>${escapeHtml(key.replaceAll("_", " "))}</dt><dd>${escapeHtml(typeof value === "object" ? JSON.stringify(value) : value)}</dd>`).join("")}</dl>`; target.scrollIntoView({behavior:"smooth"}); }

function terminalWrite(text, kind = "success") { const item = document.createElement("pre"); item.className = `terminal-entry ${kind}`; item.textContent = text; $("#web-terminal-output").append(item); $("#web-terminal-output").scrollTop = $("#web-terminal-output").scrollHeight; return item; }
function resetTerminal() { $("#web-terminal-output").innerHTML = ""; $("#terminal-prompt").textContent = `${state.operator || "operator"}@cybersec:~$`; terminalWrite("CYBERSEC AGENT WEB CLI\nType help to list available audit operations.\nOnly use authorized targets.", "muted"); }
function splitCommand(input) { const parts = []; let current = ""; let quote = null; for (const char of input.trim()) { if ((char === "'" || char === '"') && !quote) { quote = char; continue; } if (char === quote) { quote = null; continue; } if (/\s/.test(char) && !quote) { if (current) { parts.push(current); current = ""; } } else current += char; } if (quote) throw new Error("Unclosed quote in command."); if (current) parts.push(current); return parts; }
function optionsFrom(tokens) { const options = {}; for (let index = 0; index < tokens.length; index += 1) { if (!tokens[index].startsWith("--")) continue; const key = tokens[index].slice(2); options[key] = tokens[index + 1] && !tokens[index + 1].startsWith("--") ? tokens[++index] : true; } return options; }
function terminalHelp() { return `Available commands:
  dashboard
  usage
  decisions list | decisions get <decision-id>
  findings list
  findings analyze --source sonarqube|zap --payload '{"rule":"..."}'
  reviews list
  audit review <decision-id> --by <name> --verdict agree|disagree|escalate --comment "text"
  audits plan <target> --type sast|dast|full [--authorize-dast]
  audits trace <audit-id>
  clear`; }
function summary(items, fields) { return items.length ? items.map((item) => fields.map((field) => `${field}: ${item[field] ?? "—"}`).join(" | ")).join("\n") : "No records found."; }
async function executeTerminal(input) {
  const command = input.trim(); if (!command) return; terminalWrite(`${state.operator || "operator"}@cybersec:~$ ${command}`, "command");
  let loading; try { const parts = splitCommand(command); const options = optionsFrom(parts); loading = terminalWrite("⠋ Executing API operation…", "muted"); let output;
    if (parts[0] === "help") output = terminalHelp();
    else if (parts[0] === "clear") { resetTerminal(); return; }
    else if (parts[0] === "dashboard") { const [health, usage] = await Promise.all([api("/health"), api("/api/v1/decisions/usage")]); output = `API: ${health.status}\nDATABASE: ${health.database}\nLLM: ${health.llm_provider}\nTOKENS: ${usage.total_tokens} total (${usage.prompt_tokens} input / ${usage.completion_tokens} output)`; loadDashboard(); }
    else if (parts[0] === "usage") { const usage = await api("/api/v1/decisions/usage"); output = `ANALYSES: ${usage.analyzed_decisions}\nTOTAL TOKENS: ${usage.total_tokens}\nINPUT TOKENS: ${usage.prompt_tokens}\nOUTPUT TOKENS: ${usage.completion_tokens}`; }
    else if (parts[0] === "decisions" && parts[1] === "list") { const data = await api("/api/v1/decisions/?limit=50"); output = summary(data, ["id", "final_decision", "severity_assessed", "confidence_score", "total_tokens"]); }
    else if (parts[0] === "decisions" && parts[1] === "get" && parts[2]) { const data = await api(`/api/v1/decisions/${parts[2]}`); output = JSON.stringify(data, null, 2); }
    else if (parts[0] === "findings" && parts[1] === "list") { const data = await api("/api/v1/findings/?limit=50"); output = summary(data, ["id", "source", "created_at"]); }
    else if (parts[0] === "findings" && parts[1] === "analyze" && options.source && options.payload) { const data = await api("/api/v1/findings/analyze", {method:"POST",body:JSON.stringify({source:options.source,raw_payload:JSON.parse(options.payload)})}); output = JSON.stringify(data, null, 2); loadDashboard(); }
    else if ((parts[0] === "reviews" && parts[1] === "list") || (parts[0] === "audit" && parts[1] === "list")) { const data = await api("/api/v1/audit/reviews?limit=50"); output = summary(data, ["id", "reviewed_by", "review_verdict", "reviewed_at"]); }
    else if (parts[0] === "audit" && parts[1] === "review" && parts[2] && options.by && options.verdict) { const data = await api("/api/v1/audit/review", {method:"POST",body:JSON.stringify({decision_id:parts[2],reviewed_by:options.by,review_verdict:options.verdict,review_comment:options.comment || null})}); output = JSON.stringify(data, null, 2); }
    else if (parts[0] === "audits" && parts[1] === "plan" && parts[2] && options.type) { const data = await api("/api/v1/audits/plan", {method:"POST",body:JSON.stringify({target:parts[2],scan_type:options.type,dast_authorized:Boolean(options["authorize-dast"])})}); output = JSON.stringify(data, null, 2); }
    else if (parts[0] === "audits" && parts[1] === "trace" && parts[2]) { const data = await api(`/api/v1/audits/${parts[2]}/trace`); output = JSON.stringify(data, null, 2); }
    else throw new Error("Unknown command. Type help for supported operations.");
    loading.remove(); terminalWrite(output, "success");
  } catch (error) { loading?.remove(); terminalWrite(`✗ ${error.message}`, "error"); }
}

$("#api-url").value = state.apiUrl;
$("#landing-api-url").value = state.apiUrl;
$("#operator-name").value = state.operator;
$("#operator-display").textContent = state.operator || "—";
function enterWorkspace() { document.body.classList.add("workspace"); $("#operator-display").textContent = state.operator; resetTerminal(); showView("terminal"); }
function showLanding() { document.body.classList.remove("workspace"); }
$("#workspace-form").addEventListener("submit", (event) => { event.preventDefault(); state.operator = $("#operator-name").value.trim(); state.apiUrl = $("#landing-api-url").value.trim().replace(/\/$/, ""); localStorage.setItem("cybersec_operator", state.operator); localStorage.setItem("cybersec_api_url", state.apiUrl); $("#api-url").value = state.apiUrl; enterWorkspace(); });
$("#switch-workspace").addEventListener("click", showLanding);
document.querySelectorAll(".nav-item").forEach((item) => item.addEventListener("click", () => showView(item.dataset.view)));
document.querySelectorAll("[data-go]").forEach((item) => item.addEventListener("click", () => showView(item.dataset.go)));
$("#connect-button").addEventListener("click", () => { state.apiUrl = $("#api-url").value.trim().replace(/\/$/, ""); localStorage.setItem("cybersec_api_url", state.apiUrl); loadDashboard(); });
$("#refresh-button").addEventListener("click", () => showView(document.querySelector(".view.active").id));
$("#load-decisions").addEventListener("click", loadDecisions); $("#load-reviews").addEventListener("click", loadReviews);
$("#terminal-form").addEventListener("submit", (event) => { event.preventDefault(); const input = $("#terminal-command"); executeTerminal(input.value); input.value = ""; });
$("#clear-terminal").addEventListener("click", resetTerminal);
document.querySelectorAll("[data-command]").forEach((button) => button.addEventListener("click", () => { $("#terminal-command").value = button.dataset.command; $("#terminal-command").focus(); }));
$("#decisions-table").addEventListener("click", (event) => { const id = event.target.dataset.decision; if (id) showDecision(id); });
$("#finding-form").addEventListener("submit", async (event) => { event.preventDefault(); const form = new FormData(event.currentTarget); try { const raw_payload = JSON.parse(form.get("raw_payload")); const result = await api("/api/v1/findings/analyze", {method:"POST",body:JSON.stringify({source:form.get("source"),raw_payload})}); renderResult($("#analysis-result"), result, "OPENAI ANALYSIS COMPLETE"); toast("Finding analyzed and decision recorded."); loadDashboard(); } catch (error) { toast(error instanceof SyntaxError ? "Finding JSON is invalid." : error.message, "error"); } });
$("#review-form").addEventListener("submit", async (event) => { event.preventDefault(); const form = new FormData(event.currentTarget); try { await api("/api/v1/audit/review", {method:"POST",body:JSON.stringify(Object.fromEntries(form))}); toast("Human review recorded."); event.currentTarget.reset(); loadReviews(); } catch (error) { toast(error.message, "error"); } });
$("#audit-form").addEventListener("submit", async (event) => { event.preventDefault(); const form = new FormData(event.currentTarget); try { const result = await api("/api/v1/audits/plan", {method:"POST",body:JSON.stringify({target:form.get("target"),scan_type:form.get("scan_type"),dast_authorized:form.get("dast_authorized") === "on"})}); renderResult($("#audit-result"), result, "AUDIT PLAN CREATED"); toast("Audit plan created."); } catch (error) { toast(error.message, "error"); } });
