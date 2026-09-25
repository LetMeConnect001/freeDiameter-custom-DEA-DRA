const API = "/api";

let editingId = null;

const el = (id) => document.getElementById(id);

function splitPath(text) {
	return text.split(":").map((s) => s.trim()).filter((s) => s.length > 0);
}

function joinPath(path) {
	return (path || []).join(" : ");
}

async function api(path, options) {
	const res = await fetch(API + path, {
		headers: { "Content-Type": "application/json" },
		...options,
	});
	const body = await res.json().catch(() => null);
	if (!res.ok) {
		const detail = body && body.detail ? body.detail : res.statusText;
		throw new Error(detail);
	}
	return body;
}

function showStatus(message, kind) {
	const bar = el("statusBar");
	bar.textContent = message;
	bar.hidden = false;
	bar.className = "status-bar " + kind;
	if (kind === "ok") {
		setTimeout(() => { bar.hidden = true; }, 4000);
	}
}

function typeLabel(type) {
	return { move: "Déplacer", delete: "Supprimer", add: "Ajouter" }[type] || type;
}

function ruleSummary(rule) {
	if (rule.type === "move") {
		return `${joinPath(rule.source_avp_path)} → ${joinPath(rule.dest_avp_path)}`;
	}
	if (rule.type === "delete") {
		return joinPath(rule.source_avp_path);
	}
	if (rule.type === "add") {
		return `[${rule.command_name}] ${joinPath(rule.dest_avp_path)} = "${rule.value}"`;
	}
	return "";
}

function conditionSummary(rule) {
	if (!rule.condition) return "—";
	return `${joinPath(rule.condition.variable_avp_path)} ${rule.condition.operator} "${rule.condition.value}"`;
}

async function loadRules() {
	const rules = await api("/rules");
	const tbody = el("ruleTableBody");
	tbody.innerHTML = "";

	for (const rule of rules) {
		const tr = document.createElement("tr");

		const badgeClass = rule.enabled ? `badge-${rule.type}` : "badge-off";
		tr.innerHTML = `
			<td><span class="badge ${badgeClass}">${rule.enabled ? "on" : "off"}</span></td>
			<td>${escapeHtml(rule.name)}</td>
			<td>${typeLabel(rule.type)}</td>
			<td><code>${escapeHtml(ruleSummary(rule))}</code></td>
			<td><code>${escapeHtml(conditionSummary(rule))}</code></td>
			<td>
				<button class="btn-icon" data-action="edit" data-id="${rule.id}">Éditer</button>
				<button class="btn-danger" data-action="delete" data-id="${rule.id}">Suppr.</button>
			</td>
		`;
		tbody.appendChild(tr);
	}

	tbody.querySelectorAll("[data-action=edit]").forEach((btn) => {
		btn.addEventListener("click", () => editRule(parseInt(btn.dataset.id, 10)));
	});
	tbody.querySelectorAll("[data-action=delete]").forEach((btn) => {
		btn.addEventListener("click", () => deleteRule(parseInt(btn.dataset.id, 10)));
	});

	await refreshPreview();
}

function escapeHtml(s) {
	const d = document.createElement("div");
	d.textContent = s == null ? "" : String(s);
	return d.innerHTML;
}

async function refreshPreview() {
	try {
		const { config } = await api("/preview");
		el("previewText").textContent = config || "(aucune règle active)";
	} catch (e) {
		el("previewText").textContent = "Erreur de génération: " + e.message;
	}
}

function showTypeFields() {
	const type = el("f_type").value;
	el("fields_move").hidden = type !== "move";
	el("fields_delete").hidden = type !== "delete";
	el("fields_add").hidden = type !== "add";
}

function resetForm() {
	editingId = null;
	el("formTitle").textContent = "Nouvelle règle";
	el("ruleForm").reset();
	el("f_hasCondition").checked = false;
	el("conditionFields").hidden = true;
	showTypeFields();
}

function fillForm(rule) {
	editingId = rule.id;
	el("formTitle").textContent = "Éditer la règle";
	el("f_name").value = rule.name;
	el("f_type").value = rule.type;
	el("f_enabled").checked = rule.enabled;

	el("f_source_move").value = "";
	el("f_dest_move").value = "";
	el("f_source_delete").value = "";
	el("f_command").value = "";
	el("f_dest_add").value = "";
	el("f_value").value = "";

	if (rule.type === "move") {
		el("f_source_move").value = joinPath(rule.source_avp_path);
		el("f_dest_move").value = joinPath(rule.dest_avp_path);
	} else if (rule.type === "delete") {
		el("f_source_delete").value = joinPath(rule.source_avp_path);
	} else if (rule.type === "add") {
		el("f_command").value = rule.command_name || "";
		el("f_dest_add").value = joinPath(rule.dest_avp_path);
		el("f_value").value = rule.value || "";
	}

	const hasCond = !!rule.condition;
	el("f_hasCondition").checked = hasCond;
	el("conditionFields").hidden = !hasCond;
	if (hasCond) {
		el("f_cond_avp").value = joinPath(rule.condition.variable_avp_path);
		el("f_cond_op").value = rule.condition.operator;
		el("f_cond_value").value = rule.condition.value;
	}

	showTypeFields();
	el("formSection").hidden = false;
	el("formSection").scrollIntoView({ behavior: "smooth" });
}

async function editRule(id) {
	const rule = await api(`/rules/${id}`);
	fillForm(rule);
}

async function deleteRule(id) {
	if (!confirm("Supprimer cette règle ?")) return;
	try {
		await api(`/rules/${id}`, { method: "DELETE" });
		showStatus("Règle supprimée.", "ok");
		await loadRules();
	} catch (e) {
		showStatus("Erreur: " + e.message, "error");
	}
}

function buildRuleFromForm() {
	const type = el("f_type").value;
	const rule = {
		name: el("f_name").value,
		type,
		enabled: el("f_enabled").checked,
		source_avp_path: null,
		dest_avp_path: null,
		command_name: null,
		value: null,
		condition: null,
	};

	if (type === "move") {
		rule.source_avp_path = splitPath(el("f_source_move").value);
		rule.dest_avp_path = splitPath(el("f_dest_move").value);
	} else if (type === "delete") {
		rule.source_avp_path = splitPath(el("f_source_delete").value);
	} else if (type === "add") {
		rule.command_name = el("f_command").value;
		rule.dest_avp_path = splitPath(el("f_dest_add").value);
		rule.value = el("f_value").value;
	}

	if (el("f_hasCondition").checked) {
		rule.condition = {
			variable_avp_path: splitPath(el("f_cond_avp").value),
			operator: el("f_cond_op").value,
			value: el("f_cond_value").value,
		};
	}

	return rule;
}

async function saveRule(e) {
	e.preventDefault();
	const rule = buildRuleFromForm();
	try {
		if (editingId) {
			await api(`/rules/${editingId}`, { method: "PUT", body: JSON.stringify(rule) });
		} else {
			await api("/rules", { method: "POST", body: JSON.stringify(rule) });
		}
		showStatus("Règle enregistrée.", "ok");
		el("formSection").hidden = true;
		resetForm();
		await loadRules();
	} catch (err) {
		showStatus("Erreur: " + err.message, "error");
	}
}

async function applyRules() {
	if (!confirm("Écrire la config et recharger freeDiameter maintenant ?")) return;
	try {
		const result = await api("/apply", { method: "POST" });
		showStatus(`Appliqué et rechargé (pid ${result.pid}, fichier ${result.conf_path}).`, "ok");
	} catch (e) {
		showStatus("Échec de l'application: " + e.message, "error");
	}
}

async function backupRules() {
	try {
		const result = await api("/backup/rt_rewrite", { method: "POST" });
		showStatus(`Sauvegardé : ${result.backup_path || "(rien à sauvegarder, fichier inexistant)"}`, "ok");
	} catch (e) {
		showStatus("Échec de la sauvegarde: " + e.message, "error");
	}
}

el("newRuleBtn").addEventListener("click", () => {
	resetForm();
	el("formSection").hidden = false;
	el("formSection").scrollIntoView({ behavior: "smooth" });
});
el("cancelBtn").addEventListener("click", () => {
	el("formSection").hidden = true;
});
el("f_type").addEventListener("change", showTypeFields);
el("f_hasCondition").addEventListener("change", () => {
	el("conditionFields").hidden = !el("f_hasCondition").checked;
});
el("ruleForm").addEventListener("submit", saveRule);
el("applyBtn").addEventListener("click", applyRules);
el("backupRulesBtn").addEventListener("click", backupRules);

/* ------------------------------------------------------------------ */
/* Tabs                                                                 */
/* ------------------------------------------------------------------ */

function switchTab(tab) {
	document.querySelectorAll(".tab-btn").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
	el("tab-rules").hidden = tab !== "rules";
	el("tab-peers").hidden = tab !== "peers";
	el("applyBtn").hidden = tab !== "rules";
	el("applyDaemonBtn").hidden = tab !== "peers";
	el("pageTitle").textContent = tab === "rules" ? "Règles AVP (rt_rewrite)" : "Peers & Identité (freeDiameter.conf)";
	if (tab === "peers") {
		loadIdentity();
		loadPeers();
		loadDiscoveredPeers();
	}
}

document.querySelectorAll(".tab-btn").forEach((b) => {
	b.addEventListener("click", () => switchTab(b.dataset.tab));
});

/* ------------------------------------------------------------------ */
/* Identity                                                             */
/* ------------------------------------------------------------------ */

async function loadIdentity() {
	try {
		const identity = await api("/identity");
		if (identity) {
			el("f_identity").value = identity.identity;
			el("f_realm").value = identity.realm;
		}
	} catch (e) {
		showStatus("Erreur chargement identité: " + e.message, "error");
	}
	await refreshDaemonPreview();
}

async function saveIdentity(e) {
	e.preventDefault();
	try {
		await api("/identity", {
			method: "PUT",
			body: JSON.stringify({ identity: el("f_identity").value, realm: el("f_realm").value }),
		});
		showStatus("Identité enregistrée (pas encore écrite dans freeDiameter.conf -- clique 'Écrire la config').", "ok");
		await refreshDaemonPreview();
	} catch (e) {
		showStatus("Erreur: " + e.message, "error");
	}
}

el("identityForm").addEventListener("submit", saveIdentity);

/* ------------------------------------------------------------------ */
/* Peers                                                                */
/* ------------------------------------------------------------------ */

let editingPeerId = null;

function splitLines(text) {
	return text.split("\n").map((s) => s.trim()).filter((s) => s.length > 0);
}

function peerOptionsSummary(peer) {
	const opts = [];
	if (peer.no_tls) opts.push("No_TLS");
	if (peer.prefer_tcp) opts.push("Prefer_TCP");
	if (peer.no_tcp) opts.push("No_TCP");
	if (peer.no_sctp) opts.push("No_SCTP");
	if (peer.no_ip) opts.push("No_IP");
	if (peer.no_ipv6) opts.push("No_IPv6");
	if (peer.tls_old_method) opts.push("TLS_old_method");
	if (peer.port) opts.push(`Port=${peer.port}`);
	return opts.join(", ") || "—";
}

async function loadPeers() {
	const peers = await api("/peers");
	const tbody = el("peerTableBody");
	tbody.innerHTML = "";

	for (const peer of peers) {
		const tr = document.createElement("tr");
		tr.innerHTML = `
			<td><span class="badge ${peer.enabled ? "badge-move" : "badge-off"}">${peer.enabled ? "on" : "off"}</span></td>
			<td>${escapeHtml(peer.diameter_id)}</td>
			<td><code>${escapeHtml((peer.connect_to || []).join(", "))}</code></td>
			<td>${escapeHtml(peer.realm || "—")}</td>
			<td><code>${escapeHtml(peerOptionsSummary(peer))}</code></td>
			<td><span class="badge badge-status-down" title="Pas encore implémenté">inconnu</span></td>
			<td>
				<button class="btn-live-add" data-action="live-add-peer" data-id="${peer.id}" title="Ajoute ce peer maintenant via fd_peer_add(), sans redémarrer freeDiameterd. N'écrit PAS dans freeDiameter.conf -- utilise 'Écrire la config' pour le rendre permanent.">⚡ Live-add</button>
				<button class="btn-icon" data-action="edit-peer" data-id="${peer.id}">Éditer</button>
				<button class="btn-danger" data-action="delete-peer" data-id="${peer.id}">Suppr.</button>
			</td>
		`;
		tbody.appendChild(tr);
	}

	tbody.querySelectorAll("[data-action=edit-peer]").forEach((btn) => {
		btn.addEventListener("click", () => editPeer(parseInt(btn.dataset.id, 10)));
	});
	tbody.querySelectorAll("[data-action=delete-peer]").forEach((btn) => {
		btn.addEventListener("click", () => deletePeer(parseInt(btn.dataset.id, 10)));
	});
	tbody.querySelectorAll("[data-action=live-add-peer]").forEach((btn) => {
		btn.addEventListener("click", () => liveAddPeer(parseInt(btn.dataset.id, 10)));
	});

	await refreshDaemonPreview();
}

async function refreshDaemonPreview() {
	try {
		const { config } = await api("/daemon-config/preview");
		el("daemonPreviewText").textContent = config || "(rien -- configure l'identité et au moins un peer)";
	} catch (e) {
		el("daemonPreviewText").textContent = "Erreur de génération: " + e.message;
	}
}

function resetPeerForm() {
	editingPeerId = null;
	el("peerFormTitle").textContent = "Nouveau peer";
	el("peerForm").reset();
	el("p_enabled").checked = true;
}

function fillPeerForm(peer) {
	editingPeerId = peer.id;
	el("peerFormTitle").textContent = "Éditer le peer";
	el("p_diameter_id").value = peer.diameter_id;
	el("p_connect_to").value = (peer.connect_to || []).join("\n");
	el("p_port").value = peer.port ?? "";
	el("p_realm").value = peer.realm || "";
	el("p_tc_timer").value = peer.tc_timer ?? "";
	el("p_tw_timer").value = peer.tw_timer ?? "";
	el("p_tls_prio").value = peer.tls_prio || "";
	el("p_no_tls").checked = !!peer.no_tls;
	el("p_prefer_tcp").checked = !!peer.prefer_tcp;
	el("p_no_tcp").checked = !!peer.no_tcp;
	el("p_no_sctp").checked = !!peer.no_sctp;
	el("p_no_ip").checked = !!peer.no_ip;
	el("p_no_ipv6").checked = !!peer.no_ipv6;
	el("p_tls_old_method").checked = !!peer.tls_old_method;
	el("p_enabled").checked = peer.enabled;

	el("peerFormSection").hidden = false;
	el("peerFormSection").scrollIntoView({ behavior: "smooth" });
}

async function editPeer(id) {
	const peer = await api(`/peers/${id}`);
	fillPeerForm(peer);
}

async function deletePeer(id) {
	if (!confirm("Supprimer ce peer ?")) return;
	try {
		await api(`/peers/${id}`, { method: "DELETE" });
		showStatus("Peer supprimé.", "ok");
		await loadPeers();
	} catch (e) {
		showStatus("Erreur: " + e.message, "error");
	}
}

function intOrNull(v) {
	const s = (v || "").trim();
	if (!s) return null;
	const n = parseInt(s, 10);
	return Number.isNaN(n) ? null : n;
}

function buildPeerFromForm() {
	return {
		diameter_id: el("p_diameter_id").value,
		enabled: el("p_enabled").checked,
		connect_to: splitLines(el("p_connect_to").value),
		port: intOrNull(el("p_port").value),
		realm: el("p_realm").value || null,
		tc_timer: intOrNull(el("p_tc_timer").value),
		tw_timer: intOrNull(el("p_tw_timer").value),
		tls_prio: el("p_tls_prio").value || null,
		no_tls: el("p_no_tls").checked,
		prefer_tcp: el("p_prefer_tcp").checked,
		no_tcp: el("p_no_tcp").checked,
		no_sctp: el("p_no_sctp").checked,
		no_ip: el("p_no_ip").checked,
		no_ipv6: el("p_no_ipv6").checked,
		tls_old_method: el("p_tls_old_method").checked,
	};
}

async function savePeer(e) {
	e.preventDefault();
	const peer = buildPeerFromForm();
	try {
		if (editingPeerId) {
			await api(`/peers/${editingPeerId}`, { method: "PUT", body: JSON.stringify(peer) });
		} else {
			await api("/peers", { method: "POST", body: JSON.stringify(peer) });
		}
		showStatus("Peer enregistré.", "ok");
		el("peerFormSection").hidden = true;
		resetPeerForm();
		await loadPeers();
	} catch (err) {
		showStatus("Erreur: " + err.message, "error");
	}
}

async function applyDaemonConfig() {
	if (!confirm("Écrire Identity/Realm/Peers dans freeDiameter.conf maintenant ? (redémarrage manuel du daemon nécessaire ensuite)")) return;
	try {
		const result = await api("/daemon-config/apply", { method: "POST" });
		showStatus(`Écrit dans ${result.conf_path} (backup: ${result.backup_path || "aucun"}). Redémarre freeDiameterd pour appliquer.`, "ok");
	} catch (e) {
		showStatus("Échec: " + e.message, "error");
	}
}

async function liveAddPeer(id) {
	if (!confirm("Ajouter ce peer maintenant sans redémarrer freeDiameterd ? (n'écrit pas dans freeDiameter.conf -- utilise 'Écrire la config' séparément pour le rendre permanent)")) return;
	try {
		const result = await api(`/peers/${id}/live-add`, { method: "POST" });
		showStatus(`Peer ajouté en live (signal envoyé au pid ${result.pid}). Vérifie les logs freeDiameter pour confirmer la connexion.`, "ok");
	} catch (e) {
		showStatus("Échec du live-add: " + e.message, "error");
	}
}

/* ------------------------------------------------------------------ */
/* Discovered peers                                                     */
/* ------------------------------------------------------------------ */

function formatTimestamp(unixSeconds) {
	if (!unixSeconds) return "—";
	return new Date(unixSeconds * 1000).toLocaleString("fr-FR");
}

async function loadDiscoveredPeers() {
	let candidates = [];
	try {
		candidates = await api("/discovered-peers");
	} catch (e) {
		showStatus("Erreur chargement peers découverts: " + e.message, "error");
	}

	const tbody = el("discoveredTableBody");
	tbody.innerHTML = "";

	if (candidates.length === 0) {
		tbody.innerHTML = `<tr><td colspan="5" class="hint-text">Aucun peer inconnu détecté pour l'instant.</td></tr>`;
		return;
	}

	for (const c of candidates) {
		const tr = document.createElement("tr");
		tr.innerHTML = `
			<td>${escapeHtml(c.diameter_id)}</td>
			<td>${escapeHtml(c.realm || "—")}</td>
			<td>${c.attempts ?? "—"}</td>
			<td>${formatTimestamp(c.last_seen)}</td>
			<td><button class="btn-secondary btn-small" data-action="adopt-peer" data-id="${escapeHtml(c.diameter_id)}">Adopter</button></td>
		`;
		tbody.appendChild(tr);
	}

	tbody.querySelectorAll("[data-action=adopt-peer]").forEach((btn) => {
		btn.addEventListener("click", () => adoptDiscoveredPeer(btn.dataset.id));
	});
}

async function adoptDiscoveredPeer(diameterId) {
	try {
		const peer = await api(`/discovered-peers/${encodeURIComponent(diameterId)}/adopt`, { method: "POST" });
		showStatus(`"${diameterId}" ajouté au formulaire Peers -- relis/complète avant d'appliquer.`, "ok");
		await loadPeers();
		fillPeerForm(peer);
	} catch (e) {
		showStatus("Erreur: " + e.message, "error");
	}
}

el("refreshDiscoveredBtn").addEventListener("click", loadDiscoveredPeers);

async function backupDaemonConfig() {
	try {
		const result = await api("/backup/daemon", { method: "POST" });
		showStatus(`Sauvegardé : ${result.backup_path || "(rien à sauvegarder, fichier inexistant)"}`, "ok");
	} catch (e) {
		showStatus("Échec de la sauvegarde: " + e.message, "error");
	}
}

el("newPeerBtn").addEventListener("click", () => {
	resetPeerForm();
	el("peerFormSection").hidden = false;
	el("peerFormSection").scrollIntoView({ behavior: "smooth" });
});
el("peerCancelBtn").addEventListener("click", () => {
	el("peerFormSection").hidden = true;
});
el("peerForm").addEventListener("submit", savePeer);
el("applyDaemonBtn").addEventListener("click", applyDaemonConfig);
el("backupDaemonBtn").addEventListener("click", backupDaemonConfig);

resetForm();
resetPeerForm();
loadRules();
