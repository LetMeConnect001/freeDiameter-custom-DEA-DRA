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

resetForm();
loadRules();
