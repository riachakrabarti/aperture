package aperture

import rego.v1

# Inputs are assembled by the trusted gateway, never supplied by the agent.
# Tool semantics (tags) and profile rules live in aperture_data.json, loaded as
# policy data. The gateway passes only the workflow's recorded action history;
# every trajectory, egress, approval and budget judgement is made here.

cfg := data.aperture_config

profile := object.get(cfg.profiles, input.profile, {})

rules := object.get(profile, "sequence_rules", [])

history := object.get(input, "history", [])

tool_def(name) := object.get(cfg.tools, name, {})

tags_of(name) := base | extra if {
	base := {t | some t in object.get(tool_def(name), "tags", [])}
	extra := {t | some t in object.get(object.get(profile, "extra_tags", {}), name, [])}
}

current_tags := tags_of(input.tool)

history_tags := [tags_of(h.tool) | some h in history]

spent := sum([amount |
	some h in history
	"effect:spend" in tags_of(h.tool)
	amount := h.arguments[tool_def(h.tool).spend_argument]
])

# ---- Violations: {id, overridable}. Only overridable ones yield to an approval.

violations contains {"id": "unknown_profile", "overridable": false} if {
	not cfg.profiles[input.profile]
}

violations contains {"id": "unknown_tool", "overridable": false} if {
	not cfg.tools[input.tool]
}

violations contains {"id": "workflow_unresolved", "overridable": false} if {
	input.state.unresolved == true
}

violations contains {"id": "history_limit_reached", "overridable": false} if {
	count(history) >= cfg.max_history
}

violations contains {"id": "invalid_policy_configuration", "overridable": false} if {
	some r in rules
	not count(r.pattern) in {2, 3}
}

violations contains {"id": "exact_approval_required", "overridable": true} if {
	"approval:required" in current_tags
}

# Two-step trajectory: an earlier action tagged pattern[0], now pattern[1].
violations contains {"id": r.id, "overridable": r.overridable} if {
	some r in rules
	count(r.pattern) == 2
	r.pattern[1] in current_tags
	some tags in history_tags
	r.pattern[0] in tags
}

# Three-step trajectory: ordered, not necessarily adjacent.
violations contains {"id": r.id, "overridable": r.overridable} if {
	some r in rules
	count(r.pattern) == 3
	r.pattern[2] in current_tags
	some i, first in history_tags
	r.pattern[0] in first
	some j, second in history_tags
	i < j
	r.pattern[1] in second
}

violations contains {"id": "egress_destination_not_allowlisted", "overridable": false} if {
	"sink:external" in current_tags
	allowlist := object.get(profile, "egress_allowlist", null)
	allowlist != null
	argument := object.get(tool_def(input.tool), "destination_argument", "destination")
	not object.get(input.arguments, argument, "") in allowlist
}

violations contains {"id": "cumulative_budget_exceeded", "overridable": false} if {
	"effect:spend" in current_tags
	amount := input.arguments[tool_def(input.tool).spend_argument]
	spent + amount > input.budget_cents
}

overridden(v) if {
	v.overridable
	input.approval_valid == true
}

reasons contains v.id if {
	some v in violations
	not overridden(v)
}

overridden_ids contains v.id if {
	some v in violations
	overridden(v)
}

# ---- Evidence mapping, from the profile's data. Replayable with the decision.

evidence_cfg := object.get(profile, "evidence", {})

controls contains c if {
	some c in object.get(evidence_cfg, "baseline", [])
}

controls contains c if {
	some v in violations
	some c in object.get(object.get(evidence_cfg, "by_reason", {}), v.id, [])
}

controls contains c if {
	input.approval_valid == true
	count(overridden_ids) > 0
	some c in object.get(evidence_cfg, "on_approval", [])
}

evidence := {
	"profile": input.profile,
	"framework": object.get(evidence_cfg, "framework", "none"),
	"controls": sort(controls),
}

decision := {
	"allow": count(reasons) == 0,
	"reasons": sort(reasons),
	"overridden": sort(overridden_ids),
	"evidence": evidence,
}

# ---- Queries used by the gateway outside tool calls.

approvable if {
	"approval:required" in current_tags
}

approvable if {
	some r in rules
	r.overridable
	r.pattern[count(r.pattern) - 1] in current_tags
}

approval_terms := {
	"approvable": approvable == true,
	"max_ttl_seconds": object.get(profile, "max_approval_ttl_seconds", 900),
}

default approvable := false

summary := {
	"profile": input.profile,
	"spent_cents": spent,
	"tags_seen": sort({t | some ts in history_tags; some t in ts}),
}
