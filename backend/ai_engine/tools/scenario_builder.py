# FILE: backend/ai_engine/tools/scenario_builder.py
# PURPOSE: Builds step-by-step attack narrative skeleton for the AI scenario agent
# SECURITY NOTE: Narrative-only; no executable code is generated

TOOL_SPEC = {
    "name": "build_attack_steps",
    "description": (
        "Build a numbered step-by-step attack narrative for a vulnerability scenario. "
        "Steps guide a learner through reconnaissance, exploitation, and impact."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "vuln_type": {"type": "string"},
            "target_field": {
                "type": "string",
                "description": "The specific UI field or endpoint (e.g. 'username field on /login')"
            },
            "payloads": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Payload strings to incorporate into the steps"
            },
            "include_defense": {
                "type": "boolean",
                "description": "Include mitigation steps after the attack walkthrough"
            }
        },
        "required": ["vuln_type", "target_field", "payloads"]
    }
}


async def execute(input: dict) -> dict:
    vuln_type = input["vuln_type"]
    target = input["target_field"]
    payloads = input.get("payloads", [])
    include_defense = input.get("include_defense", True)

    base_steps = [
        {"step": 1, "phase": "Reconnaissance",
         "title": f"Identify the target: {target}",
         "description": f"Observe the {target} and determine it accepts user input."},
        {"step": 2, "phase": "Probe",
         "title": "Test with a benign probe",
         "description": "Enter a simple value to confirm the field is functional."},
        {"step": 3, "phase": "Exploit",
         "title": "Inject the attack payload",
         "description": f"Enter payload: {payloads[0] if payloads else 'N/A'}"},
        {"step": 4, "phase": "Impact",
         "title": "Observe and document the outcome",
         "description": "Confirm that the exploit succeeded and record the result."},
    ]

    if include_defense:
        base_steps.append({
            "step": 5, "phase": "Defense",
            "title": "Switch to Secure Mode and repeat",
            "description": "Toggle Security Mode ON and retry the same payload — observe it is blocked."
        })

    return {
        "vuln_type": vuln_type,
        "target_field": target,
        "steps": base_steps
    }
