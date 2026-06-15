# VulnLab — OWASP Top 10 Security Training Platform

A full-stack web application that simulates OWASP Top 10 vulnerabilities for educational purposes.
Toggle between **Vulnerable** and **Secure** mode at runtime to compare behavior side-by-side.

---

## Quick Start

```bash
# Start everything (Ollama + Docker stack + ELK)
./start-project.sh
```

| Service        | URL                        |
|----------------|----------------------------|
| Frontend       | http://localhost:4200       |
| Backend API    | http://localhost:8000       |
| Juice Shop     | http://localhost:3000       |
| Kibana         | http://localhost:5601       |
| Elasticsearch  | http://localhost:9200       |
| Ollama         | http://localhost:11434      |

Default login: `admin / admin123`

---

## Stack

| Layer      | Technology                                      |
|------------|-------------------------------------------------|
| Frontend   | Angular 17+ standalone components + Material    |
| Backend    | Python FastAPI (async) + Pydantic v2            |
| Database   | PostgreSQL via SQLAlchemy async + asyncpg       |
| Container  | Docker + Docker Compose                         |
| AI Engine  | Ollama (llama3.2) or Anthropic claude-sonnet-4-6|
| Monitoring | Elasticsearch + Logstash + Kibana (ELK 8.12)    |

---

## Configuration

Copy `.env.example` to `.env` and set your values:

```env
AI_PROVIDER=ollama                              # or "anthropic"
OLLAMA_BASE_URL=http://host.docker.internal:11434/v1
OLLAMA_MODEL=llama3.2
ANTHROPIC_API_KEY=sk-ant-REPLACE_ME            # only if AI_PROVIDER=anthropic
```

---

## Log Queries in Kibana

Open **http://localhost:5601** → Discover, select an index pattern.

### Index: `vulnlab-agent-*`
```
log_type: "agent_step"
```
Shows every AI scenario generation call with tool name, input, output and duration in ms.

### Index: `vulnlab-probes-*`
```
confirmed: true
```
Shows only probe scenarios that confirmed a vulnerability. Filter further:
```
confirmed: true AND vuln_type: "sql_injection"
```

### Index: `vulnlab-results-*`
```
severity: "critical" OR severity: "high"
```
Shows high-severity findings across all scans. Sort by `@timestamp` descending.

```
status: "success" AND scenarios_confirmed: >0
```
Results where Juice Shop-specific probe scenarios were confirmed.

### Index: `vulnlab-scans-*`
```
log_type: "session_complete"
```
One document per completed scan session — overview of all scans.
```
log_type: "session_complete" AND vulnerabilities_found: >0
```
Only scans that found vulnerabilities.

---

## Recommended Kibana Visualisations

| Visualisation         | Type       | Index                  | Field                        |
|-----------------------|------------|------------------------|------------------------------|
| Vulns by severity     | Bar chart  | `vulnlab-results-*`    | `severity`                   |
| Scan sessions over time | Timeline | `vulnlab-scans-*`      | `@timestamp`                 |
| Top confirmed vulns   | Data table | `vulnlab-probes-*`     | `scenario_name`, `confirmed` |
| Total scans & vulns   | Metric     | `vulnlab-scans-*`      | count, `vulnerabilities_found`|
| Vuln type distribution| Pie chart  | `vulnlab-results-*`    | `vuln_type`                  |
| Avg scan duration     | Line chart | `vulnlab-scans-*`      | `total_duration_ms`          |
| Agent call duration   | Bar chart  | `vulnlab-agent-*`      | `duration_ms`                |

---

## ELK Log Schema

Every log document includes `timestamp`, `service: "vulnlab-backend"`, and `log_type`.

### `scan_request`
```json
{ "log_type": "scan_request", "session_id": 1, "target_url": "...",
  "target_name": "...", "requested_by": "admin", "vuln_types": [...], "total_checks": 13 }
```

### `agent_step`
```json
{ "log_type": "agent_step", "session_id": 1, "vuln_type": "sql_injection",
  "step_number": 1, "tool_name": "generate_scenario",
  "tool_input": {...}, "tool_output": {...}, "duration_ms": 4200 }
```

### `probe_result`
```json
{ "log_type": "probe_result", "session_id": 1, "vuln_type": "xss",
  "scenario_name": "Reflected XSS in search endpoint",
  "request_method": "GET", "request_url": "/rest/products/search?q=...",
  "response_status": 200, "confirmed": true, "evidence": "...", "duration_ms": 320 }
```

### `scan_result`
```json
{ "log_type": "scan_result", "session_id": 1, "vuln_type": "sql_injection",
  "status": "success", "severity": "critical",
  "finding_summary": "SQL error message leaked...",
  "scenarios_tested": 4, "scenarios_confirmed": 2, "total_duration_ms": 8100 }
```

### `session_complete`
```json
{ "log_type": "session_complete", "session_id": 1, "target_url": "http://localhost:3000",
  "total_checks": 13, "vulnerabilities_found": 5,
  "highest_severity": "critical", "total_duration_ms": 142000 }
```

---

## Scanning Juice Shop

1. Start all services: `./start-project.sh`
2. Login to VulnLab at http://localhost:4200 (`admin / admin123`)
3. Click **Scan → New Scan**
4. Set target URL: `http://juice-shop:3000` (internal Docker hostname)
5. Click **Start Scan**
6. Watch results in the live scan view
7. Export PDF report when complete
8. View structured logs in Kibana: http://localhost:5601
