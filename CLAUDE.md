# CLAUDE.md — Agent Instructions for VulnLab

> Auto-read by Claude agents in VSCode. Follow every rule precisely.
> Read PROJECT_BRIEF.md and AI_ENGINE_SPEC.md before writing any code.

---

## Stack

| Layer     | Technology                                    |
|-----------|-----------------------------------------------|
| Frontend  | Angular 17+ standalone components + Material  |
| Backend   | Python FastAPI (async) + Pydantic v2          |
| Database  | PostgreSQL via SQLAlchemy async + asyncpg     |
| Container | Docker + Docker Compose                       |
| AI Engine | Anthropic API `claude-sonnet-4-6` + Tool Use  |

---

## Phase Execution Order

Complete each phase fully and pass its verification before starting the next.

---

### Phase 1 — Scaffold & Docker

1. Create full directory tree from PROJECT_BRIEF.md section 2
2. Create `docker-compose.yml` (services: `db`, `backend`, `frontend`)
3. Create `.env.example` from PROJECT_BRIEF.md section 5
4. Create `backend/Dockerfile`, `backend/requirements.txt`
5. Create `frontend/Dockerfile`, `frontend/nginx.conf`, `frontend/package.json`
6. Create `backend/config.py` using pydantic-settings reading from env vars
7. Create `backend/database.py` with async SQLAlchemy engine + `AsyncSessionLocal`

**requirements.txt must include:**
```
fastapi==0.111.0
uvicorn[standard]==0.30.1
sqlalchemy[asyncio]==2.0.30
asyncpg==0.29.0
alembic==1.13.1
pydantic==2.7.1
pydantic-settings==2.3.0
python-multipart==0.0.9
passlib[bcrypt]==1.7.4
python-jose[cryptography]==3.3.0
bleach==6.1.0
anthropic==0.28.0
httpx==0.27.0
pillow==10.3.0
python-magic==0.4.27
```

**package.json key deps:**
```json
"@angular/core": "^17.3.0",
"@angular/material": "^17.3.0",
"@angular/cdk": "^17.3.0",
"@angular/router": "^17.3.0",
"@angular/forms": "^17.3.0",
"rxjs": "~7.8.0",
"prismjs": "^1.29.0"
```

✅ **Verify:** `docker-compose config` exits 0

---

### Phase 2 — Database Models & Seed

1. Create all 5 SQLAlchemy models: `user.py`, `comment.py`, `upload.py`, `scenario.py`, `attack_log.py`
2. Create Alembic migration: `alembic init alembic` + generate initial migration
3. Create `backend/seed.py` inserting:
   - Users: `admin/admin123` (role=admin), `alice/password`, `bob/test`
   - Passwords stored BOTH as plain text (`password_plain`) AND bcrypt hash (`password_hash`)
   - 5 comments: 3 normal text, 2 containing XSS payloads as strings (for demo display)

✅ **Verify:** `cd backend && python seed.py` → "Seeded successfully" with no errors

---

### Phase 3 — Backend Core

1. Create `backend/main.py`:
   - FastAPI app with CORS (allow `FRONTEND_URL` from env)
   - Mount all routers
   - `/health` endpoint returning `{"status": "ok"}`
   - On startup: run Alembic migrations

2. Create `backend/middleware/security_mode.py`:
   ```python
   # Reads header X-Security-Mode
   # Sets request.state.secure_mode = True | False
   # Default: False (vulnerable) if header absent
   ```

3. Create `backend/security/` — 4 files:
   - `sql_injection.py`: `vulnerable_login()` (raw string concat) + `safe_login()` (prepared statements + bcrypt check)
   - `xss_filter.py`: `render_raw(text)` (no filter) + `render_safe(text)` (bleach sanitize)
   - `file_validator.py`: `save_no_check(file)` + `save_validated(file)` (whitelist MIME + rename)
   - `csrf_token.py`: `generate_token(session_id)` + `verify_token(token, session_id)`

4. Create all 4 routers (NOT scenarios.py yet):
   - `auth.py` — POST /api/auth/login, POST /api/auth/register
   - `comments.py` — GET/POST /api/comments
   - `uploads.py` — POST /api/uploads, GET /api/uploads
   - `csrf_demo.py` — GET /api/csrf/token, POST /api/csrf/action

5. Every router must log to `attack_logs` table: endpoint, payload, mode, result

✅ **Verify:** `uvicorn main:app --reload` → `GET /health` returns 200

---

### Phase 4 — AI Engine

Follow AI_ENGINE_SPEC.md exactly.

1. Create `backend/ai_engine/tools/payload_generator.py` — copy TOOL_SPEC and PAYLOADS dict from AI_ENGINE_SPEC.md verbatim (all 13 vuln types)
2. Create `backend/ai_engine/tools/scenario_builder.py` — copy TOOL_SPEC and execute() from spec
3. Create `backend/ai_engine/tools/risk_analyzer.py` — copy TOOL_SPEC, BASE_SCORES, OWASP_MAPPING, execute() from spec
4. Create `backend/ai_engine/scenario_agent.py` — copy agent loop from spec exactly
5. Create `backend/routers/scenarios.py` — copy router from spec

✅ **Verify:**
```bash
curl -X POST http://localhost:8000/api/scenarios/generate \
  -H "Content-Type: application/json" \
  -d '{"vuln_type":"sql_injection","difficulty":"beginner"}'
```
Response must be a JSON object with keys: `title`, `steps`, `payloads`, `risk`, `defense_tips`, `code_examples`

---

### Phase 5 — Angular Frontend

1. Scaffold Angular app:
   ```bash
   cd frontend && npx @angular/cli@17 new vuln-lab \
     --routing --style=scss --standalone --skip-git
   ```

2. Create `SecurityModeService`:
   ```typescript
   // Holds BehaviorSubject<'vulnerable'|'secure'>
   // Exposes toggle(), currentMode$, currentMode signal
   // Persists to localStorage key 'vuln-lab-mode'
   ```

3. Create `SecurityModeInterceptor`:
   ```typescript
   // Appends header X-Security-Mode: vulnerable|secure to every HttpRequest
   ```

4. Create shared components (all standalone):
   - `ModeToggleComponent` — slide toggle, shows current mode, emits on change
   - `SourceViewerComponent` — takes `{vulnerable: string, secure: string}`, shows syntax-highlighted code side by side using PrismJS
   - `PayloadBadgeComponent` — displays a payload string with copy button

5. Create 6 feature components (standalone, lazy-loaded):
   - `DashboardComponent` — grid of 13 vulnerability cards, each links to scenario-lab
   - `AuthDemoComponent` — login form, shows SQLi result, source code viewer
   - `XssDemoComponent` — comment form + list, renders raw HTML in vulnerable mode
   - `UploadDemoComponent` — file upload with result display
   - `CsrfDemoComponent` — shows form with/without CSRF token
   - `ScenarioLabComponent` — dropdown for vuln type + difficulty, "Generate Scenario" button, renders steps/payloads/risk from API

6. Set up routing in `app.routes.ts` with lazy loading for all features

7. Add Angular Material toolbar with mode toggle visible on all pages

✅ **Verify:** `ng build --configuration production` exits 0

---

### Phase 6 — Integration & Docker

1. Update `frontend/nginx.conf` to proxy `/api/` to `http://backend:8000`
2. Ensure `docker-compose up --build` starts all 3 services cleanly
3. Smoke test full flow:
   - Toggle to Vulnerable → POST login with `' OR '1'='1` → see "Login successful"
   - Toggle to Secure → same payload → see "Invalid credentials"
   - Go to Scenario Lab → select "XSS" → Generate → see structured scenario

✅ **Verify:** `docker-compose up --build` — all containers healthy, app reachable at http://localhost:4200

---

## Rules — Never Violate

### Security Mode
```python
# EVERY router handler must follow this pattern
secure = request.state.secure_mode   # set by SecurityModeMiddleware
if secure:
    result = await safe_operation(...)
else:
    result = await vulnerable_operation(...)
```

### Vulnerable code is real but scoped
- SQLi: raw `f"SELECT * FROM users WHERE username='{username}'"` — no ORM
- XSS: `return HTMLResponse(content=f"<p>{user_input}</p>")` — no escaping
- File upload: save with original filename, no MIME check
- These only run inside Docker; production config must always use secure path

### Angular — strictly standalone
- No NgModules anywhere
- Use `inject()` not constructor injection
- Use `HttpClient` with `provideHttpClient(withInterceptors([securityModeInterceptor]))`
- Only Tailwind utility classes OR Angular Material — not both mixed

### AI Engine
- Model: always `claude-sonnet-4-6`
- `max_tokens`: 4000
- Loop until `stop_reason == "end_turn"` (max 8 iterations)
- Save every generated scenario to `scenarios` table
- All 13 vuln types must be supported

### Code quality
- Python: type hints on all functions, async/await everywhere
- TypeScript: `strict: true` in tsconfig, no `any`
- No hardcoded secrets — read exclusively from env via `config.py`
- Every file starts with a header comment: purpose + security note

---

## File Header Template

```python
# FILE: backend/routers/auth.py
# PURPOSE: Login/register — demonstrates SQL Injection (vulnerable mode)
#          and Parameterized Queries + bcrypt (secure mode)
# READS: request.state.secure_mode (set by SecurityModeMiddleware)
```

```typescript
// FILE: frontend/src/app/features/xss-demo/xss-demo.component.ts
// PURPOSE: Comment form demo for XSS vulnerability
// SECURE MODE: renders content as plain text via Angular binding
// VULNERABLE MODE: renders raw innerHTML (DO NOT use in production)
```

## What NOT To Do

- Do NOT use Flask — use FastAPI
- Do NOT use NgModules — use standalone components
- Do NOT skip the agentic tool loop — scenarios must be AI-generated, never hardcoded
- Do NOT use synchronous SQLAlchemy — use asyncpg + async_session
- Do NOT store uploaded files outside the Docker volume
- Do NOT expose ANTHROPIC_API_KEY to the frontend
- Do NOT proceed to next phase if current phase verification fails
- Do NOT commit .env to git — .gitignore must exclude it
- Do NOT gitignore .env.example — it must be committed as a template

