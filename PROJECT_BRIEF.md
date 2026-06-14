# VulnLab — Web Security Learning Platform
## Master Project Brief

---

## 1. Project Overview

Build a full-stack web application that simulates OWASP Top 10 vulnerabilities for
educational purposes. The platform has **two modes** toggleable at runtime:
`Vulnerable Mode` and `Secure Mode`, so learners can compare behavior side-by-side.

**Stack:**
- Frontend: **Angular 17+** (standalone components, Angular Material)
- Backend: **Python FastAPI** (async, Pydantic v2)
- Database: **PostgreSQL** (via SQLAlchemy async + asyncpg)
- Container: **Docker + Docker Compose**
- AI Scenario Engine: **Anthropic API** (`claude-sonnet-4-6`) with Tool Use

---

## 2. Repository Structure

```
vuln-lab/
├── docker-compose.yml
├── .env.example
├── README.md
|-- .gitignore
├── CLAUDE.md
├── PROJECT_BRIEF.md
├── AI_ENGINE_SPEC.md
│
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py
│   ├── config.py
│   ├── database.py
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   ├── user.py
│   │   ├── comment.py
│   │   ├── upload.py
│   │   ├── scenario.py
│   │   └── attack_log.py
│   │
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── auth.py
│   │   ├── comments.py
│   │   ├── uploads.py
│   │   ├── csrf_demo.py
│   │   └── scenarios.py
│   │
│   ├── middleware/
│   │   └── security_mode.py
│   │
│   ├── security/
│   │   ├── sql_injection.py
│   │   ├── xss_filter.py
│   │   ├── file_validator.py
│   │   └── csrf_token.py
│   │
│   ├── ai_engine/
│   │   ├── __init__.py
│   │   ├── scenario_agent.py
│   │   ├── prompts.py
│   │   └── tools/
│   │       ├── __init__.py
│   │       ├── payload_generator.py
│   │       ├── scenario_builder.py
│   │       └── risk_analyzer.py
│   │
│   └── seed.py
│
└── frontend/
    ├── Dockerfile
    ├── nginx.conf
    ├── package.json
    ├── angular.json
    ├── tsconfig.json
    │
    └── src/
        ├── main.ts
        ├── styles.scss
        └── app/
            ├── app.config.ts
            ├── app.routes.ts
            │
            ├── core/
            │   ├── services/
            │   │   ├── security-mode.service.ts
            │   │   ├── auth.service.ts
            │   │   └── scenario.service.ts
            │   └── interceptors/
            │       └── security-mode.interceptor.ts
            │
            ├── shared/
            │   └── components/
            │       ├── mode-toggle/
            │       ├── source-viewer/
            │       └── payload-badge/
            │
            └── features/
                ├── dashboard/
                ├── auth-demo/
                ├── xss-demo/
                ├── upload-demo/
                ├── csrf-demo/
                └── scenario-lab/
```

---

## 3. Core Design — Security Mode Toggle

Every API request carries header: `X-Security-Mode: vulnerable` or `X-Security-Mode: secure`

- Frontend `SecurityModeService` holds a `BehaviorSubject<'vulnerable'|'secure'>`
- `SecurityModeInterceptor` appends the header to ALL outgoing HTTP requests
- Backend `SecurityModeMiddleware` reads the header → sets `request.state.secure_mode: bool`
- All business logic branches on `request.state.secure_mode`

```python
# Standard pattern used in EVERY router
secure = request.state.secure_mode
if secure:
    result = await safe_operation(...)
else:
    result = await vulnerable_operation(...)
```

---

## 4. Database Schema (PostgreSQL)

```sql
-- users
CREATE TABLE users (
  id            SERIAL PRIMARY KEY,
  username      VARCHAR(50) UNIQUE NOT NULL,
  password_plain VARCHAR(255),        -- vulnerable mode: plain text
  password_hash  VARCHAR(255),        -- secure mode: bcrypt hash
  role          VARCHAR(20) DEFAULT 'user',   -- 'user' | 'admin'
  created_at    TIMESTAMP DEFAULT NOW()
);

-- comments
CREATE TABLE comments (
  id          SERIAL PRIMARY KEY,
  user_id     INT REFERENCES users(id),
  content     TEXT NOT NULL,          -- XSS demo target field
  created_at  TIMESTAMP DEFAULT NOW()
);

-- uploads
CREATE TABLE uploads (
  id           SERIAL PRIMARY KEY,
  user_id      INT REFERENCES users(id),
  file_name    VARCHAR(255) NOT NULL,
  file_path    VARCHAR(255) NOT NULL,
  file_size    INT,
  mime_type    VARCHAR(100),
  uploaded_at  TIMESTAMP DEFAULT NOW()
);

-- scenarios (AI-generated)
-- vuln_type values:
--   'sql_injection' | 'xss' | 'csrf' | 'file_upload' | 'broken_auth'
--   'security_misconfig' | 'sensitive_data_exposure' | 'logging_monitoring'
--   'supply_chain' | 'cryptographic_failure' | 'insecure_design'
--   'exceptional_conditions' | 'underprotected_apis'
CREATE TABLE scenarios (
  id           SERIAL PRIMARY KEY,
  vuln_type    VARCHAR(60) NOT NULL,
  title        VARCHAR(255),
  steps        JSONB,
  payloads     JSONB,
  cvss_score   FLOAT,
  generated_at TIMESTAMP DEFAULT NOW()
);

-- attack_logs (every request with payload)
CREATE TABLE attack_logs (
  id            SERIAL PRIMARY KEY,
  endpoint      VARCHAR(255),
  payload       TEXT,
  security_mode VARCHAR(20),
  result        VARCHAR(50),   -- 'exploited' | 'blocked'
  timestamp     TIMESTAMP DEFAULT NOW()
);
```

---

## 5. Environment Variables (.env.example)

```env
DATABASE_URL=postgresql+asyncpg://vulnlab:vulnlab123@db:5432/vulnlab
ANTHROPIC_API_KEY=sk-ant-REPLACE_ME
SECRET_KEY=change-me-in-production
UPLOAD_DIR=/app/uploads
MAX_UPLOAD_SIZE_MB=10
FRONTEND_URL=http://localhost:4200
```
