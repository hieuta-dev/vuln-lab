# VSCODE_SETUP.md — Setup & Start Commands

---

## Prerequisites

- VSCode + **Cline** extension (or Claude Dev / Roo Code)
- Docker Desktop running
- Anthropic API key (Claude Opus access)

---

## Bước 1 — Tạo project folder

```bash
mkdir vuln-lab && cd vuln-lab
```

---

## Bước 2 — Tạo các file bootstrap thủ công

Copy nội dung từ `STARTER_FILES.md`, tạo đúng các file sau:

```
vuln-lab/
├── docker-compose.yml        ← từ STARTER_FILES.md
├── .env.example              ← từ STARTER_FILES.md
├── backend/
│   ├── Dockerfile            ← từ STARTER_FILES.md
│   └── requirements.txt      ← từ STARTER_FILES.md
└── frontend/
    ├── Dockerfile            ← từ STARTER_FILES.md
    ├── nginx.conf            ← từ STARTER_FILES.md
    └── package.json          ← từ STARTER_FILES.md
```

Sau đó copy 5 file MD vào root:

```bash
cp CLAUDE.md PROJECT_BRIEF.md AI_ENGINE_SPEC.md STARTER_FILES.md VSCODE_SETUP.md vuln-lab/
```

---

## Bước 3 — Tạo .env

```bash
cd vuln-lab
cp .env.example .env
# Mở .env, điền ANTHROPIC_API_KEY thật của bạn
```

---

## Bước 4 — Mở VSCode

```bash
code .
```

---

## Bước 5 — Cấu hình Cline extension

Trong Cline settings:
- **Model:** `claude-opus-4-6` (hoặc `claude-opus-4-7` nếu có)
- **Max tokens:** 8000
- **Auto-approve:** file create + edit (để agent không hỏi từng file)

---

## ═══════════════════════════════════════
## LỆNH KHỞI ĐỘNG CHO AGENT
## ═══════════════════════════════════════

Mở Cline chat panel, paste đúng prompt sau:

### Prompt khởi động (copy nguyên)

```
Read these files in order before writing any code:
1. CLAUDE.md
2. PROJECT_BRIEF.md  
3. AI_ENGINE_SPEC.md

Then execute Phase 1 from CLAUDE.md completely.
After Phase 1 verification passes, continue with Phase 2.
Continue sequentially through all 6 phases without stopping.
If a verification step fails, fix the error and re-verify before proceeding.
Do not ask for confirmation between phases — complete all 6 phases automatically.
```

---

## Chạy từng phase (nếu muốn kiểm soát từng bước)

```
Read CLAUDE.md, PROJECT_BRIEF.md, AI_ENGINE_SPEC.md.
Execute Phase 1 only. Stop and report when verification passes.
```

Sau khi Phase 1 xong:
```
Phase 1 verified. Execute Phase 2 only.
```

Tiếp tục cho đến Phase 6.

---

## Prompt xử lý lỗi

```
Phase [N] verification failed with this error:
[paste error message here]

Fix the error, then re-run the verification command for Phase [N].
```

---

## Prompt thêm vuln type mới

```
Add a new vulnerability demo for "Server-Side Request Forgery (SSRF)":
- vuln_type id: "ssrf"
- Add payloads to AI_ENGINE_SPEC.md PAYLOADS dict
- Add to ALLOWED_VULN_TYPES in backend/routers/scenarios.py
- Add to ScenarioService.VULN_TYPES array in Angular
- Add new router: backend/routers/ssrf_demo.py (vulnerable + secure)
- Add new Angular feature: frontend/src/app/features/ssrf-demo/
- Add card to DashboardComponent
```

---

## Verification commands (chạy tay để kiểm tra)

```bash
# Phase 1 — Docker config valid
docker-compose config

# Phase 2 — Seed DB
cd backend && python seed.py

# Phase 3 — Backend health
cd backend && uvicorn main:app --reload &
curl http://localhost:8000/health
# expected: {"status":"ok"}

# Phase 4 — AI scenario generation
curl -X POST http://localhost:8000/api/scenarios/generate \
  -H "Content-Type: application/json" \
  -d '{"vuln_type":"sql_injection","difficulty":"beginner"}'
# expected: JSON with title, steps, payloads, risk, defense_tips

# Phase 5 — Angular build
cd frontend && ng build --configuration production
# expected: exit 0

# Phase 6 — Full stack
docker-compose up --build
# open http://localhost:4200
```

---

## Troubleshooting

| Lỗi | Fix |
|-----|-----|
| `asyncpg.InvalidPasswordError` | Kiểm tra `.env` DATABASE_URL khớp với docker-compose |
| `anthropic.AuthenticationError` | Điền đúng `ANTHROPIC_API_KEY` trong `.env` |
| `CORS blocked` từ Angular | Kiểm tra `FRONTEND_URL=http://localhost:4200` trong `.env` |
| `ng build` fail `Cannot find module` | Chạy `npm install` trong `frontend/` |
| Agent loop không kết thúc | Tăng `max_iterations` trong `scenario_agent.py` lên 10 |
| `stop_reason` = `max_tokens` | Tăng `max_tokens` lên 6000 trong agent |
| Frontend không gọi được API | Kiểm tra `nginx.conf` proxy đúng port 8000 |
