# STARTER_FILES.md
# Paste these files manually BEFORE running the agent.

---

## docker-compose.yml

```yaml
version: '3.9'

services:
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: vulnlab
      POSTGRES_PASSWORD: vulnlab123
      POSTGRES_DB: vulnlab
    volumes:
      - pgdata:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U vulnlab"]
      interval: 5s
      timeout: 5s
      retries: 5

  backend:
    build: ./backend
    env_file: .env
    environment:
      DATABASE_URL: postgresql+asyncpg://vulnlab:vulnlab123@db:5432/vulnlab
      FRONTEND_URL: http://localhost:4200
    volumes:
      - ./backend:/app
      - uploads:/app/uploads
    ports:
      - "8000:8000"
    depends_on:
      db:
        condition: service_healthy
    command: uvicorn main:app --host 0.0.0.0 --port 8000 --reload

  frontend:
    build: ./frontend
    ports:
      - "4200:80"
    depends_on:
      - backend

volumes:
  pgdata:
  uploads:
```

---

## .env.example

```env
DATABASE_URL=postgresql+asyncpg://vulnlab:vulnlab123@db:5432/vulnlab
ANTHROPIC_API_KEY=sk-ant-REPLACE_ME
SECRET_KEY=change-me-in-production
UPLOAD_DIR=/app/uploads
MAX_UPLOAD_SIZE_MB=10
FRONTEND_URL=http://localhost:4200
```

---

## backend/Dockerfile

```dockerfile
FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    libpq-dev gcc libmagic1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## backend/requirements.txt

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

---

## frontend/Dockerfile

```dockerfile
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build -- --configuration production

FROM nginx:alpine
COPY --from=builder /app/dist/vuln-lab/browser /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
```

---

## frontend/nginx.conf

```nginx
server {
  listen 80;
  root /usr/share/nginx/html;
  index index.html;

  location /api/ {
    proxy_pass http://backend:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_read_timeout 120s;
  }

  location / {
    try_files $uri $uri/ /index.html;
  }
}
```

---

## frontend/package.json

```json
{
  "name": "vuln-lab",
  "version": "0.0.1",
  "scripts": {
    "ng": "ng",
    "start": "ng serve --host 0.0.0.0 --port 4200",
    "build": "ng build",
    "watch": "ng build --watch --configuration development"
  },
  "dependencies": {
    "@angular/animations": "^17.3.0",
    "@angular/cdk": "^17.3.0",
    "@angular/common": "^17.3.0",
    "@angular/compiler": "^17.3.0",
    "@angular/core": "^17.3.0",
    "@angular/forms": "^17.3.0",
    "@angular/material": "^17.3.0",
    "@angular/platform-browser": "^17.3.0",
    "@angular/platform-browser-dynamic": "^17.3.0",
    "@angular/router": "^17.3.0",
    "rxjs": "~7.8.0",
    "tslib": "^2.3.0",
    "zone.js": "~0.14.3",
    "prismjs": "^1.29.0"
  },
  "devDependencies": {
    "@angular-devkit/build-angular": "^17.3.0",
    "@angular/cli": "^17.3.0",
    "@angular/compiler-cli": "^17.3.0",
    "@types/prismjs": "^1.26.0",
    "typescript": "~5.4.2"
  }
}
```


## .gitignore

```Í
# Secrets
.env

# Python
__pycache__/
*.pyc
.venv/
venv/

# Node / Angular
node_modules/
dist/
.angular/

# Uploads
backend/uploads/

# IDE
.vscode/
.idea/
```