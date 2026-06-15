#!/usr/bin/env zsh

# ─────────────────────────────────────────
# start-project.sh — Start Ollama + VulnLab
# macOS zsh
# ─────────────────────────────────────────

echo ""
echo "══════════════════════════════════════"
echo "   VulnLab — Project Startup"
echo "══════════════════════════════════════"

# ─────────────────────────────────────────
# 1. OLLAMA
# ─────────────────────────────────────────
echo ""
echo "🦙 [1/3] Starting Ollama + llama3.2..."

if ! command -v ollama &> /dev/null; then
  echo "❌ Ollama not installed. Run: brew install ollama"
  exit 1
fi

if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
  echo "✅ Ollama already running"
else
  echo "▶ Starting Ollama server..."
  ollama serve &> /tmp/ollama.log &

  echo "⏳ Waiting for Ollama..."
  for i in {1..15}; do
    if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
      echo "✅ Ollama ready (${i}s)"
      break
    fi
    sleep 1
    if [[ $i == 15 ]]; then
      echo "❌ Ollama failed. Check: cat /tmp/ollama.log"
      exit 1
    fi
  done
fi

if ollama list 2>/dev/null | grep -q "llama3.2"; then
  echo "✅ llama3.2 already available"
else
  echo "📥 Pulling llama3.2 (~2GB first time)..."
  ollama pull llama3.2
  if [[ $? -ne 0 ]]; then
    echo "❌ Failed to pull llama3.2"
    exit 1
  fi
fi

# Quick test
RESPONSE=$(curl -s http://localhost:11434/api/generate \
  -d '{"model":"llama3.2","prompt":"reply with OK only","stream":false}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('response','').strip())" 2>/dev/null)

if [[ -n "$RESPONSE" ]]; then
  echo "✅ llama3.2 responding"
else
  echo "⚠️  llama3.2 no response yet — will be ready shortly"
fi

# ─────────────────────────────────────────
# 2. DOCKER COMPOSE (VulnLab + Juice Shop)
# ─────────────────────────────────────────
echo ""
echo "🐳 [2/3] Starting VulnLab + Juice Shop via Docker Compose..."

cd "$(dirname "$0")"

if ! command -v docker &> /dev/null; then
  echo "❌ Docker not installed or not running"
  exit 1
fi

docker-compose up -d --build
if [[ $? -ne 0 ]]; then
  echo "❌ Docker Compose failed"
  exit 1
fi

# ─────────────────────────────────────────
# 3. WAIT FOR SERVICES
# ─────────────────────────────────────────
echo ""
echo "⏳ [3/3] Waiting for services to be ready..."

# Wait for backend
echo "   Waiting for backend..."
for i in {1..30}; do
  if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo "   ✅ Backend ready (${i}s)"
    break
  fi
  sleep 1
  if [[ $i == 30 ]]; then
    echo "   ⚠️  Backend slow — check: docker-compose logs backend"
  fi
done

# Wait for Juice Shop
echo "   Waiting for Juice Shop..."
for i in {1..30}; do
  if curl -s http://localhost:3000 > /dev/null 2>&1; then
    echo "   ✅ Juice Shop ready (${i}s)"
    break
  fi
  sleep 1
  if [[ $i == 30 ]]; then
    echo "   ⚠️  Juice Shop slow — check: docker-compose logs juice-shop"
  fi
done

# ─────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────
echo ""
echo "══════════════════════════════════════"
echo "✅ All services ready"
echo "══════════════════════════════════════"
echo ""
echo "🌐 VulnLab       : http://localhost:4200"
echo "⚙️  Backend API   : http://localhost:8000"
echo "🧃 Juice Shop    : http://localhost:3000"
echo "🦙 Ollama        : http://localhost:11434"
echo ""
echo "📋 Scan Juice Shop using:"
echo "   http://juice-shop:3000"
echo ""
echo "📜 Logs:"
echo "   docker-compose logs -f"
echo "══════════════════════════════════════"

# ─────────────────────────────────────────
# ELK STACK
# ─────────────────────────────────────────
echo ""
echo "⏳ Waiting for Elasticsearch..."
for i in {1..30}; do
  if curl -s http://localhost:9200/_cluster/health 2>/dev/null | grep -q '"status"'; then
    echo "   ✅ Elasticsearch ready (${i}×2s)"
    break
  fi
  sleep 2
  if [[ $i == 30 ]]; then
    echo "   ⚠️  Elasticsearch slow — check: docker-compose logs elasticsearch"
  fi
done

echo "⏳ Waiting for Kibana..."
for i in {1..40}; do
  if curl -s http://localhost:5601/api/status 2>/dev/null | grep -q "available"; then
    echo "   ✅ Kibana ready (${i}×3s)"
    break
  fi
  sleep 3
  if [[ $i == 40 ]]; then
    echo "   ⚠️  Kibana slow — check: docker-compose logs kibana"
  fi
done

echo "🗂  Setting up Kibana index patterns..."
bash "$(dirname "$0")/monitoring/kibana/setup.sh"

echo ""
echo "📊 Kibana dashboard : http://localhost:5601"
echo "🔍 Elasticsearch   : http://localhost:9200"