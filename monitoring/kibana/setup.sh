#!/usr/bin/env bash
# monitoring/kibana/setup.sh
# Creates Kibana index patterns for all VulnLab log indices.
# Run once after Kibana is healthy.

KIBANA="http://localhost:5601"

echo "⏳ Waiting for Kibana to be fully available..."
until curl -s "$KIBANA/api/status" 2>/dev/null | grep -q '"level":"available"'; do
  echo "   Kibana not ready yet..."
  sleep 5
done
echo "✅ Kibana available"

# Create index patterns
for INDEX in vulnlab-scans vulnlab-agent vulnlab-probes vulnlab-results vulnlab-general; do
  echo "   Creating index pattern: ${INDEX}-*"
  curl -s -X POST "$KIBANA/api/index_patterns/index_pattern" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: application/json" \
    -d "{\"index_pattern\":{\"title\":\"${INDEX}-*\",\"timeFieldName\":\"@timestamp\"}}" \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print('   OK:', d.get('index_pattern',{}).get('title','?'))" 2>/dev/null \
    || echo "   (index pattern may already exist)"
done

echo ""
echo "✅ Kibana index patterns created"
echo "   Open: http://localhost:5601"
