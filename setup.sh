#!/bin/bash
set -e

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║     NexBank Digital — Lab Setup          ║"
echo "║     RedCIPHER Security Training          ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Add to /etc/hosts
if ! grep -q "nexbank.local" /etc/hosts; then
    echo "[*] Adding nexbank.local to /etc/hosts (requires sudo)..."
    echo "127.0.0.1  nexbank.local" | sudo tee -a /etc/hosts
else
    echo "[✓] nexbank.local already in /etc/hosts"
fi

# Build and start containers
echo "[*] Building Docker containers..."
docker-compose down -v --remove-orphans 2>/dev/null || true
docker-compose up -d --build

echo "[*] Waiting for database to be ready..."
sleep 8

# Seed database
echo "[*] Seeding database..."
docker-compose exec -T app python -c "from seeds.seed_data import seed_all; seed_all()"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  ✅  NexBank Lab is ready!               ║"
echo "╠══════════════════════════════════════════╣"
echo "║  URL:  http://nexbank.local              ║"
echo "║                                          ║"
echo "║  Test Users:                             ║"
echo "║  9100000001 / password123  (customer)    ║"
echo "║  9100000002 / password123  (customer)    ║"
echo "║  9999999999 / Admin@123    (admin)        ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "  Lab Guide: docs/LAB_GUIDE.md"
echo "  Logs:      docker-compose logs -f app"
echo "  Reset:     docker-compose down -v && ./setup.sh"
echo ""
