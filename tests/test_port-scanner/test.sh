#!/usr/bin/env bash

# test.sh — Abre puertos de prueba con netcat (OpenBSD), ejecuta el escáner
#           y verifica si detecta esos puertos correctamente.

set -euo pipefail

echo "🔍 Verificando que no haya puertos abiertos antes del test..."

# if ../../bin/port-scanner | grep -v -E '^$'; then
#   echo "⚠️  Hay puertos abiertos antes de iniciar la prueba. Limpia primero."
#   exit 1
# fi

# --- Configuración ---
PORTS=(22 3306 631 4080 1025)
NC_PIDS=()

# --- Abrir puertos con netcat (versión OpenBSD, sin -p) ---
echo "🚀 Abriendo puertos de prueba: ${PORTS[*]}"
for p in "${PORTS[@]}"; do
  nc -l "$p" &> /dev/null &
  NC_PIDS+=($!)
done

# --- Esperar que los puertos se levanten ---
sleep 2

# --- Ejecutar escáner ---
echo "🔎 Ejecutando escáner de puertos..."
OUTPUT=$(../../bin/port-scanner)

# --- Verificación ---
echo "🧪 Verificando resultados del escáner..."
ALL_OK=true

for p in "${PORTS[@]}"; do
  if echo "$OUTPUT" | grep -qE "^$p\b"; then
    echo "  ✅ Puerto $p detectado correctamente."
  else
    echo "  ❌ ERROR: Puerto $p NO fue detectado."
    ALL_OK=false
  fi
done

# --- Limpiar procesos ---
echo "🧹 Cerrando listeners..."
for pid in "${NC_PIDS[@]}"; do
  kill "$pid" 2>/dev/null || true
done

# --- Resultado final ---
if $ALL_OK; then
  echo "🎉 Todas las pruebas pasaron correctamente."
  exit 0
else
  echo "❗ Al menos una prueba falló."
  exit 1
fi
