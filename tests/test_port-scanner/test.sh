#!/usr/bin/env bash
#
# test.sh — abre puertos de prueba con netcat, ejecuta el escáner
#           y verifica que detecta esos puertos.

# 1) Define los puertos que quieres probar
PORTS=(631 22 55)

# 2) Arranca netcat en background para cada puerto
NC_PIDS=()    # array donde guardamos los PID de netcat
for p in "${PORTS[@]}"; do
  # -l : listen, -p : puerto, & : background, &> /dev/null silencia output
  nc -l -p "$p" &> /dev/null &
  NC_PIDS+=($!)    # $! es el PID del último proceso lanzado
done

# 3) Espera un segundo para que netcat levante los listeners
sleep 1

# 4) Ejecuta el escáner y captura su salida
OUTPUT=$(../../bin/port-scanner)

# 5) Comprueba puerto por puerto
echo "🧪 Verificando resultados..."
ALL_OK=true
for p in "${PORTS[@]}"; do
  if echo "$OUTPUT" | grep -q "^$p "; then
    echo "  ✅ Puerto $p detectado."
  else
    echo "  ❌ ERROR: Puerto $p NO detectado."
    ALL_OK=false
  fi
done

# 6) Mata los netcat que arrancaste
for pid in "${NC_PIDS[@]}"; do
  kill "$pid" 2>/dev/null
done

# 7) Exit status según resultado
if $ALL_OK; then
  echo "🎉 Todas las pruebas pasaron."
  exit 0
else
  echo "⚠️  Al menos una prueba falló."
  exit 1
fi
