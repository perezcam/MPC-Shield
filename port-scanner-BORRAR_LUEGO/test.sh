#!/bin/bash

# Nombre del ejecutable (ajusta si es diferente)
ESCANER="./scanner"
OUT_FILE="salida_escaneo.txt"
EXPECTED_FILE="puertos_esperados.txt"
TMP_SORTED="salida_filtrada.txt"
PASS=true

echo "🧪 Iniciando prueba automatizada del escáner..."

# 1. Activar servicios que abren puertos conocidos
echo "🔧 Iniciando servicios para prueba..."
sudo systemctl start ssh 2>/dev/null
sudo systemctl start cups 2>/dev/null
sudo systemctl start apache2 2>/dev/null

sleep 1  # Esperar que levanten

# 2. Ejecutar escáner
echo "🚀 Ejecutando escáner..."
$ESCANER > "$OUT_FILE"

# 3. Filtrar solo líneas con puertos abiertos
grep -E "^[0-9]+ " "$OUT_FILE" | sort > "$TMP_SORTED"

# 4. Crear archivo de puertos esperados
cat <<EOL > $EXPECTED_FILE
22 SSH
80 HTTP
631 IPP 
EOL

sort "$EXPECTED_FILE" > expected_sorted.txt

# 5. Comparar
echo "🔍 Comparando resultados..."
diff -y --suppress-common-lines "$TMP_SORTED" expected_sorted.txt > diferencias.txt

if [[ -s diferencias.txt ]]; then
    echo "❌ TEST FALLIDO: Diferencias encontradas:"
    cat diferencias.txt
    PASS=false
else
    echo "✅ TEST EXITOSO: Todos los puertos esperados están abiertos y detectados correctamente."
fi

# 6. Limpiar
echo "🧹 Deteniendo servicios de prueba..."
sudo systemctl stop apache2 2>/dev/null
sudo systemctl stop cups 2>/dev/null

echo "🧼 Limpiando archivos temporales..."
rm -f "$OUT_FILE" "$TMP_SORTED" expected_sorted.txt diferencias.txt "$EXPECTED_FILE"

# 7. Resultado
if $PASS; then
    exit 0
else
    exit 1
fi
