#!/usr/bin/env bash

set -e

# -----------------------------
# CONFIGURAZIONE
# -----------------------------
NUM_CLIENTS=10     # Numero di client da avviare
SUPERLINK_PORT=9092
CLIENTAPI_BASE_PORT=9095

CERT_CA="certificates/ca.crt"
CERT_SERVER="certificates/server.pem"
CERT_KEY="certificates/server.key"

FEDERATION_NAME="my-federation"

# -----------------------------
# 1. AVVIA SUPERLINK
# -----------------------------
echo "Avvio flower-superlink..."

flower-superlink \
  --ssl-ca-certfile "$CERT_CA" \
  --ssl-certfile "$CERT_SERVER" \
  --ssl-keyfile "$CERT_KEY" \
  --enable-supernode-auth &

SUPERLINK_PID=$!
echo "Superlink avviato (PID $SUPERLINK_PID)"
sleep 2

# -----------------------------
# 2. REGISTRA I CLIENT
# -----------------------------
echo "Registrazione dei client nella federation..."

for i in $(seq 1 $NUM_CLIENTS); do
  PUBKEY="keys/client_credentials_${i}.pub"
  echo "  - Registrazione client $i con pubkey $PUBKEY"
  flwr supernode register "$PUBKEY" . "$FEDERATION_NAME"
done

# -----------------------------
# 3. AVVIA I SUPERNODE (CLIENT)
# -----------------------------
echo "Avvio dei supernode-client..."

for i in $(seq 1 $NUM_CLIENTS); do
  PRIVKEY="keys/client_credentials_${i}"
  DATASET="datasets/cifar10_part_${i}"
  API_PORT=$((CLIENTAPI_BASE_PORT + i - 1))

  echo "  - Avvio supernode client $i (dataset $DATASET, API port $API_PORT)"

  flower-supernode \
    --root-certificates "$CERT_CA" \
    --auth-supernode-private-key "$PRIVKEY" \
    --superlink "127.0.0.1:${SUPERLINK_PORT}" \
    --node-config "dataset-path=\"$DATASET\" num-cores=1" \
    --clientappio-api-address="0.0.0.0:${API_PORT}" &
done

echo "Tutti i client sono stati avviati!"
wait
