#!/bin/bash
# This script will generate keys to setup node authentication

set -e
# Change directory to the script's directory
cd "$(dirname "${BASH_SOURCE[0]}")"

KEY_DIR=keys

mkdir -p $KEY_DIR

rm -f $KEY_DIR/*

CURVES=("secp112r1" "secp256k1" "sect571k1")
SIZES=("112" "256" "512")

generate_client_credentials() {
    local num_clients=${1:-2}
    for ((i=1; i<=num_clients; i++))
    do
        local curve_index=$(( (i - 1) % ${#CURVES[@]} ))
        local curve_name=${CURVES[$curve_index]}
        local curve_size=${SIZES[$curve_index]}

        echo "[*] Generating client $i with curve ${curve_name} (${curve_size}-bit)"
        openssl ecparam -name "$curve_name" -genkey -noout \
            -out "${KEY_DIR}/client_credentials_${i}.key"
        openssl ec -in "${KEY_DIR}/client_credentials_${i}.key" -pubout \
            -out "${KEY_DIR}/client_credentials_${i}.pub"
    done
}

generate_client_credentials "$1"

for ((i=1; i<=${1:-2}; i++))
do
    entry="$(openssl base64 -A -in "${KEY_DIR}/client_credentials_${i}.pub")"
    if [ "$i" -eq 1 ]; then
        printf "%s" "$entry" > $KEY_DIR/client_public_keys.csv
    else
        printf ",%s" "$entry" >> $KEY_DIR/client_public_keys.csv
    fi
done
printf "\n" >> $KEY_DIR/client_public_keys.csv
