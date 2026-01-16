#!/bin/bash
# debug-sequential.sh

echo "=== SCRIPT START: $(date) ==="

ALL_ARGS=("$@")

# Filter logic (sama)
CLEAN_ARGS=()
SKIP=false
for arg in "${ALL_ARGS[@]}"; do
    if [ "$SKIP" = true ]; then
        SKIP=false
        continue
    fi
    case "$arg" in
        "--script"|"--exec-script") SKIP=true ;;
        --script=*|--exec-script=*) ;;
        *) CLEAN_ARGS+=("$arg") ;;
    esac
done
CLEAN_ARGS=("${CLEAN_ARGS[@]:1}")

# Remove protocol flags
NO_PROTO_ARGS=()
for arg in "${CLEAN_ARGS[@]}"; do
    case "$arg" in
        "--ssh"|"--ftp"|"--telnet") continue ;;
        *) NO_PROTO_ARGS+=("$arg") ;;
    esac
done

echo "Time before SSH: $(date)"
echo "=== STARTING SSH SCAN ==="
./minotaur "${NO_PROTO_ARGS[@]}" --ssh --output=debug-ssh.csv
echo "SSH finished at: $(date)"

echo "=== STARTING FTP SCAN ==="
./minotaur "${NO_PROTO_ARGS[@]}" --ftp --output=debug-ftp.csv
echo "FTP finished at: $(date)"

echo "=== SCRIPT END: $(date) ==="
