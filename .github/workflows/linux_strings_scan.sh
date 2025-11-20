#!/usr/bin/env bash

set -euo pipefail

DATE_TAG="$(date +%Y%m%d_%H%M%S)"
BASE_DIR="/root/ccdc_hardening"
OUT_DIR="$BASE_DIR/suspicious_strings_$DATE_TAG"
mkdir -p "$OUT_DIR"

echo "[*] Logs: $OUT_DIR"

TARGET_DIRS=(
    "/usr/bin"
    "/usr/sbin"
    "/bin"
    "/sbin"
)

echo "[*] Searching system binaries for suspicious strings..."
for dir in "${TARGET_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        outfile="$OUT_DIR/strings_$(basename $dir)_$DATE_TAG.txt"
        echo "[*] Scanning $dir ..."
        for f in "$dir"/*; do
            if [[ -f "$f" && -x "$f" ]]; then
                strings "$f" 2>/dev/null | \
                    grep -Ei "password|secret|token|key=|aws_|session|backdoor|connect|socket|/bin/sh|/bin/bash|wget|curl|nc|netcat|reverse|shell" \
                    && echo "--- $f" 
            fi
        done > "$outfile"
    fi
done

echo "[*] Checking SUID/SGID binaries..."
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | \
while read suid; do
    strings "$suid" 2>/dev/null | \
        grep -Ei "password|secret|key|token|cmd|bash|/tmp|sh -c|evil|shadow|crypt" \
        && echo "--- $suid"
done > "$OUT_DIR/suid_strings_$DATE_TAG.txt"

echo "[*] Checking web directories for suspicious code..."
if [[ -d /var/www ]]; then
    grep -Rin --binary-files=without-match \
        -E "password|secret|cmd|shell_exec|system\(|passthru|base64_decode|eval\(|exec\(" \
        /var/www > "$OUT_DIR/web_suspicious_strings_$DATE_TAG.txt" 2>/dev/null || true
fi

echo "[+] Linux suspicious strings scan complete."
echo "[+] Results stored in: $OUT_DIR"
