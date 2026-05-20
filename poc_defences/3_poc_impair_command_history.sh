#!/bin/bash
# POC: Impair Command History Logging (T1562.003)
# Triggers: impair-command-history detector
# Description: Accesses and modifies shell command history files

echo "[*] POC: Impair Command History Logging (T1562.003)"
echo "[*] This script demonstrates command history tampering detection"
echo ""

# Get current user
CURRENT_USER=$(whoami)
HOME_DIR=$(eval echo ~$CURRENT_USER)

# List of history files to check
HISTORY_FILES=(
    "$HOME_DIR/.bash_history"
    "$HOME_DIR/.zsh_history"
    "$HOME_DIR/.history"
    "$HOME_DIR/.ksh_history"
    "$HOME_DIR/.sh_history"
    "$HOME_DIR/.tcsh_history"
    "$HOME_DIR/.fish_history"
)

echo "[*] Attempting to access shell command history files..."
for history_file in "${HISTORY_FILES[@]}"; do
    if [[ -f "$history_file" ]]; then
        echo "[*] Found and accessing: $history_file"
        wc -l "$history_file" 2>/dev/null || true
    fi
done

# Attempt to view current shell's history
echo "[*] Attempting to view current shell history..."
if [[ -n "$BASH" ]]; then
    history | head -3 2>/dev/null || true
elif [[ -n "$ZSH_NAME" ]]; then
    history | head -3 2>/dev/null || true
fi

# Simulate history tampering by creating temporary history entries
echo "[*] Creating temporary history test entry..."
TEST_HISTORY="$HOME_DIR/.bash_history.test"
echo "# POC test entry - command history tampering detection" > "$TEST_HISTORY"
echo "id" >> "$TEST_HISTORY"
rm -f "$TEST_HISTORY"

# Attempt to clear history (without actually clearing it)
echo "[*] Demonstrating history clearing command (not executing)..."
echo "[*] Command that would clear history: history -c && history -w"

echo ""
echo "[+] POC complete - detector should have fired for history file access"
