#!/bin/bash
# Установка ssb-ruleset-patch на IN-ноду SSB одной командой:
#
#   curl -fsSL https://raw.githubusercontent.com/Anton98567/ssb-ruleset-patch/main/install.sh | bash
#
# Что делает: кладёт утилиту /usr/local/bin/ssb-ruleset-patch и сразу применяет
# наборы правил (bypass-apps, encrypted-dns, android-fcm) к template.json ноды —
# новые конфиги заказов будут содержать правила, старые не меняются.
set -euo pipefail

REPO="https://raw.githubusercontent.com/Anton98567/ssb-ruleset-patch/main"
BIN=/usr/local/bin/ssb-ruleset-patch

[[ $EUID -eq 0 ]] || { echo "ОШИБКА: нужен root (sudo bash)"; exit 1; }

echo "Качаю утилиту..."
curl -fsSL "$REPO/ssb-ruleset-patch.sh" -o "$BIN"
chmod 755 "$BIN"
bash -n "$BIN"

echo "Применяю наборы правил..."
exec "$BIN" apply
