#!/bin/bash
# Установка ssb-ruleset-patch на IN-ноду SSB одной командой:
#
#   # только новые конфиги (правила вшиваются при генерации):
#   curl -fsSL https://raw.githubusercontent.com/Anton98567/ssb-ruleset-patch/main/install.sh | bash
#
#   # + внедрить правила в УЖЕ созданные конфиги:
#   curl -fsSL https://raw.githubusercontent.com/Anton98567/ssb-ruleset-patch/main/install.sh | bash -s -- --existing
#
# Что делает: кладёт утилиту /usr/local/bin/ssb-ruleset-patch и применяет наборы
# правил (bypass-apps, encrypted-dns, android-fcm) к template.json ноды;
# флаг --existing дополнительно обновляет уже выданные конфиги (ссылки/пароли
# не меняются; клиенты подхватят при обновлении подписки/импорте).
set -euo pipefail

REPO="https://raw.githubusercontent.com/Anton98567/ssb-ruleset-patch/main"
BIN=/usr/local/bin/ssb-ruleset-patch

[[ $EUID -eq 0 ]] || { echo "ОШИБКА: нужен root (sudo bash)"; exit 1; }

echo "Качаю утилиту..."
curl -fsSL "$REPO/ssb-ruleset-patch.sh" -o "$BIN"
chmod 755 "$BIN"
bash -n "$BIN"

echo "Применяю наборы правил..."
exec "$BIN" apply "$@"
