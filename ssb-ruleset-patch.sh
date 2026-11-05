#!/bin/bash
# ssb-ruleset-patch — добавляет в клиентский шаблон IN-ноды (template.json) наборы
# правил из A-Zuro/sb-rule-sets для НОВЫХ конфигов (старые конфиги не трогаются —
# правила вшиваются в конфиг при генерации):
#   bypass-apps   — 530 приложений (банки/Госуслуги/маркетплейсы) -> direct
#                   (антифрод приложений не видит «иностранную IP»)
#   encrypted-dns — DoH/DoT-провайдеры -> reject (закрыть обход DNS-политики)
#   android-fcm   — Firebase push -> direct (уведомления Android не глючат)
#
# Запускать НА IN-ноде от root. Для раскатки на другую ноду — просто повторить там.
# Команды:
#   ssb-ruleset-patch.sh apply    — скачать наборы + прописать в template.json
#   ssb-ruleset-patch.sh status   — что применено
#   ssb-ruleset-patch.sh remove   — убрать наборы из шаблона (файлы удалить)
#
# Источник: https://github.com/A-Zuro/sb-rule-sets (файлы валидируются после скачивания).
# Правила добавляются рядом с существующим torrent-clients (порядок важен: специфичные
# правила идут до широких .ru-правил).

set -euo pipefail

SRC="https://raw.githubusercontent.com/A-Zuro/sb-rule-sets/main"
SETS=(bypass-apps encrypted-dns android-fcm)
BAKDIR="/root/bak-template"

die() { echo "ОШИБКА: $*"; exit 1; }
[[ $EUID -eq 0 ]] || die "нужен root"

TPL=$(find /var/www -maxdepth 2 -name template.json 2>/dev/null | head -1)
[[ -n $TPL ]] || die "template.json не найден"
RDIRFILE=$(find /var/www -maxdepth 2 -name torrent-clients.json 2>/dev/null | head -1)
[[ -n $RDIRFILE ]] || die "не найден каталог rule-set (torrent-clients.json)"
RDIR=$(dirname "$RDIRFILE")

echo "template:  $TPL"
echo "rule-sets: $RDIR"

# --- python-патчер шаблона (apply|remove) ---
patch_tpl() {
    python3 - "$TPL" "$1" <<'PYEOF'
import json, sys
tpl, action = sys.argv[1], sys.argv[2]
with open(tpl) as f:
    c = json.load(f)

NEW = [
    ("bypass-apps",   {"rule_set": ["bypass-apps"], "outbound": "direct"},
                      {"rule_set": ["bypass-apps"], "server": "dns-local"}),
    ("encrypted-dns", {"rule_set": ["encrypted-dns"], "action": "reject", "method": "drop"},
                      None),
    ("android-fcm",   {"rule_set": ["android-fcm"], "outbound": "direct"},
                      {"rule_set": ["android-fcm"], "server": "dns-local"}),
]

def insert_after(rules, pred, items):
    idx = next((i for i, r in enumerate(rules) if pred(r)), 0)
    return rules[:idx+1] + items + rules[idx+1:]

if action == "apply":
    have = {rs.get("tag") for rs in c.setdefault("route", {}).setdefault("rule_set", [])}
    for tag, rrule, _ in NEW:
        if tag not in have:
            c["route"]["rule_set"].append({
                "type": "remote", "tag": tag, "format": "source",
                "url": f"https://DOMAIN/RULESETPATH/{tag}.json",
            })
    is_tc = lambda r: (r.get("rule_set") or [None])[0] == "torrent-clients"
    c["route"]["rules"] = insert_after(c["route"]["rules"], is_tc,
                                       [r for _, r, _ in NEW if r])
    dns_rules = c.setdefault("dns", {}).setdefault("rules", [])
    dns_new = [d for _, _, d in NEW if d and not any(
        (x.get("rule_set") or [None])[0] == (d.get("rule_set") or [None])[0] for x in dns_rules)]
    c["dns"]["rules"] = insert_after(dns_rules, is_tc, dns_new)
elif action == "remove":
    tags = {t for t, _, _ in NEW}
    c["route"]["rule_set"] = [rs for rs in c["route"].get("rule_set", [])
                              if rs.get("tag") not in tags]
    hit = lambda r: (r.get("rule_set") or [None])[0] in tags
    c["route"]["rules"] = [r for r in c["route"].get("rules", []) if not hit(r)]
    if "dns" in c:
        c["dns"]["rules"] = [r for r in c["dns"].get("rules", []) if not hit(r)]

with open(tpl, "w") as f:
    json.dump(c, f, indent=2, ensure_ascii=False)
print(f"template.json: {action} OK")
PYEOF
}

cmd_apply() {
    mkdir -p "$BAKDIR"
    local bak="$BAKDIR/template.json.bak-$(date +%Y%m%d-%H%M%S)"
    cp -a "$TPL" "$bak"
    echo "backup: $bak"
    local ok=1
    for s in "${SETS[@]}"; do
        if ! curl -fsS "$SRC/$s.json" -o "$RDIR/$s.json.tmp"; then
            echo "  $s: ОШИБКА скачивания"; ok=0; continue
        fi
        if ! python3 -c "import json,sys; d=json.load(open(sys.argv[1])); assert d.get('rules'), 'no rules'" "$RDIR/$s.json.tmp" 2>/dev/null; then
            echo "  $s: ОШИБКА валидации (не JSON / нет rules)"; ok=0; rm -f "$RDIR/$s.json.tmp"; continue
        fi
        mv "$RDIR/$s.json.tmp" "$RDIR/$s.json"
        chmod 644 "$RDIR/$s.json"
        echo "  $s: скачан ($(grep -c 'package_name\|domain\|port' "$RDIR/$s.json" 2>/dev/null || echo '?') строк-записей)"
    done
    [[ $ok == 1 ]] || { echo "часть наборов не скачалась — шаблон НЕ тронут"; rm -f "$RDIR"/*.tmp; exit 1; }
    patch_tpl apply
    echo "Готово. Правила действуют для НОВЫХ заказов (ssb-add-order)."
    cmd_status
}

cmd_remove() {
    patch_tpl remove
    for s in "${SETS[@]}"; do rm -f "$RDIR/$s.json"; done
    echo "Наборы убраны из шаблона и удалены из каталога rule-set."
}

cmd_status() {
    echo "=== ssb-ruleset-patch status ==="
    python3 - "$TPL" <<'PYEOF'
import json, sys
c = json.load(open(sys.argv[1]))
tags = {rs.get("tag") for rs in c.get("route", {}).get("rule_set", [])}
for t in ("torrent-clients", "bypass-apps", "encrypted-dns", "android-fcm"):
    in_route = any((r.get("rule_set") or [None])[0] == t for r in c.get("route", {}).get("rules", []))
    in_dns = any((r.get("rule_set") or [None])[0] == t for r in c.get("dns", {}).get("rules", []))
    state = "ЕСТЬ" if t in tags else "нет"
    print(f"  {t}: {state} (route-rule: {'+' if in_route else '-'}, dns-rule: {'+' if in_dns else '-'})")
PYEOF
    for s in "${SETS[@]}"; do
        [[ -f $RDIR/$s.json ]] && echo "  файл $s.json: есть ($(stat -c%s "$RDIR/$s.json") байт)" || echo "  файл $s.json: НЕТ"
    done
}

case "${1:-}" in
    apply)  cmd_apply ;;
    remove) cmd_remove ;;
    status) cmd_status ;;
    *) echo "Использование: ssb-ruleset-patch.sh {apply|remove|status}"; exit 1 ;;
esac
