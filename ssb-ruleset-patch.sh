#!/bin/bash
# ssb-ruleset-patch — добавляет в клиентский шаблон IN-ноды (template.json) наборы
# правил из A-Zuro/sb-rule-sets для НОВЫХ конфигов (старые конфиги по умолчанию не
# трогаются — правила вшиваются в конфиг при генерации):
#   bypass-apps   — 530 приложений (банки/Госуслуги/маркетплейсы) -> direct
#                   (антифрод приложений не видит «иностранную IP»)
#   encrypted-dns — DoH/DoT-провайдеры -> reject (закрыть обход DNS-политики)
#   android-fcm   — Firebase push -> direct (уведомления Android не глючат)
#
# Запускать НА IN-ноде от root. Для раскатки на другую ноду — просто повторить там.
# Команды:
#   ssb-ruleset-patch.sh apply [--existing] — скачать наборы + прописать в template.json;
#                        --existing дополнительно внедряет правила в УЖЕ созданные
#                        конфиги (*-CLIENT.json в webdir). Ссылки и пароли не меняются,
#                        меняется только маршрутизация; клиенты подхватят изменения при
#                        обновлении подписки/повторном импорте конфига.
#   ssb-ruleset-patch.sh status   — что применено
#   ssb-ruleset-patch.sh remove   — убрать наборы из шаблона (файлы удалить)
#
# Порядок для новой ноды: установка SSB -> ssb-ruleset-patch apply -> создание заказов.
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
    # дубликаты НЕ создаем: правило добавляется, только если тега ещё нет
    rules_now = c["route"]["rules"]
    have_rule = lambda t: any((x.get("rule_set") or [None])[0] == t for x in rules_now)
    route_new = [r for _, r, _ in NEW if r and not have_rule((r.get("rule_set") or [None])[0])]
    c["route"]["rules"] = insert_after(rules_now, is_tc, route_new)
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

# --- внедрение правил в УЖЕ созданные конфиги (веб-файлы *-CLIENT.json) ---
cmd_existing() {
    local WEBDIR
    WEBDIR=$(dirname "$TPL")
    local bak="$BAKDIR/existing-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$bak"
    cp -a "$WEBDIR"/*-CLIENT.json "$bak"/ 2>/dev/null || true
    echo "бэкап существующих конфигов: $bak"
    python3 - "$WEBDIR" <<'PYEOF'
import json, os, re, sys
webdir = sys.argv[1]
NEW = [
    ("bypass-apps",   {"rule_set": ["bypass-apps"], "outbound": "direct"},
                      {"rule_set": ["bypass-apps"], "server": "dns-local"}),
    ("encrypted-dns", {"rule_set": ["encrypted-dns"], "action": "reject", "method": "drop"},
                      None),
    ("android-fcm",   {"rule_set": ["android-fcm"], "outbound": "direct"},
                      {"rule_set": ["android-fcm"], "server": "dns-local"}),
]
patched = skipped = 0
for fn in sorted(os.listdir(webdir)):
    if not fn.endswith("-CLIENT.json"):
        continue
    path = os.path.join(webdir, fn)
    try:
        c = json.load(open(path))
    except Exception:
        continue
    rs = c.setdefault("route", {}).setdefault("rule_set", [])
    if "bypass-apps" in {x.get("tag") for x in rs}:
        skipped += 1
        continue
    base = None
    for x in rs:
        m = re.match(r"^(.*/)[^/]+\.json$", x.get("url", ""))
        if m:
            base = m.group(1)
            break
    if not base:
        print(f"  {fn}: пропущен (нет url наборов)")
        continue
    for tag, _, _ in NEW:
        rs.append({"type": "remote", "tag": tag, "format": "source", "url": base + tag + ".json"})
    is_tc = lambda r: (r.get("rule_set") or [None])[0] == "torrent-clients"
    rules = c["route"]["rules"]
    idx = next((i for i, r in enumerate(rules) if is_tc(r)), 0)
    c["route"]["rules"] = rules[:idx+1] + [r for _, r, _ in NEW if r] + rules[idx+1:]
    dns_rules = c.setdefault("dns", {}).setdefault("rules", [])
    dns_new = [d for _, _, d in NEW if d and not any(
        (x.get("rule_set") or [None])[0] == (d.get("rule_set") or [None])[0] for x in dns_rules)]
    didx = next((i for i, r in enumerate(dns_rules) if is_tc(r)), len(dns_rules) - 1)
    c["dns"]["rules"] = dns_rules[:didx+1] + dns_new + dns_rules[didx+1:]
    json.dump(c, open(path, "w"), indent=2, ensure_ascii=False)
    patched += 1
print(f"  существующих конфигов обновлено: {patched}, пропущено (уже с правилами): {skipped}")
PYEOF
}

cmd_apply() {
    local existing=0
    [[ "${1:-}" == "--existing" ]] && existing=1
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
        echo "  $s: скачан и проверен"
    done
    [[ $ok == 1 ]] || { echo "часть наборов не скачалась — шаблон НЕ тронут"; rm -f "$RDIR"/*.tmp; exit 1; }
    patch_tpl apply
    echo "Готово. Правила действуют для НОВЫХ заказов (ssb-add-order)."
    [[ $existing == 1 ]] && cmd_existing
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
    apply)  shift; cmd_apply "${1:-}" ;;
    remove) cmd_remove ;;
    status) cmd_status ;;
    *) echo "Использование: ssb-ruleset-patch.sh {apply [--existing]|remove|status}"; exit 1 ;;
esac
