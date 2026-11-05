# ssb-ruleset-patch

Патч для **IN-нод SSB** (sing-box): добавляет в клиентский шаблон (template.json)
три готовых набора правил из [A-Zuro/sb-rule-sets](https://github.com/A-Zuro/sb-rule-sets).
Применяется **после установки обычного SSB**, одной командой. Правила попадают в
НОВЫЕ конфиги заказов (генерируются ssb-add-order); уже выданные конфиги не меняются.

| Набор | Что делает |
|---|---|
| **bypass-apps** | 530 приложений (банки, Госуслуги, маркетплейсы) идут **мимо VPN** → антифрод приложений не видит «иностранную IP» и не рвёт сессии |
| **encrypted-dns** | DoH/DoT-провайдеры → **reject** — приложение не обойдёт DNS-политику через шифрованный DNS |
| **android-fcm** | Firebase push → **direct** — push-уведомления Android работают при включённом VPN |

## Установка (одна команда, на IN-ноде)

```bash
# только новые конфиги (правила вшиваются при генерации):
curl -fsSL https://raw.githubusercontent.com/Anton98567/ssb-ruleset-patch/main/install.sh | bash

# + внедрить правила в УЖЕ созданные конфиги:
curl -fsSL https://raw.githubusercontent.com/Anton98567/ssb-ruleset-patch/main/install.sh | bash -s -- --existing
```

Обе команды идемпотентны — повторный запуск ничего не дублирует.

## Управление

Устанавливается в `/usr/local/bin/ssb-ruleset-patch`:

| Команда | Что делает |
|---|---|
| `ssb-ruleset-patch apply` | скачать наборы + вшить в template.json (с бэкапом) |
| `ssb-ruleset-patch apply --existing` | то же + внедрить правила в **уже созданные** конфиги (ссылки/пароли не меняются; клиенты подхватят при обновлении подписки/импорте) |
| `ssb-ruleset-patch status` | что применено (наборы, правила, файлы) |
| `ssb-ruleset-patch remove` | полный откат (убрать из шаблона + удалить файлы) |

## Как это работает

1. качает `bypass-apps.json`, `encrypted-dns.json`, `android-fcm.json` из
   A-Zuro/sb-rule-sets в каталог rule-set ноды (рядом с torrent-clients.json)
   и **валидирует** их после скачивания;
2. добавляет их в `template.json` (секции `route.rule_set`, `route.rules`, `dns.rules` —
   рядом с существующим правилом torrent-clients, порядок соблюдается);
3. `ssb-add-order` при генерации конфигов вшивает правила в каждый конфиг;
   клиент подтягивает сами списки по HTTPS с ноды.

Бэкап шаблона — в `/root/bak-template/`. Файлы валидируются перед заменой —
битый/пустой ответ не испортит шаблон.

## Порядок применения

- **новая нода:** установка SSB -> `apply` -> создание заказов (правила попадают в конфиги при генерации);
- **нода с существующими заказами:** `apply --existing` — обновит и шаблон, и уже выданные конфиги.

## Проверка

```bash
ssb-ruleset-patch status
# затем создать тестовый конфиг и убедиться, что в нём появились rule_set:
#   ssb-add-order <ORDER> 1 <out> name=ruletest
#   jq '[.route.rule_set[].tag]' /var/www/*/ORDER-*-ruletest-TRJ-CLIENT.json
```

## Совместимость

- IN-ноды SSB (структура webdir + template.json + каталог rule-set с torrent-clients.json);
- Ubuntu 22.04/24.04, Debian; требует python3 и curl; root.

Списки — [A-Zuro/sb-rule-sets](https://github.com/A-Zuro/sb-rule-sets) (BSD-2-Clause).
