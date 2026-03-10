# ⚡ PyZapret — DPI Bypass Tool (Windows)

Графический интерфейс для обхода DPI-блокировок на Windows.  
Поддерживает два движка: **winws.exe** (zapret) и встроенный **pydivert**.

---

## 📁 Структура папки

```
твоя_папка/
├── bin/
│   ├── winws.exe
│   ├── quic_initial_www_google_com.bin
│   ├── tls_clienthello_www_google_com.bin
│   ├── tls_clienthello_4pda_to.bin
│   ├── tls_clienthello_max_ru.bin
│   ├── stun.bin
│   └── ...
├── lists/
│   ├── list-general.txt
│   ├── list-general-user.txt
│   ├── list-google.txt
│   ├── list-exclude.txt
│   ├── list-exclude-user.txt
│   ├── ipset-all.txt
│   ├── ipset-exclude.txt
│   └── ...
├── pyzapret.py        ← главный файл
├── service.bat        ← (опционально) загрузка GameFilter
└── README.md
```

> Папки `bin/` и `lists/` определяются автоматически относительно `pyzapret.py` — ничего настраивать не нужно.

---

## 🔧 Требования

| Компонент | Версия | Обязательно |
|-----------|--------|-------------|
| Windows | 10 / 11 | ✅ |
| Python | 3.10+ | ✅ |
| Права Администратора | — | ✅ |
| winws.exe (zapret) | последняя | для движка WinWS |
| pydivert | `pip install pydivert` | для движка PyDivert |
| ttkbootstrap | `pip install ttkbootstrap` | нет (но улучшает вид) |

---

## 🚀 Установка и запуск

### 1. Установить зависимости Python

```bash
pip install pydivert ttkbootstrap
```

### 2. Положить файлы на место

Скопируйте `winws.exe` и `.bin`-файлы в папку `bin/`,  
списки хостов и ipset — в папку `lists/`.

### 3. Запустить от имени Администратора

```bash
# Правой кнопкой → "Запуск от имени администратора"
python pyzapret.py
```

Или через PowerShell (Admin):
```powershell
python pyzapret.py
```

> ⚠️ Без прав администратора WinDivert / winws.exe не запустятся.

---

## 🖥️ Интерфейс

### Выбор движка

| Движок | Описание |
|--------|----------|
| **winws.exe** | Запускает оригинальный zapret. Рекомендуется — более мощный, поддерживает UDP/QUIC, ipset, hostlist |
| **pydivert** | Встроенный Python-движок. Работает без `winws.exe`, только TCP |

---

### Вкладка WinWS (zapret)

| Поле | Описание |
|------|----------|
| Папка bin/ | Путь к `winws.exe` и `.bin`-файлам. Определяется автоматически |
| Папка lists/ | Путь к спискам хостов и ipset. Определяется автоматически |
| GameFilter TCP/UDP | Дополнительные игровые порты. Если пусто — загружается из `service.bat` автоматически |
| WF TCP/UDP extra | Дополнительные порты WinDivert фильтра |
| Группы правил | Включение/отключение отдельных групп обхода |

#### Группы правил

| Группа | Что обходит |
|--------|-------------|
| YouTube / Discord | QUIC UDP 443, Discord TCP/UDP (порты 2053, 2083, 2087, 2096, 8443) |
| Google | TCP 443 по `list-google.txt` с `--ip-id=zero` |
| General HTTP/S | TCP 80/443 по `list-general.txt` и `list-general-user.txt` |
| QUIC ipset | UDP 443 по `ipset-all.txt` |
| ipset TCP | TCP 80/443/8443 по `ipset-all.txt` |
| Game TCP | Порты из GameFilterTCP по ipset |
| Game UDP | Порты из GameFilterUDP по ipset |

---

### Вкладка PyDivert

| Параметр | Описание |
|----------|----------|
| Стратегия | Метод обхода (см. ниже) |
| Порты | TCP-порты для перехвата (через запятую) |
| Split position | Позиция разреза пакета (`auto` — по SNI/Host) |
| Fake TTL | TTL для фейковых пакетов (обычно 1) |

#### Стратегии PyDivert

| Стратегия | Как работает |
|-----------|--------------|
| `split` | Разрезает TCP-сегмент на 2 части — DPI видит неполный заголовок |
| `disorder` | То же, но сегменты отправляются в **обратном порядке** |
| `fake` | Перед настоящим пакетом шлёт «мусорный» с TTL=1 (до сервера не доходит) |
| `fakedsplit` | Комбо: fake + split для каждого чанка. Максимальный обход |

#### Пресеты

| Пресет | Для чего |
|--------|----------|
| YouTube/Discord | Порт 443, стратегия disorder |
| HTTP Sites | Порт 80, стратегия split |
| Max Bypass | Порты 80+443, стратегия fakedsplit |
| Gentle | Порты 80+443, стратегия fake |

---

## 📋 Лог

- Цветовая подсветка по уровням: INFO / SUCCESS / WARNING / ERROR
- Выделение TLS и HTTP пакетов отдельными цветами
- Счётчики пакетов: всего / TLS / HTTP
- Кнопка **Clear** — очистить лог и счётчики
- Чекбокс **Auto-scroll** — автопрокрутка к новым записям

---

## ❓ Частые проблемы

**`WinDivert error` при старте**
→ Запустите от имени Администратора.  
→ Убедитесь, что `pydivert` установлен: `pip install pydivert`.

**`winws.exe не найден`**
→ Убедитесь, что `bin/winws.exe` существует рядом с `pyzapret.py`.

**Сайты по-прежнему не открываются**
→ Попробуйте другую стратегию или активируйте больше групп правил.  
→ Убедитесь, что нужный хост присутствует в `lists/list-general.txt`.  
→ Для UDP/QUIC используйте движок WinWS — PyDivert работает только с TCP.

**`GameFilter` не загружается**
→ Введите порты вручную в полях `GameFilter TCP/UDP`.  
→ Или положите `service.bat` в папку рядом с `pyzapret.py`.

---

## 📝 Пользовательские списки

| Файл | Назначение |
|------|------------|
| `lists/list-general-user.txt` | Добавить свои домены в общий список |
| `lists/list-exclude-user.txt` | Исключить домены из обхода |
| `lists/list-google.txt` | Домены Google (специальная обработка) |
| `lists/ipset-all.txt` | IP-адреса для обхода |
| `lists/ipset-exclude.txt` | IP-адреса, исключённые из обхода |

Формат — по одному домену или IP/CIDR на строку.

---

## ⚖️ Лицензия и ответственность

Программа предназначена для обхода технических ограничений в личных целях.  
Используйте в соответствии с законодательством вашей страны.  
Авторы не несут ответственности за возможные последствия использования.
