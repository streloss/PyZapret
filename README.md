<div align="center">

<img src="https://img.shields.io/badge/Windows-10%2F11-0078D4?style=flat-square&logo=windows&logoColor=white"/>
<img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
<img src="https://img.shields.io/badge/Release-v2.0-blue?style=flat-square"/>
<img src="https://img.shields.io/badge/Requires-Administrator-red?style=flat-square"/>

# ⚡ PyZapret GUI

**Графический инструмент для обхода DPI-блокировок на Windows**

Поддерживает два движка: встроенный Python (`pydivert`) и внешний `winws.exe` от проекта [zapret](https://github.com/bol-van/zapret).

</div>

---

## Возможности

- **Два движка** — `winws.exe` (zapret, рекомендуется) и `pydivert` (встроенный Python-движок)
- **Три стратегии WinWS** — MultiSplit, HostFakeSplit, Original
- **Умная детекция протоколов** — автоматическое определение TLS ClientHello и HTTP-запросов с извлечением SNI и Host
- **Живой лог** с фильтрами по уровню (INFO / WARNING / ERROR / TLS / winws)
- **Статистика пакетов** — счётчики TLS, HTTP и общий uptime
- **Готовые пресеты** для PyDivert (YouTube, Discord, HTTP, Max Bypass)
- **Тонкая настройка** — группы правил, GameFilter TCP/UDP, кастомные WF-порты
- **Тёмный UI** в стиле Windows 11, без внешних зависимостей для интерфейса

---

## Стратегии WinWS

| Стратегия | Метод | Подходит для |
|-----------|-------|-------------|
| **MultiSplit** ✅ | `fake,multisplit` + seqovl + паттерн | Ростелеком, МТС, Мегафон |
| **HostFakeSplit** | `hostfakesplit` + подмена Host | Билайн, МГТС, Tele2 |
| **Original** | простой `fake` | Слабый DPI / тест-режим |

---

## Требования

| Компонент | Версия / Примечание |
|-----------|---------------------|
| Windows | 10 или 11 |
| Python | 3.10+ |
| Права | Администратор (обязательно) |
| `pydivert` | только для PyDivert-движка — `pip install pydivert` |
| `winws.exe` + `WinDivert` | только для WinWS-движка (из zapret) |

---

## Быстрый старт

### 1. Клонировать репозиторий

```bash
git clone https://github.com/your-username/pyzapret-gui.git
cd pyzapret-gui
```

### 2. Установить зависимости

```bash
# Обязательно — если планируете использовать движок PyDivert
pip install pydivert

# Для движка WinWS зависимостей Python нет
```

### 3. Запустить (от Администратора)

```bash
# Через Python
python pyzapret_gui.py

# Или запустить скомпилированный .exe от имени Администратора
```

### 4. Структура папок для WinWS

```
pyzapret-gui/
├── pyzapret_gui.py
├── service.bat           ← из zapret (для автозагрузки GameFilter)
├── bin/
│   ├── winws.exe
│   ├── WinDivert.dll
│   ├── WinDivert64.sys
│   ├── quic_initial_www_google_com.bin
│   ├── tls_clienthello_www_google_com.bin
│   ├── tls_clienthello_max_ru.bin
│   ├── tls_clienthello_4pda_to.bin
│   └── stun.bin
└── lists/
    ├── list-general.txt
    ├── list-general-user.txt
    ├── list-google.txt
    ├── list-exclude.txt
    ├── list-exclude-user.txt
    ├── ipset-all.txt
    ├── ipset-exclude.txt
    └── ipset-exclude-user.txt
```

> Файлы `bin/` и `lists/` берутся из оригинального проекта [zapret](https://github.com/bol-van/zapret).

---

## Сборка в .exe

### PyInstaller (рекомендуется)

```bash
pip install pyinstaller
pyinstaller --onedir --windowed --hidden-import=pydivert --name=PyZapret pyzapret_gui.py
```

Готовая папка появится в `dist/PyZapret/`. Скопируйте туда `bin/`, `lists/`, `service.bat`.

### Nuitka (меньше антивирусных срабатываний)

```bash
pip install nuitka
python -m nuitka --onefile --windows-disable-console --include-package=pydivert --output-filename=PyZapret.exe pyzapret_gui.py
```

---

## Как выбрать стратегию

```
Провайдер неизвестен?
│
├─► Попробуйте MultiSplit (рекомендуется по умолчанию)
│       Не помогло?
│       └─► Переключитесь на HostFakeSplit
│               Не помогло?
│               └─► Попробуйте Original (тест-режим)
│
└─► Если известен провайдер:
        Ростелеком / МТС / Мегафон  →  MultiSplit
        Билайн / МГТС / Tele2       →  HostFakeSplit
```

---

## Движок PyDivert — стратегии

| Стратегия | Описание |
|-----------|----------|
| `split` | Разрезает пакет на 2 TCP-сегмента |
| `disorder` | Разрезает + отправляет в обратном порядке |
| `fake` | Фейковый пакет (TTL=1) перед настоящим |
| `fakedsplit` | Фейк + разрез — максимальный обход |

---

## Часто задаваемые вопросы

**Почему нужны права Администратора?**
WinDivert (используется обоими движками) работает на уровне ядра Windows и требует привилегированного доступа для перехвата сетевых пакетов.

**Где взять winws.exe и bin-файлы?**
Из оригинального проекта [zapret](https://github.com/bol-van/zapret) — раздел Releases.

**Антивирус ругается на WinDivert / winws.exe?**
Это нормально. WinDivert — легитимный драйвер для работы с сетью на уровне ядра, он используется во многих VPN и прокси-инструментах. Добавьте папку `bin/` в исключения.

**Работает ли на Windows 7/8?**
Нет. Требуется Windows 10 или 11.

---

## Лицензия

MIT License — используйте свободно, указывайте источник.

---

<div align="center">
Основан на проекте <a href="https://github.com/bol-van/zapret">zapret</a> от bol-van
</div>
