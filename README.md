<div align="center">
  <img src="https://files.catbox.moe/4d98m3.png" width="120" alt="PyZapret"/>

  # PyZapret
  
  **GUI-оболочка для обхода DPI-блокировок на Windows**
  
  ![Version](https://img.shields.io/badge/version-3.1--a-blue?style=flat-square)
  ![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey?style=flat-square)
  ![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
</div>

---

## Как это работает

PyZapret запускает [winws.exe](https://github.com/bol-van/zapret) (zapret) с нужными аргументами и предоставляет удобный веб-интерфейс для управления им.

Внутри запускается локальный Flask-сервер на `127.0.0.1:5000`, к которому подключается встроенное окно на базе pywebview. Все события (логи, статус, статистика) передаются через WebSocket в реальном времени.

**Движки:**
- **WinWS** — запускает `winws.exe` через выбранный `.bat` из папки `strategies/`. Основной режим
- **PyDivert** — встроенный Python-движок, перехватывает TCP-пакеты напрямую через WinDivert и применяет стратегии `split / disorder / fake / fakedsplit` без запуска winws.exe. Экспериментальный

**Стратегии DPI-обхода:**
- `fake` — отправляет фейковый пакет с TTL=1 перед настоящим, DPI видит его первым и теряется
- `disorder` — разбивает пакет на фрагменты и меняет их местами
- `multisplit` — разбивает с перекрытием sequence numbers, DPI не может собрать поток
- `hostfakesplit` — подменяет Host/SNI в заголовке перед разбивкой
- `hopbyhop` — добавляет невалидный IPv6 extension header для обмана инспектора

---

## Структура

```
PyZapretTestBuilding/
├── PyZapret.exe        ← запускать от Администратора
├── bin/
│   ├── winws.exe       ← движок zapret
│   ├── WinDivert.dll
│   ├── WinDivert64.sys
│   ├── ui.html         ← интерфейс
│   ├── icon.ico
│   ├── service.bat
│   └── *.bin           ← fake-пакеты (TLS/QUIC/STUN)
├── lists/
│   ├── ipset-all.txt   ← IP-адреса заблокированных ресурсов
│   ├── list-general.txt
│   ├── list-google.txt
│   └── ...
└── strategies/         ← .bat стратегии
```

---

## Стратегии

Все стратегии лежат в `strategies/` и отображаются в интерфейсе как официальные.

| Файл | Для кого |
|---|---|
| `general.bat` | Универсальный — попробуй первым |
| `Rostelecom.bat` | Ростелеком / Домру |
| `MTS.bat` | МТС |
| `Megafon.bat` | Мегафон |
| `Beeline.bat` | Билайн |
| `Tele2.bat` | Tele2 |
| `general (ALT).bat` … `general (ALT11).bat` | Альтернативы с разными параметрами |
| `general (FAKE TLS AUTO).bat` | Fake TLS серия |
| `general (SIMPLE FAKE).bat` | Простой fake без hostlist |
| `general (GAME+).bat` | Игровой режим — порты Steam / PSN / EGS |

Если `general.bat` не помогает — пробуй ALT варианты по порядку. Если провайдер известен — используй его батник напрямую.

---

## Требования

- Windows 10 / 11 x64
- Права **Администратора** (обязательно — WinDivert работает только с ними)
- `winws.exe` + `WinDivert.dll` + `WinDivert64.sys` в папке `bin/`

---

<div align="center">
  <sub>by <a href="https://github.com/streloss">streloss</a></sub>
</div>
