# 🐍 VIPERSCAN

[English](#english) | [Русский](#русский)

---

## English

A lightweight, fast, and multi-threaded network port scanner built with C for Linux environments. It allows you to scan ranges of ports, specific custom ports, or simply check if a host is alive, utilizing POSIX threads for maximum performance.

### 🚀 Features
* **Multi-threaded Scan:** Runs up to 100 parallel checks simultaneously.
* **Flexible Target Selection:** Supports both IP addresses and domain names (via automatic DNS resolution).
* **Execution Time Counter:** Displays exactly how long the scan took.
* **No `//` Comments:** Pure, compliant C source code execution.

### 🛠️ Installation & Compilation

First, make sure you have `build-essential` installed. Then, compile and install the utility globally:

```bash
# Compile the source code
gcc viperscan.c -o vscan -pthread

# Install globally to run from anywhere without "./"
sudo cp vscan /usr/local/bin/
```

### 📋 Usage & Options

```bash
vscan <target> [start_port end_port] [options]
vscan -v
```

* `-help` — Show help message.
* `-v` — Verbose mode. Shows tool version if used alone, or displays closed ports during a scan.
* `-sn` — Ping Scan. Host discovery only (checks if the target is alive without scanning ports).
* `-p-` — Scan all 65535 ports.
* `-p` — Scan specific ports separated by commas (e.g., `-p 22,80,443`).

### 💡 Examples

```bash
# Scan default range (1-1000)
vscan 127.0.0.1

# Scan specific range with verbose output
vscan 127.0.0.1 20 30 -v

# Scan custom specific ports
vscan google.com -p 80,443

# Check if a host is alive (Ping scan)
vscan 192.168.1.1 -sn

# Scan absolutely all ports
vscan 127.0.0.1 -p-
```

---

## Русский

Легковесный, быстрый и многопоточный сканер сетевых портов, написанный на языке C для систем Linux. Позволяет сканировать диапазоны портов, выбранные порты или просто проверять доступность хоста с использованием потоков POSIX для максимальной скорости.

### 🚀 Возможности
* **Многопоточность:** Одновременно запускает до 100 параллельных проверок.
* **Гибкий выбор цели:** Поддерживает как IP-адреса, так и доменные имена (через автоматический DNS-резолв).
* **Счетчик времени:** Выводит точное время, затраченное на сканирование.
* **Чистый код:** Исходный код написан строго в соответствии со стандартами разработки.

### 🛠️ Сборка и установка

Убедитесь, что у вас установлен пакет `build-essential`. После этого скомпилируйте программу и установите её в систему:

```bash
# Компиляция исходного кода
gcc viperscan.c -o vscan -pthread

# Установка в систему, чтобы запускать из любой папки без "./"
sudo cp vscan /usr/local/bin/
```

### 📋 Параметры и использование

```bash
vscan <цель> [начальный_порт конечный_порт] [опции]
vscan -v
```

* `-help` — Показать справку по использованию.
* `-v` — Подробный режим (Verbose). Если запущен без цели — выведет версию утилиты. Если с целью — будет отображать в том числе и закрытые порты.
* `-sn` — Пинг-сканирование. Только обнаружение хоста (проверяет, жив ли сервер, без сканирования портов).
* `-p-` — Сканировать абсолютно все 65535 портов.
* `-p` — Сканировать только указанные порты через запятую (например, `-p 22,80,443`).

### 💡 Примеры команд

```bash
# Сканирование стандартного диапазона (1-1000)
vscan 127.0.0.1

# Сканирование диапазона с подробным выводом
vscan 127.0.0.1 20 30 -v

# Проверка конкретных портов на удаленном сервере
vscan google.com -p 80,443

# Быстрая проверка, включен ли сервер (Ping-скан)
vscan 192.168.1.1 -sn

# Сканирование всех существующих портов
vscan 127.0.0.1 -p-
```

### 📄 License / Лицензия
This project is licensed under the GNU General Public License v3.0 (GPLv3).
Проект распространяется под лицензией GNU General Public License v3.0 (GPLv3).
