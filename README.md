# Kaifa MA309 P1 Smart Meter Reader (Netz NÖ) → MQTT → Home Assistant

This project provides a **robust Python-based reader for the Kaifa MA309 smart meter** used by **Netz Niederösterreich**, accessing the **P1 customer interface (DLMS/COSEM over M-Bus)**.

It is designed to run **24/7 on a Raspberry Pi**, decode encrypted M-Bus telegrams using the **Gurux DLMS stack**, extract measurements via **OBIS codes**, and publish them to **MQTT** in a **Home Assistant friendly format** with full **MQTT Discovery** support.

---

## ✨ Features

* ✅ Compatible with **Kaifa MA309** (Netz NÖ P1 interface)
* ✅ DLMS/COSEM decoding via **Gurux GXDLMSTranslator**
* ✅ Robust serial read + frame assembly (tolerant to partial reads)
* ✅ OBIS-based value parsing (tolerant to format variations)
* ✅ Correct scaling / unit handling (incl. **signed scaler**)
* ✅ MQTT publishing with clean topic structure
* ✅ **Home Assistant MQTT Discovery** (sensors auto-appear)
* ✅ Availability handling (online/offline, retained)
* ✅ Phase-level voltage & current monitoring (L1/L2/L3)
* ✅ Import/export energy and power values
* ✅ Optimized for **Raspberry Pi / Linux** (systemd-ready)

---

## 📊 Exposed Measurements (typical)

> Exact OBIS mappings can vary slightly depending on meter configuration/firmware. The following are the typical values exposed by Kaifa MA309 on Netz NÖ.

| Measurement          | Typical OBIS Code     | Unit |
| -------------------- | --------------------- | ---- |
| Energy import (A+)   | 1.0.1.8.0.255         | Wh   |
| Energy export (A−)   | 1.0.2.8.0.255         | Wh   |
| Power import (P+)    | 1.0.1.7.0.255         | W    |
| Power export (P−)    | 1.0.2.7.0.255         | W    |
| Net power            | derived (P+ − P−)     | W    |
| Voltage L1 / L2 / L3 | 1.0.32/52/72.7.0.255  | V    |
| Current L1 / L2 / L3 | 1.0.31/51/71.7.0.255  | A    |
| Power factor (PF)    | 1.0.13.7.0.255 (typ.) | –    |

---

## 🏠 Home Assistant Integration (MQTT Discovery)

The script publishes values via **MQTT** and automatically creates sensors in Home Assistant using **MQTT Discovery**.

### MQTT Topic Structure

Device topics are **namespaced by meter identity** (e.g. `kaifa_5682A4DE`).
Availability is device-specific and **retained**, so HA won’t get stuck on a shared “bridge” availability topic.

```
smartmeter/kaifa_5682A4DE/
├── status   (online/offline, retained)
└── state    (JSON payload, e.g. energy_import, voltage_l1, ...)
```

### Example `state` payload

```json
{
  "energy_import": 20971.61,
  "energy_export": 533.811,
  "power_import": 76,
  "power_export": 0,
  "power_net": 76,
  "voltage_l1": 235.0,
  "voltage_l2": 236.3,
  "voltage_l3": 238.6,
  "current_l1": 1.31,
  "current_l2": 1.35,
  "current_l3": 2.02,
  "power_factor": 0.766,
  "_meta": {
    "timestamp": "2026-03-23T11:02:15",
    "timestamp_utc": "2026-03-23T10:02:15+00:00",
    "system_title": "4B464D65509BEE36"
  }
}
```

No manual YAML configuration is required in Home Assistant.

---

## 🔧 Requirements

### Hardware

* Kaifa MA309 smart meter
* Enabled **P1 customer interface** (Netz NÖ)
* USB M-Bus / P1 adapter
* Raspberry Pi (or any Linux system)

### Software

* Python 3.9+
* MQTT broker (e.g. Mosquitto / Home Assistant Mosquitto add-on)
* Home Assistant (optional, recommended)

---

## 📦 Installation

### 1) System packages

```bash
sudo apt update
sudo apt install -y python3-pip python3-venv
```

### 2) Create a virtual environment (recommended)

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
```

### 3) Install dependencies

```bash
pip install pyserial paho-mqtt gurux-dlms beautifulsoup4 html5lib
```

> Depending on your build, you may also need:
> `pip install cryptography`

---

## 🔑 Configuration

You need the **GUEK (Global Unicast Encryption Key)** provided by Netz NÖ for your meter.

### Environment variables (recommended)

Create `/home/pi/kaifa/kaifa.env` (or your preferred location):

```bash
KAIFA_GUEK="<YOUR_GUEK_HEX_KEY>"

MQTT_HOST="192.168.30.2"
MQTT_PORT="1883"
MQTT_USER="mqtt_smartmeter"
MQTT_PASS="<YOUR_MQTT_PASSWORD>"
```

---

## ▶️ Usage

### Run manually

```bash
python3 kaifa_ma309_mbus_to_mqtt.py \
  --port /dev/ttyUSB0 \
  --baud 2400
```

> Tip: prefer a stable serial path:
> `/dev/serial/by-id/...` instead of `/dev/ttyUSB0`

---

## 🔄 Autostart (systemd)

Create a service file (example):

```ini
[Unit]
Description=Kaifa MA309 Smartmeter -> MQTT (HA Discovery)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/kaifa
EnvironmentFile=/home/pi/kaifa/kaifa.env
Environment=PYTHONUNBUFFERED=1

ExecStart=/home/pi/kaifa/venv/bin/python /home/pi/kaifa/kaifa_ma309_mbus_to_mqtt.py --port /dev/ttyUSB0 --baud 2400

Restart=always
RestartSec=2
StartLimitIntervalSec=0

[Install]
WantedBy=multi-user.target
```

Enable + start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now kaifa-ma309.service
```

Logs:

```bash
sudo journalctl -u kaifa-ma309.service -f
```

---

## 📈 Typical Use Cases

* Home Assistant energy dashboards
* PV self-consumption and grid feed-in monitoring
* Phase imbalance and peak load detection
* Load-based automations (wallbox, heat pump, etc.)
* Long-term analytics with InfluxDB / Grafana

---

## 🧠 Design Notes

* Robust handling of partial/short serial reads
* Each telegram is parsed independently (no fixed offsets required)
* OBIS codes define meaning, scaling, and units
* MQTT Discovery payloads are retained for HA restarts
* Availability is **device-specific** to avoid global “offline” lockouts

---

## ⚠️ Disclaimer

This project is **not affiliated with Netz Niederösterreich or Kaifa**.
Use at your own risk. Always comply with local regulations and utility provider terms.

---

## 📄 License

MIT License

---

## 🙌 Contributions

Issues, pull requests and improvements are very welcome!
