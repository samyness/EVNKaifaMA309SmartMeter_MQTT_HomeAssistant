# Kaifa MA309 P1 Smart Meter Reader (Netz NÖ)

This project provides a **robust Python-based reader for the Kaifa MA309 smart meter** used by **Netz Niederösterreich**, accessing the **P1 customer interface (DLMS/COSEM over M-Bus)**.
It is designed to run **24/7 on a Raspberry Pi**, decode encrypted M-Bus telegrams using the **Gurux DLMS stack**, extract values via **OBIS codes**, and publish them to **MQTT** in a **Home-Assistant-friendly format** with full **MQTT Discovery** support.

---

## ✨ Features

* ✅ Compatible with **Kaifa MA309** (Netz NÖ P1 interface)
* ✅ DLMS/COSEM decoding via **Gurux GXDLMSTranslator**
* ✅ Stable **M-Bus long-frame extraction** (no fixed read sizes)
* ✅ OBIS-based value parsing (robust against format changes)
* ✅ MQTT publishing with clean topic structure
* ✅ **Home Assistant MQTT Discovery** (sensors auto-appear)
* ✅ Availability handling (online/offline via MQTT LWT)
* ✅ Phase-level voltage & current monitoring (L1/L2/L3)
* ✅ Import/export energy and power values
* ✅ Optimized for **Raspberry Pi / Linux**

---

## 📊 Exposed Measurements

| Measurement        | OBIS Code            | Unit |
| ------------------ | -------------------- | ---- |
| Energy import (A+) | 1.0.1.8.0.255        | Wh   |
| Energy export (A−) | 1.0.2.8.0.255        | Wh   |
| Power import (P+)  | 1.0.1.7.0.255        | W    |
| Power export (P−)  | 1.0.2.7.0.255        | W    |
| Net power          | derived              | W    |
| Voltage L1/L2/L3   | 1.0.32/52/72.7.0.255 | V    |
| Current L1/L2/L3   | 1.0.31/51/71.7.0.255 | A    |
| Power factor       | 1.0.13.7.0.255       | –    |

---

## 🏠 Home Assistant Integration

The script publishes all values via **MQTT** and automatically creates sensors in Home Assistant using **MQTT Discovery**.

### MQTT Topic Structure

```
smartmeter/kaifa_ma309/
├── status                (online/offline)
└── state/
    ├── power_net_w
    ├── energy_import_wh
    ├── voltage_l1_v
    └── ...
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
* MQTT broker (e.g. Mosquitto)
* Home Assistant (optional, but recommended)

---

## 📦 Installation

```bash
sudo apt update
sudo apt install -y python3-pip
pip3 install pyserial paho-mqtt gurux-dlms
```

Clone the repository:

```bash
git clone https://github.com/<your-username>/kaifa-ma309-p1-reader.git
cd kaifa-ma309-p1-reader
```

---

## 🔑 Configuration

You need the **GUEK (Global Unicast Encryption Key)** provided by Netz NÖ for your meter.

You can either pass it as a parameter or via environment variable.

### Environment Variables (recommended)

```bash
export P1_GUEK="<YOUR_GUEK_HEX_KEY>"
export MQTT_HOST="192.168.1.10"
```

---

## ▶️ Usage

### Run with MQTT + Home Assistant Discovery

```bash
python3 smartmeter_kaifa_ma309_ha_mqtt.py \
  --port /dev/ttyUSB0 \
  --mqtt \
  --mqtt-host 192.168.1.10
```

### Run without MQTT (console output only)

```bash
python3 smartmeter_kaifa_ma309_ha_mqtt.py \
  --port /dev/ttyUSB0 \
  --guek <YOUR_GUEK_HEX_KEY> \
  --no-mqtt
```

---

## 🔄 Autostart (systemd)

For 24/7 operation on a Raspberry Pi, it is recommended to run the script as a **systemd service**.

A sample service file can be found in the `systemd/` directory or created manually.

---

## 📈 Typical Use Cases

* Home Assistant energy dashboards
* PV self-consumption and grid feed-in monitoring
* Phase imbalance and peak load detection
* Load-based automations (wallbox, heat pump, etc.)
* Long-term analytics with InfluxDB / Grafana

---

## 🧠 Design Notes

* No fixed byte offsets are used
* Each M-Bus telegram is parsed independently
* OBIS codes define meaning and scaling
* MQTT Discovery payloads are retained for HA restarts

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

If you find this project useful, feel free to ⭐ the repository.
