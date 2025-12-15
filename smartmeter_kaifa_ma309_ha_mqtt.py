#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import socket
import logging
import argparse
import xml.etree.ElementTree as ET
from binascii import unhexlify

import serial

from gurux_dlms.GXByteBuffer import GXByteBuffer
from gurux_dlms.GXDLMSTranslator import GXDLMSTranslator
from gurux_dlms.GXDLMSTranslatorMessage import GXDLMSTranslatorMessage

try:
    import paho.mqtt.client as mqtt
except ImportError:
    mqtt = None

LOG = logging.getLogger("kaifa_ma309")

# -----------------------------
# OBIS -> key + scale
# (Netz NÖ P1 Doku: U ×10^-1, I ×10^-2, PF ×10^-3; Energie Wh, Leistung W ohne Skalierung)
# -----------------------------
OBIS_MAP = {
    "0100010800FF": ("energy_import_wh", 1.0),   # 1.0.1.8.0.255 A+ Wh
    "0100020800FF": ("energy_export_wh", 1.0),   # 1.0.2.8.0.255 A- Wh
    "0100010700FF": ("power_import_w", 1.0),     # 1.0.1.7.0.255 P+ W
    "0100020700FF": ("power_export_w", 1.0),     # 1.0.2.7.0.255 P- W

    "0100200700FF": ("voltage_l1_v", 0.1),       # 1.0.32.7.0.255 U L1 V
    "0100340700FF": ("voltage_l2_v", 0.1),       # 1.0.52.7.0.255 U L2 V
    "0100480700FF": ("voltage_l3_v", 0.1),       # 1.0.72.7.0.255 U L3 V

    "01001F0700FF": ("current_l1_a", 0.01),      # 1.0.31.7.0.255 I L1 A
    "0100330700FF": ("current_l2_a", 0.01),      # 1.0.51.7.0.255 I L2 A
    "0100470700FF": ("current_l3_a", 0.01),      # 1.0.71.7.0.255 I L3 A

    "01000D0700FF": ("power_factor", 0.001),     # 1.0.13.7.0.255 PF
}

NUMERIC_TAGS = {"UInt32", "UInt16", "Int32", "Int16", "UInt8", "Int8"}

# -----------------------------
# Home Assistant MQTT Discovery Setup
# -----------------------------
HA_DISCOVERY_PREFIX = "homeassistant"
BASE_TOPIC_DEFAULT = "smartmeter/kaifa_ma309"

DEVICE_BASE = {
    "identifiers": ["kaifa_ma309_p1"],
    "name": "Smartmeter Kaifa MA309 (P1)",
    "manufacturer": "Kaifa",
    "model": "MA309",
    "sw_version": "1.0",
}

SENSORS = {
    "energy_import_wh": {"name": "Wirkenergie Import", "unit": "Wh", "device_class": "energy", "state_class": "total_increasing"},
    "energy_export_wh": {"name": "Wirkenergie Export", "unit": "Wh", "device_class": "energy", "state_class": "total_increasing"},
    "power_import_w":   {"name": "Leistung Import",    "unit": "W",  "device_class": "power",  "state_class": "measurement"},
    "power_export_w":   {"name": "Leistung Export",    "unit": "W",  "device_class": "power",  "state_class": "measurement"},
    "power_net_w":      {"name": "Leistung Netto",     "unit": "W",  "device_class": "power",  "state_class": "measurement"},
    "voltage_l1_v":     {"name": "Spannung L1",        "unit": "V",  "device_class": "voltage","state_class": "measurement"},
    "voltage_l2_v":     {"name": "Spannung L2",        "unit": "V",  "device_class": "voltage","state_class": "measurement"},
    "voltage_l3_v":     {"name": "Spannung L3",        "unit": "V",  "device_class": "voltage","state_class": "measurement"},
    "current_l1_a":     {"name": "Strom L1",           "unit": "A",  "device_class": "current","state_class": "measurement"},
    "current_l2_a":     {"name": "Strom L2",           "unit": "A",  "device_class": "current","state_class": "measurement"},
    "current_l3_a":     {"name": "Strom L3",           "unit": "A",  "device_class": "current","state_class": "measurement"},
    "power_factor":     {"name": "Leistungsfaktor",    "unit": "",   "device_class": None,     "state_class": "measurement"},
}

# -----------------------------
# Helpers
# -----------------------------
def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def safe_int_from_hex(value: str) -> int:
    value = (value or "").strip()
    if not value:
        raise ValueError("Empty numeric value")
    try:
        return int(value, 16)
    except ValueError:
        return int(value, 10)


def build_translator(guek_hex: str) -> GXDLMSTranslator:
    tr = GXDLMSTranslator()
    tr.comments = True
    tr.completePdu = True
    key_bytes = unhexlify(guek_hex.strip())
    tr.blockCipherKey = GXByteBuffer(key_bytes)
    return tr


def read_frames_to_xml(tr: GXDLMSTranslator, raw_bytes: bytes) -> str:
    msg = GXDLMSTranslatorMessage()
    msg.message = GXByteBuffer(raw_bytes)
    xml = ""
    pdu = GXByteBuffer()
    while tr.findNextFrame(msg, pdu):
        pdu.clear()
        xml += tr.messageToXml(msg)
    return xml


def parse_gurux_xml(xml: str) -> dict:
    """
    OBIS-basiert: OctetString(Value==OBIS) -> nächster Zahlenwert wird übernommen und skaliert.
    Zusätzlich versuchen wir meter_id aus OctetString ASCII-Digits zu decodieren (falls vorhanden).
    """
    out = {}
    current_obis = None

    root = ET.fromstring(xml)

    for el in root.iter():
        tag = el.tag.split("}")[-1]
        val = el.attrib.get("Value")

        if tag == "OctetString" and val:
            if val in OBIS_MAP:
                current_obis = val
                continue

            # meter_id optional: OctetString mit ASCII-Ziffern in HEX (z.B. "3138..." -> "18...")
            # Wir nehmen nur "digit-only" Strings in plausibler Länge.
            try:
                decoded = bytes.fromhex(val).decode("ascii", errors="strict")
                if decoded.isdigit() and 6 <= len(decoded) <= 32:
                    out["meter_id"] = decoded
            except Exception:
                pass

        if current_obis and tag in NUMERIC_TAGS and val is not None:
            key, factor = OBIS_MAP[current_obis]
            raw = safe_int_from_hex(val)
            out[key] = raw * factor
            current_obis = None

    if "power_import_w" in out and "power_export_w" in out:
        out["power_net_w"] = out["power_import_w"] - out["power_export_w"]

    return out


def extract_mbus_long_frames(buf: bytearray) -> list:
    """
    Extrahiert M-Bus Long Frames aus einem Stream.
    Format:
      68 L L 68 ... (L bytes payload) CS 16
    Frame-Länge = 6 + L
    """
    frames = []
    i = 0
    while True:
        try:
            i = buf.index(0x68, i)
        except ValueError:
            # Startbyte nicht mehr vorhanden -> Buffer begrenzen
            if len(buf) > 4096:
                del buf[:-1024]
            return frames

        if i + 6 > len(buf):
            if i > 0:
                del buf[:i]
            return frames

        L1 = buf[i + 1]
        L2 = buf[i + 2]
        if L1 != L2 or buf[i + 3] != 0x68:
            i += 1
            continue

        frame_len = 6 + L1
        if i + frame_len > len(buf):
            if i > 0:
                del buf[:i]
            return frames

        frame = bytes(buf[i:i + frame_len])
        if frame[-1] != 0x16:
            i += 1
            continue

        # Checksum prüfen (CS = vorletztes Byte; berechnet über frame[4:-2])
        cs = frame[-2]
        calc = sum(frame[4:-2]) & 0xFF
        if cs != calc:
            i += 1
            continue

        frames.append(frame)
        del buf[:i + frame_len]
        i = 0


def mqtt_connect(host: str, port: int, username: str, password: str, client_id: str,
                 avail_topic: str):
    if mqtt is None:
        raise RuntimeError("paho-mqtt fehlt. Install: pip install paho-mqtt")

    client = mqtt.Client(client_id=client_id, clean_session=True)
    if username or password:
        client.username_pw_set(username, password)

    # LWT: wenn Script weg ist -> offline
    client.will_set(avail_topic, payload="offline", qos=1, retain=True)

    client.reconnect_delay_set(min_delay=2, max_delay=30)
    client.connect(host, port=port, keepalive=30)
    client.loop_start()
    return client


def publish_discovery(client, base_topic: str, avail_topic: str, meter_id: str | None):
    node = socket.gethostname()
    base_uid = f"kaifa_ma309_{(meter_id or 'unknown')}_{node}".lower()

    device = dict(DEVICE_BASE)
    device["identifiers"] = list(device.get("identifiers", []))
    if meter_id:
        device["identifiers"].append(meter_id)
        device["name"] = f"Smartmeter Kaifa MA309 ({meter_id})"

    state_base = f"{base_topic}/state"

    for key, meta in SENSORS.items():
        discovery_topic = f"{HA_DISCOVERY_PREFIX}/sensor/{base_uid}/{key}/config"
        payload = {
            "name": f"{meta['name']}",
            "unique_id": f"{base_uid}_{key}",
            "state_topic": f"{state_base}/{key}",
            "availability_topic": avail_topic,
            "payload_available": "online",
            "payload_not_available": "offline",
            "device": device,
        }

        if meta.get("unit") is not None and meta.get("unit") != "":
            payload["unit_of_measurement"] = meta["unit"]
        if meta.get("device_class"):
            payload["device_class"] = meta["device_class"]
        if meta.get("state_class"):
            payload["state_class"] = meta["state_class"]

        # retain=True: HA findet es nach Restart wieder
        client.publish(discovery_topic, json.dumps(payload), qos=1, retain=True)

    LOG.info("HA discovery published (base_uid=%s)", base_uid)


def publish_states(client, base_topic: str, avail_topic: str, values: dict):
    client.publish(avail_topic, "online", qos=1, retain=True)

    state_base = f"{base_topic}/state"
    for k, v in values.items():
        # meter_id/ timestamp_raw_hex optional nicht als Sensor publishen
        if k in ("meter_id", "timestamp_raw_hex"):
            continue
        client.publish(f"{state_base}/{k}", str(v), qos=0, retain=False)


# -----------------------------
# Main
# -----------------------------
def main():
    ap = argparse.ArgumentParser(description="Kaifa MA309 (Netz NÖ P1) -> MQTT + HA Discovery")
    ap.add_argument("--port", default=os.getenv("P1_PORT", "/dev/ttyUSB0"))
    ap.add_argument("--baud", type=int, default=int(os.getenv("P1_BAUD", "2400")))
    ap.add_argument("--timeout", type=float, default=float(os.getenv("P1_TIMEOUT", "1.0")))
    ap.add_argument("--chunk", type=int, default=int(os.getenv("P1_CHUNK", "512")))
    ap.add_argument("--guek", default=os.getenv("P1_GUEK", ""), help="GUEK hex key (32 hex chars)")

    ap.add_argument("--print", dest="print_values", action="store_true")
    ap.add_argument("--no-print", dest="print_values", action="store_false")
    ap.set_defaults(print_values=True)

    ap.add_argument("--mqtt", action="store_true", help="Enable MQTT/HA")
    ap.add_argument("--mqtt-host", default=os.getenv("MQTT_HOST", "127.0.0.1"))
    ap.add_argument("--mqtt-port", type=int, default=int(os.getenv("MQTT_PORT", "1883")))
    ap.add_argument("--mqtt-user", default=os.getenv("MQTT_USER", ""))
    ap.add_argument("--mqtt-pass", default=os.getenv("MQTT_PASS", ""))
    ap.add_argument("--mqtt-base-topic", default=os.getenv("MQTT_BASE_TOPIC", BASE_TOPIC_DEFAULT))
    ap.add_argument("--verbose", action="store_true")

    args = ap.parse_args()
    setup_logging(args.verbose)

    if not args.guek or len(args.guek.strip()) < 32:
        LOG.error("GUEK fehlt/zu kurz. Übergib --guek <HEXKEY> oder setze P1_GUEK env var.")
        sys.exit(2)

    tr = build_translator(args.guek)

    base_topic = args.mqtt_base_topic.rstrip("/")
    avail_topic = f"{base_topic}/status"

    mqtt_client = None
    discovery_sent = False
    known_meter_id = None

    if args.mqtt:
        if mqtt is None:
            LOG.error("MQTT aktiviert, aber paho-mqtt fehlt. Install: pip install paho-mqtt")
            sys.exit(2)

        mqtt_client = mqtt_connect(
            host=args.mqtt_host,
            port=args.mqtt_port,
            username=args.mqtt_user,
            password=args.mqtt_pass,
            client_id="SmartMeterKaifaMA309",
            avail_topic=avail_topic,
        )
        # direkt online setzen
        mqtt_client.publish(avail_topic, "online", qos=1, retain=True)
        LOG.info("MQTT connected to %s:%d (base_topic=%s)", args.mqtt_host, args.mqtt_port, base_topic)

    ser = serial.Serial(
        port=args.port,
        baudrate=args.baud,
        bytesize=serial.EIGHTBITS,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        timeout=args.timeout,
    )
    LOG.info("Listening on %s @ %d baud", args.port, args.baud)

    buffer = bytearray()

    try:
        while True:
            chunk = ser.read(args.chunk)
            if chunk:
                buffer.extend(chunk)

            frames = extract_mbus_long_frames(buffer)
            if not frames:
                continue

            for frame in frames:
                xml = read_frames_to_xml(tr, frame)
                if not xml:
                    continue

                try:
                    values = parse_gurux_xml(xml)
                except Exception as e:
                    LOG.warning("Parse failed: %s", e)
                    if args.verbose:
                        LOG.debug("XML: %s", xml)
                    continue

                if not values:
                    continue

                known_meter_id = values.get("meter_id", known_meter_id)

                # HA Discovery: senden sobald wir meter_id kennen, sonst nach 1. Wert als fallback
                if mqtt_client and not discovery_sent:
                    if known_meter_id is not None:
                        publish_discovery(mqtt_client, base_topic, avail_topic, known_meter_id)
                        discovery_sent = True
                    else:
                        # fallback: discovery mit unknown nach erstem valid values
                        publish_discovery(mqtt_client, base_topic, avail_topic, None)
                        discovery_sent = True

                if args.print_values:
                    # kompakt
                    shown = {k: v for k, v in values.items() if k not in ("timestamp_raw_hex",)}
                    for k in sorted(shown.keys()):
                        print(f"{k}: {shown[k]}")
                    print("-" * 50)

                if mqtt_client:
                    publish_states(mqtt_client, base_topic, avail_topic, values)

            # kurze Pause optional (P1 sendet alle ~5s)
            # time.sleep(0.01)

    except KeyboardInterrupt:
        LOG.info("Stopping...")
    finally:
        try:
            ser.close()
        except Exception:
            pass

        if mqtt_client:
            try:
                mqtt_client.publish(avail_topic, "offline", qos=1, retain=True)
                mqtt_client.loop_stop()
                mqtt_client.disconnect()
            except Exception:
                pass


if __name__ == "__main__":
    main()
