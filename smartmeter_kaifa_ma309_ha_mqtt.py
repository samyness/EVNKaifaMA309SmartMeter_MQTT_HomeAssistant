#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import socket
import logging
import argparse

import serial
import paho.mqtt.client as mqtt

from gurux_dlms.GXByteBuffer import GXByteBuffer
from gurux_dlms.GXDLMSTranslator import GXDLMSTranslator
from gurux_dlms.GXDLMSTranslatorMessage import GXDLMSTranslatorMessage

from bs4 import BeautifulSoup

LOG = logging.getLogger("kaifa_ma309")

BASE_TOPIC_DEFAULT = "smartmeter/kaifa_ma309"
HA_DISCOVERY_PREFIX = "homeassistant"

DEVICE_BASE = {
    "identifiers": ["kaifa_ma309_p1"],
    "name": "Smartmeter Kaifa MA309 (P1)",
    "manufacturer": "Kaifa",
    "model": "MA309",
    "sw_version": "gurux_github_style",
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

def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

def read_exact(ser: serial.Serial, size: int, hard_timeout_s: float) -> bytes:
    """
    Wie im GitHub-Script: ser.read(size=282), aber robust: wir sammeln bis 'size' voll ist.
    """
    deadline = time.time() + hard_timeout_s
    out = bytearray()
    while len(out) < size and time.time() < deadline:
        chunk = ser.read(size - len(out))
        if chunk:
            out.extend(chunk)
        else:
            time.sleep(0.01)
    return bytes(out)

def build_gurux_translator(guek_hex: str) -> GXDLMSTranslator:
    # WICHTIG: genau wie GitHub -> GXByteBuffer(evn_schluessel) mit HEX-STRING
    tr = GXDLMSTranslator()
    tr.blockCipherKey = GXByteBuffer(guek_hex.strip())
    tr.comments = True
    tr.completePdu = True
    return tr

def mqtt_connect(host: str, port: int, username: str, password: str, client_id: str, avail_topic: str):
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
    except Exception:
        client = mqtt.Client(client_id=client_id, clean_session=True)

    if username or password:
        client.username_pw_set(username, password)

    client.will_set(avail_topic, payload="offline", qos=1, retain=True)
    client.reconnect_delay_set(min_delay=2, max_delay=30)
    client.connect(host, port=port, keepalive=30)
    client.loop_start()
    return client

def publish_discovery(client, base_topic: str, avail_topic: str):
    node = socket.gethostname()
    base_uid = f"kaifa_ma309_{node}".lower()

    state_base = f"{base_topic}/state"

    for key, meta in SENSORS.items():
        discovery_topic = f"{HA_DISCOVERY_PREFIX}/sensor/{base_uid}/{key}/config"
        payload = {
            "name": meta["name"],
            "unique_id": f"{base_uid}_{key}",
            "state_topic": f"{state_base}/{key}",
            "availability_topic": avail_topic,
            "payload_available": "online",
            "payload_not_available": "offline",
            "device": DEVICE_BASE,
        }
        if meta.get("unit"):
            payload["unit_of_measurement"] = meta["unit"]
        if meta.get("device_class"):
            payload["device_class"] = meta["device_class"]
        if meta.get("state_class"):
            payload["state_class"] = meta["state_class"]

        client.publish(discovery_topic, json.dumps(payload), qos=1, retain=True)

    LOG.info("HA discovery published")

def publish_states(client, base_topic: str, avail_topic: str, values: dict):
    client.publish(avail_topic, "online", qos=1, retain=True)
    state_base = f"{base_topic}/state"
    for k, v in values.items():
        client.publish(f"{state_base}/{k}", str(v), qos=0, retain=False)

def parse_values_github_style(xml: str) -> dict:
    """
    Entschlüsselung passiert durch Gurux beim messageToXml().
    Parsing ist stabiler als die String-Slices im GitHub, aber Ergebnis identisch.
    """
    soup = BeautifulSoup(xml, "html5lib")
    u32_tags = soup.find_all("uint32")
    u16_tags = soup.find_all("uint16")

    u32 = []
    for t in u32_tags:
        v = t.get("value")
        if v:
            u32.append(int(v, 16))

    u16 = []
    for t in u16_tags:
        v = t.get("value")
        if v:
            u16.append(int(v, 16))

    # GitHub-Reihenfolge:
    # u32: A+ Wh, A- Wh, P+ W, P- W
    # u16: U1, U2, U3, I1, I2, I3, PF
    if len(u32) < 4 or len(u16) < 7:
        return {}

    values = {
        "energy_import_wh": u32[0],
        "energy_export_wh": u32[1],
        "power_import_w":   u32[2],
        "power_export_w":   u32[3],
        "power_net_w":      u32[2] - u32[3],
        "voltage_l1_v":     u16[0] / 10.0,
        "voltage_l2_v":     u16[1] / 10.0,
        "voltage_l3_v":     u16[2] / 10.0,
        "current_l1_a":     u16[3] / 100.0,
        "current_l2_a":     u16[4] / 100.0,
        "current_l3_a":     u16[5] / 100.0,
        "power_factor":     u16[6] / 1000.0,
    }
    return values

def main():
    ap = argparse.ArgumentParser(description="Kaifa MA309 P1 -> Gurux (GitHub-style decrypt) -> MQTT/HA")
    ap.add_argument("--port", default=os.getenv("P1_PORT", "/dev/ttyUSB0"))
    ap.add_argument("--baud", type=int, default=int(os.getenv("P1_BAUD", "2400")))
    ap.add_argument("--read-size", type=int, default=int(os.getenv("P1_READ_SIZE", "282")))
    ap.add_argument("--timeout", type=float, default=float(os.getenv("P1_TIMEOUT", "2.0")))
    ap.add_argument("--guek", default=os.getenv("P1_GUEK", ""))

    ap.add_argument("--mqtt", action="store_true")
    ap.add_argument("--mqtt-host", default=os.getenv("MQTT_HOST", "127.0.0.1"))
    ap.add_argument("--mqtt-port", type=int, default=int(os.getenv("MQTT_PORT", "1883")))
    ap.add_argument("--mqtt-user", default=os.getenv("MQTT_USER", ""))
    ap.add_argument("--mqtt-pass", default=os.getenv("MQTT_PASS", ""))
    ap.add_argument("--mqtt-base-topic", default=os.getenv("MQTT_BASE_TOPIC", BASE_TOPIC_DEFAULT))
    ap.add_argument("--ha-discovery", action="store_true")

    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--debug-xml", action="store_true")
    ap.add_argument("--print-raw-hex", action="store_true")

    args = ap.parse_args()
    setup_logging(args.verbose)

    if not args.guek or len(args.guek.strip()) < 32:
        LOG.error("GUEK fehlt/zu kurz.")
        sys.exit(2)

    tr = build_gurux_translator(args.guek)

    base_topic = args.mqtt_base_topic.rstrip("/")
    avail_topic = f"{base_topic}/status"

    mqtt_client = None
    if args.mqtt:
        mqtt_client = mqtt_connect(
            host=args.mqtt_host,
            port=args.mqtt_port,
            username=args.mqtt_user,
            password=args.mqtt_pass,
            client_id="SmartMeterKaifaMA309",
            avail_topic=avail_topic,
        )
        mqtt_client.publish(avail_topic, "online", qos=1, retain=True)
        LOG.info("MQTT connected to %s:%d (base_topic=%s)", args.mqtt_host, args.mqtt_port, base_topic)

        if args.ha_discovery:
            publish_discovery(mqtt_client, base_topic, avail_topic)

    ser = serial.Serial(
        port=args.port,
        baudrate=args.baud,
        bytesize=serial.EIGHTBITS,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        timeout=args.timeout,
    )
    LOG.info("Listening on %s @ %d baud (read-size=%d)", args.port, args.baud, args.read_size)

    try:
        while True:
            raw = read_exact(ser, args.read_size, hard_timeout_s=max(2.0, args.timeout * 3))
            if len(raw) != args.read_size:
                if args.verbose:
                    LOG.debug("short read: got %d/%d bytes", len(raw), args.read_size)
                continue

            daten_hex = raw.hex()
            if args.print_raw_hex:
                print(daten_hex)

            msg = GXDLMSTranslatorMessage()
            msg.message = GXByteBuffer(daten_hex)

            xml = ""
            pdu = GXByteBuffer()
            tr.completePdu = True

            try:
                while tr.findNextFrame(msg, pdu):
                    pdu.clear()
                    xml += tr.messageToXml(msg)
            except Exception as e:
                LOG.debug("findNextFrame/messageToXml error: %s", e)
                continue

            if args.debug_xml:
                LOG.debug("XML head: %r", xml[:400])

            values = parse_values_github_style(xml)
            if not values:
                LOG.debug("no values parsed (uint32=%s uint16=%s)", "?" , "?")
                continue

            LOG.info(
                "P=%sW  U1=%sV  I1=%sA  PF=%s",
                values["power_net_w"], values["voltage_l1_v"], values["current_l1_a"], values["power_factor"]
            )

            if mqtt_client:
                publish_states(mqtt_client, base_topic, avail_topic, values)

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
