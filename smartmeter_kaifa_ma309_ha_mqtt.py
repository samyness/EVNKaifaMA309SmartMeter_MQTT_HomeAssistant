#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import hashlib
import json
import logging
import os
import struct
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

import serial
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    import paho.mqtt.client as mqtt
except ImportError:
    mqtt = None

LOG = logging.getLogger("kaifa_ma309")

MQTT_HOST_DEFAULT = os.getenv("MQTT_HOST", "192.168.30.2")
MQTT_PORT_DEFAULT = int(os.getenv("MQTT_PORT", "1883"))
MQTT_USER_DEFAULT = os.getenv("MQTT_USER", "")
MQTT_PASS_DEFAULT = os.getenv("MQTT_PASS", "")
MQTT_DISCOVERY_PREFIX_DEFAULT = os.getenv("MQTT_DISCOVERY_PREFIX", "homeassistant")
BASE_TOPIC_DEFAULT = os.getenv("MQTT_BASE_TOPIC", "smartmeter")

OBIS_SENSORS = {
    "0100010800FF": {
        "key": "energy_import",
        "name": "Energie Bezug",
        "unit": "kWh",
        "device_class": "energy",
        "state_class": "total_increasing",
        "value_transform": "wh_to_kwh",
    },
    "0100020800FF": {
        "key": "energy_export",
        "name": "Energie Einspeisung",
        "unit": "kWh",
        "device_class": "energy",
        "state_class": "total_increasing",
        "value_transform": "wh_to_kwh",
    },
    "0100010700FF": {
        "key": "power_import",
        "name": "Leistung Bezug",
        "unit": "W",
        "device_class": "power",
        "state_class": "measurement",
    },
    "0100020700FF": {
        "key": "power_export",
        "name": "Leistung Einspeisung",
        "unit": "W",
        "device_class": "power",
        "state_class": "measurement",
    },
    "0100200700FF": {"key": "voltage_l1", "name": "Spannung L1", "unit": "V", "device_class": "voltage", "state_class": "measurement"},
    "0100340700FF": {"key": "voltage_l2", "name": "Spannung L2", "unit": "V", "device_class": "voltage", "state_class": "measurement"},
    "0100480700FF": {"key": "voltage_l3", "name": "Spannung L3", "unit": "V", "device_class": "voltage", "state_class": "measurement"},
    "01001F0700FF": {"key": "current_l1", "name": "Strom L1", "unit": "A", "device_class": "current", "state_class": "measurement"},
    "0100330700FF": {"key": "current_l2", "name": "Strom L2", "unit": "A", "device_class": "current", "state_class": "measurement"},
    "0100470700FF": {"key": "current_l3", "name": "Strom L3", "unit": "A", "device_class": "current", "state_class": "measurement"},
    "01000D0700FF": {"key": "power_factor", "name": "cos φ", "unit": None, "device_class": "power_factor", "state_class": "measurement"},
}


class DecodeError(Exception):
    pass


class PublishError(Exception):
    pass


class BridgeState:
    def __init__(self) -> None:
        self.device_id: Optional[str] = None
        self.discovery_sent = False
        self.connected = False
        self.last_serial_byte_monotonic = time.monotonic()
        self.last_frame_monotonic = 0.0
        self.last_good_packet_monotonic = 0.0
        self.last_state_publish_monotonic = 0.0
        self.last_serial_reopen_monotonic = 0.0
        self.service_online = False
        self.packet_counter = 0
        self.decode_error_counter = 0
        self.serial_error_counter = 0
        self.mqtt_error_counter = 0
        self.pending_long_since = 0.0


def setup_logging(debug: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def mbus_checksum(payload: bytes) -> int:
    return sum(payload) & 0xFF


def extract_mbus_frame(buf: bytearray) -> Optional[bytes]:
    while True:
        start = buf.find(b"\x68")
        if start < 0:
            if len(buf) > 4096:
                buf.clear()
            return None
        if start > 0:
            del buf[:start]

        if len(buf) < 6:
            return None

        if buf[0] != 0x68:
            del buf[0]
            continue

        l1, l2 = buf[1], buf[2]
        if l1 != l2 or buf[3] != 0x68:
            del buf[0]
            continue

        total = l1 + 6
        if len(buf) < total:
            return None

        frame = bytes(buf[:total])
        del buf[:total]

        if frame[-1] != 0x16:
            continue

        payload = frame[4:-2]
        if mbus_checksum(payload) != frame[-2]:
            continue

        return frame


def aes_ctr_suite0(key16: bytes, system_title8: bytes, ic4: bytes, ciphertext: bytes, counter32: int) -> bytes:
    iv = system_title8 + ic4 + counter32.to_bytes(4, "big")
    dec = Cipher(algorithms.AES(key16), modes.CTR(iv)).decryptor()
    return dec.update(ciphertext) + dec.finalize()


def ensure_available(d: bytes, i: int, need: int, what: str) -> None:
    have = len(d) - i
    if have < need:
        raise DecodeError(f"{what}: need {need} bytes at offset {i}, have {have}")


def read_u8(d: bytes, i: int) -> Tuple[int, int]:
    ensure_available(d, i, 1, "read_u8")
    return d[i], i + 1


def read_n(d: bytes, i: int, n: int, what: str) -> Tuple[bytes, int]:
    ensure_available(d, i, n, what)
    return d[i:i + n], i + n


def read_axdr_length(d: bytes, i: int, what: str) -> Tuple[int, int]:
    first, i = read_u8(d, i)
    if first <= 0x7F:
        return first, i
    octets = first & 0x7F
    if octets == 0 or octets > 4:
        raise DecodeError(f"{what}: unsupported length marker 0x{first:02X}")
    raw, i = read_n(d, i, octets, f"{what}/len")
    return int.from_bytes(raw, "big"), i


def parse_axdr_container(d: bytes, i: int, cnt: int, kind: str) -> Tuple[list, int]:
    arr = []
    for idx in range(cnt):
        try:
            v, i = parse_axdr_value(d, i)
            arr.append(v)
        except DecodeError as exc:
            # Wichtig: Nicht das ganze Paket verwerfen, wenn der letzte Teil eines
            # DataNotification-Rahmens unerwartet aussieht. Viele OBIS-Werte stehen
            # dann bereits am Anfang der Struktur und koennen trotzdem genutzt werden.
            LOG.warning("AXDR %s an Element %d/%d bei Offset %d vorzeitig beendet: %s", kind, idx + 1, cnt, i, exc)
            return arr, len(d)
    return arr, i


def parse_axdr_value(d: bytes, i: int) -> Tuple[Any, int]:
    tag, i = read_u8(d, i)

    if tag == 0x00:  # null-data
        return None, i

    if tag == 0x01:  # array
        cnt, i = read_axdr_length(d, i, "array-count")
        return parse_axdr_container(d, i, cnt, "array")

    if tag == 0x02:  # structure
        cnt, i = read_axdr_length(d, i, "structure-count")
        return parse_axdr_container(d, i, cnt, "structure")

    if tag == 0x03:  # boolean
        v, i = read_u8(d, i)
        return bool(v), i

    if tag == 0x05:  # int32
        raw, i = read_n(d, i, 4, "int32")
        return int.from_bytes(raw, "big", signed=True), i

    if tag == 0x06:  # uint32
        raw, i = read_n(d, i, 4, "uint32")
        return int.from_bytes(raw, "big"), i

    if tag == 0x09:  # octet-string
        ln, i = read_axdr_length(d, i, "octet-string")
        return read_n(d, i, ln, "octet-bytes")

    if tag == 0x0A:  # visible-string
        ln, i = read_axdr_length(d, i, "visible-string")
        raw, i = read_n(d, i, ln, "visible-bytes")
        return raw.decode("ascii", errors="replace"), i

    if tag == 0x0C:  # utf8-string
        ln, i = read_axdr_length(d, i, "utf8-string")
        raw, i = read_n(d, i, ln, "utf8-bytes")
        return raw.decode("utf-8", errors="replace"), i

    if tag == 0x0F:  # int8
        raw, i = read_n(d, i, 1, "int8")
        return int.from_bytes(raw, "big", signed=True), i

    if tag == 0x10:  # int16
        raw, i = read_n(d, i, 2, "int16")
        return int.from_bytes(raw, "big", signed=True), i

    if tag == 0x11:  # uint8
        raw, i = read_n(d, i, 1, "uint8")
        return raw[0], i

    if tag == 0x12:  # uint16
        raw, i = read_n(d, i, 2, "uint16")
        return int.from_bytes(raw, "big"), i

    if tag == 0x14:  # int64
        raw, i = read_n(d, i, 8, "int64")
        return int.from_bytes(raw, "big", signed=True), i

    if tag == 0x15:  # uint64
        raw, i = read_n(d, i, 8, "uint64")
        return int.from_bytes(raw, "big"), i

    if tag == 0x16:  # enum
        v, i = read_u8(d, i)
        return v, i

    if tag == 0x17:  # float32
        raw, i = read_n(d, i, 4, "float32")
        return struct.unpack(">f", raw)[0], i

    if tag == 0x18:  # float64
        raw, i = read_n(d, i, 8, "float64")
        return struct.unpack(">d", raw)[0], i

    if tag == 0x19:  # datetime (12 bytes)
        raw, i = read_n(d, i, 12, "datetime")
        return raw, i

    if tag == 0x1A:  # date (5 bytes)
        raw, i = read_n(d, i, 5, "date")
        return raw, i

    if tag == 0x1B:  # time (4 bytes)
        raw, i = read_n(d, i, 4, "time")
        return raw, i

    raise DecodeError(f"unsupported AXDR tag 0x{tag:02X} at offset {i - 1}")


def decode_dt12(dt12: bytes) -> str:
    if len(dt12) != 12:
        return dt12.hex().upper()
    year = int.from_bytes(dt12[0:2], "big")
    month, day = dt12[2], dt12[3]
    hour, minute, sec = dt12[5], dt12[6], dt12[7]
    dev = int.from_bytes(dt12[9:11], "big", signed=True)
    status = dt12[11]
    return f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{sec:02d} (dev {dev}m, status 0x{status:02X})"


def decode_axdr_values(apdu: bytes, debug: bool = False) -> Optional[Tuple[str, str, Dict[str, Tuple[Any, int, int]]]]:
    if apdu[:2] != b"\x0F\x80":
        return None

    i = 2
    invoke_raw, i = read_n(apdu, i, 4, "invoke-id")
    invoke = invoke_raw.hex().upper()

    dt12, i = read_n(apdu, i, 12, "datetime")
    ts = decode_dt12(dt12)

    dataset, i = parse_axdr_value(apdu, i)
    if not isinstance(dataset, list):
        raise DecodeError("top-level dataset is not a list/structure")

    def is_obis(x: Any) -> bool:
        return isinstance(x, (bytes, bytearray)) and len(x) == 6

    def is_scaler_unit(x: Any) -> bool:
        return isinstance(x, list) and len(x) == 2 and isinstance(x[0], int) and isinstance(x[1], int)

    obis_map: Dict[str, Tuple[Any, int, int]] = {}
    idx = 0
    while idx <= len(dataset) - 3:
        a, b, c = dataset[idx], dataset[idx + 1], dataset[idx + 2]
        if is_obis(a) and is_scaler_unit(c):
            obis_hex = bytes(a).hex().upper()
            val = b
            scaler, unit = c[0], c[1]
            if isinstance(val, int) and isinstance(scaler, int):
                val = val * (10 ** scaler)
            obis_map[obis_hex] = (val, scaler, unit)
            idx += 3
        else:
            idx += 1

    if i < len(apdu):
        LOG.debug("AXDR parsing endete vor APDU-Ende: offset=%d rest=%d bytes", i, len(apdu) - i)

    if debug and not obis_map:
        LOG.debug("AXDR decoded, aber keine OBIS-Werte erkannt; dataset_len=%d", len(dataset))
    elif obis_map:
        known = sum(1 for obis_hex in obis_map if obis_hex in OBIS_SENSORS)
        unknown = [obis_hex for obis_hex in obis_map if obis_hex not in OBIS_SENSORS]
        LOG.info("OBIS-Werte erkannt: %d (bekannt=%d, unbekannt=%d)", len(obis_map), known, len(unknown))
        if debug and unknown:
            LOG.debug("Unbekannte OBIS: %s", ", ".join(sorted(unknown)))

    return invoke, ts, obis_map


def stable_device_id(system_title: bytes) -> str:
    h = hashlib.sha1(system_title).hexdigest().upper()
    return f"kaifa_{h[:8]}"


def apply_transform(sensor_def: dict, value: Any) -> Any:
    if value is None:
        return None
    tf = sensor_def.get("value_transform")
    if tf == "wh_to_kwh":
        try:
            return float(value) / 1000.0
        except Exception:
            return value
    return value


def mqtt_safe_topic(s: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ("_", "-") else "_" for ch in s)


def mqtt_wait_publish(info: Any, topic: str, timeout: float = 0.2) -> None:
    if info is None:
        raise PublishError(f"publish returned None for topic {topic}")

    rc = getattr(info, "rc", mqtt.MQTT_ERR_SUCCESS)
    if rc != mqtt.MQTT_ERR_SUCCESS:
        raise PublishError(f"publish rc={rc} for topic {topic}")

    # Paho published asynchron. Ein Queue-OK ist fuer uns bereits ausreichend.
    # wait_for_publish() kann je nach Callback-Thread / Broker-Latenz false oder None
    # liefern, obwohl die Nachricht danach korrekt rausgeht. Deshalb hier nur
    # best-effort warten und keinen Timeout als harten Fehler behandeln.
    try:
        info.wait_for_publish(timeout=timeout)
    except TypeError:
        try:
            info.wait_for_publish()
        except Exception:
            pass
    except Exception:
        pass


class MqttBridge:
    def __init__(self, args: argparse.Namespace, bridge_state: BridgeState) -> None:
        if mqtt is None:
            raise SystemExit("paho-mqtt fehlt. Install: pip install paho-mqtt")
        self.args = args
        self.bridge_state = bridge_state
        self.service_availability_topic = f"{args.base_topic}/bridge/availability"
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=args.mqtt_client_id)
        if args.mqtt_user or args.mqtt_pass:
            self.client.username_pw_set(args.mqtt_user, args.mqtt_pass)
        self.client.will_set(self.service_availability_topic, payload="offline", qos=1, retain=True)
        self.client.reconnect_delay_set(min_delay=1, max_delay=30)
        self.client.on_connect = self.on_connect
        self.client.on_disconnect = self.on_disconnect

    def connect(self) -> None:
        self.client.connect(self.args.mqtt_host, self.args.mqtt_port, keepalive=30)
        self.client.loop_start()

    def stop(self) -> None:
        try:
            self.publish_service_availability(False)
        except Exception:
            pass
        try:
            self.client.loop_stop()
            self.client.disconnect()
        except Exception:
            pass

    def on_connect(self, client, userdata, flags, reason_code, properties=None) -> None:
        if reason_code == 0:
            self.bridge_state.connected = True
            LOG.info("MQTT verbunden: %s:%s", self.args.mqtt_host, self.args.mqtt_port)
        else:
            self.bridge_state.connected = False
            LOG.error("MQTT connect failed: %s", reason_code)

    def on_disconnect(self, client, userdata, disconnect_flags, reason_code, properties=None) -> None:
        self.bridge_state.connected = False
        if reason_code != 0:
            LOG.warning("MQTT getrennt (rc=%s, flags=%s) – reconnect läuft…", reason_code, disconnect_flags)

    def publish_service_availability(self, online: bool) -> None:
        payload = "online" if online else "offline"
        mqtt_wait_publish(
            self.client.publish(self.service_availability_topic, payload, qos=1, retain=True),
            self.service_availability_topic,
        )
        self.bridge_state.service_online = online

    def publish_discovery(self, device_id: str, device_name: str) -> None:
        state_topic = f"{self.args.base_topic}/{device_id}/state"
        device_payload = {
            "identifiers": [device_id],
            "name": device_name,
            "manufacturer": "Kaifa",
            "model": "MA309 (DLMS/M-Bus)",
        }
        for _, sdef in OBIS_SENSORS.items():
            sensor_key = sdef["key"]
            unique_id = f"{device_id}_{sensor_key}"
            object_id = mqtt_safe_topic(unique_id)
            config_topic = f"{self.args.discovery_prefix}/sensor/{device_id}/{object_id}/config"
            payload = {
                "name": sdef["name"],
                "unique_id": unique_id,
                "state_topic": state_topic,
                "availability_topic": self.service_availability_topic,
                "value_template": "{{ value_json.%s }}" % sensor_key,
                "device": device_payload,
            }
            if sdef.get("unit") is not None:
                payload["unit_of_measurement"] = sdef["unit"]
            if sdef.get("device_class"):
                payload["device_class"] = sdef["device_class"]
            if sdef.get("state_class"):
                payload["state_class"] = sdef["state_class"]
            mqtt_wait_publish(self.client.publish(config_topic, json.dumps(payload), qos=1, retain=True), config_topic)
        self.bridge_state.discovery_sent = True
        LOG.info("HA Discovery published (%s)", device_id)

    def publish_state(self, device_id: str, state: Dict[str, Any], raw: Dict[str, Any]) -> None:
        state_topic = f"{self.args.base_topic}/{device_id}/state"
        raw_topic = f"{self.args.base_topic}/{device_id}/raw"
        mqtt_wait_publish(self.client.publish(state_topic, json.dumps(state), qos=1, retain=True), state_topic)
        self.client.publish(raw_topic, json.dumps(raw), qos=0, retain=False)
        non_null = sorted(k for k, v in state.items() if not k.startswith("_") and k != "obis_raw" and v is not None)
        LOG.info("State publiziert auf %s (%d Werte): %s", state_topic, len(non_null), ", ".join(non_null) if non_null else "keine bekannten Werte")
        self.bridge_state.last_state_publish_monotonic = time.monotonic()



def build_state_payload(obis_map: Dict[str, Tuple[Any, int, int]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for obis_hex, sdef in OBIS_SENSORS.items():
        t = obis_map.get(obis_hex)
        val = t[0] if t else None
        out[sdef["key"]] = apply_transform(sdef, val)

    power_import = out.get("power_import")
    power_export = out.get("power_export")
    if isinstance(power_import, (int, float)) and isinstance(power_export, (int, float)):
        out["power_net"] = power_import - power_export

    raw = {}
    for obis_hex, (val, scaler, unit) in obis_map.items():
        raw[obis_hex] = {"value": val, "scaler": scaler, "unit": unit}
    out["obis_raw"] = raw
    return out


def process_packet(frame1: bytes, frame2: bytes, key16: bytes, debug: bool) -> Optional[Dict[str, Any]]:
    try:
        l1 = frame1[1]
        l2 = frame2[1]
        payload1 = frame1[4:4 + l1]
        payload2 = frame2[4:4 + l2]
        if len(payload1) != l1 or len(payload2) != l2:
            raise DecodeError("frame payload length mismatch")

        stream = payload1 + payload2[3:]

        i = stream.find(b"\xDB\x08")
        if i < 0 or i + 10 > len(stream):
            raise DecodeError("SystemTitle marker not found")
        st = stream[i + 2:i + 10]

        j = stream.find(b"\x81\xF8\x20", i + 10, i + 10 + 64)
        if j < 0:
            raise DecodeError("cipher block marker 81 F8 20 not found")

        ciphered = stream[j + 2:j + 2 + 0xF8]
        if len(ciphered) != 0xF8:
            raise DecodeError(f"cipher block len {len(ciphered)} != 248")

        sc = ciphered[0]
        ic = ciphered[1:5]
        ctext = ciphered[5:]
        if sc != 0x20:
            raise DecodeError(f"unexpected security control 0x{sc:02X}")

        pt = aes_ctr_suite0(key16, st, ic, ctext, 2)
        if not (len(pt) >= 2 and pt[0] == 0x0F and pt[1] == 0x80):
            raise DecodeError(f"decrypt ok, but APDU head is {pt[:8].hex().upper()}")

        decoded = decode_axdr_values(pt, debug=debug)
        if not decoded:
            raise DecodeError("decode_axdr_values returned no dataset")

        invoke, ts, obis_map = decoded
        if not obis_map:
            raise DecodeError("keine OBIS-Werte im entschluesselten Paket gefunden")
        return {
            "system_title": st,
            "ic": ic,
            "invoke": invoke,
            "timestamp_raw": ts,
            "obis": obis_map,
        }
    except DecodeError as exc:
        if debug:
            LOG.debug("Packet verworfen: %s", exc)
        else:
            LOG.warning("Packet verworfen: %s", exc)
        return None
    except Exception:
        LOG.exception("Unerwarteter Fehler beim Packet-Processing")
        return None


def open_serial_forever(args: argparse.Namespace, bridge_state: BridgeState) -> serial.Serial:
    while True:
        try:
            ser = serial.Serial(
                args.port,
                args.baud,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=args.serial_timeout,
            )
            ser.reset_input_buffer()
            ser.reset_output_buffer()
            bridge_state.last_serial_reopen_monotonic = time.monotonic()
            bridge_state.last_serial_byte_monotonic = time.monotonic()
            LOG.info("Lese %s @ %s 8N1 – warte auf Frames…", args.port, args.baud)
            return ser
        except serial.SerialException as exc:
            bridge_state.serial_error_counter += 1
            LOG.error("Serial open failed (%s). Neuer Versuch in %.1fs", exc, args.reopen_delay_seconds)
            time.sleep(args.reopen_delay_seconds)


def maybe_mark_offline(mq: MqttBridge, bridge_state: BridgeState, args: argparse.Namespace) -> None:
    if bridge_state.last_good_packet_monotonic <= 0:
        return
    age = time.monotonic() - bridge_state.last_good_packet_monotonic
    if age >= args.offline_after_seconds and bridge_state.service_online and bridge_state.connected:
        try:
            mq.publish_service_availability(False)
            LOG.warning("Keine gültigen Pakete seit %.0fs – Availability auf offline gesetzt", age)
        except Exception as exc:
            bridge_state.mqtt_error_counter += 1
            LOG.warning("Availability offline publish fehlgeschlagen: %s", exc)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="/dev/ttyUSB0")
    ap.add_argument("--baud", type=int, default=2400)
    ap.add_argument("--key", default=os.environ.get("KAIFA_GUEK", ""), help="GUEK 32-hex (oder env KAIFA_GUEK)")
    ap.add_argument("--debug", action="store_true")

    ap.add_argument("--mqtt-host", default=MQTT_HOST_DEFAULT)
    ap.add_argument("--mqtt-port", type=int, default=MQTT_PORT_DEFAULT)
    ap.add_argument("--mqtt-user", default=MQTT_USER_DEFAULT)
    ap.add_argument("--mqtt-pass", default=MQTT_PASS_DEFAULT)
    ap.add_argument("--mqtt-client-id", default=os.getenv("MQTT_CLIENT_ID", "kaifa-ma309-bridge"))

    ap.add_argument("--base-topic", default=BASE_TOPIC_DEFAULT)
    ap.add_argument("--discovery-prefix", default=MQTT_DISCOVERY_PREFIX_DEFAULT)
    ap.add_argument("--serial-timeout", type=float, default=float(os.getenv("SERIAL_TIMEOUT", "1.0")))
    ap.add_argument("--serial-stall-seconds", type=float, default=float(os.getenv("SERIAL_STALL_SECONDS", "90")))
    ap.add_argument("--pending-frame-timeout", type=float, default=float(os.getenv("PENDING_FRAME_TIMEOUT", "10")))
    ap.add_argument("--offline-after-seconds", type=float, default=float(os.getenv("OFFLINE_AFTER_SECONDS", "120")))
    ap.add_argument("--publish-interval-seconds", type=float, default=float(os.getenv("PUBLISH_INTERVAL_SECONDS", "0")))
    ap.add_argument("--reopen-delay-seconds", type=float, default=float(os.getenv("REOPEN_DELAY_SECONDS", "3")))

    args = ap.parse_args()
    setup_logging(args.debug)

    key_hex = (args.key or "").strip()
    if not key_hex:
        raise SystemExit("Key fehlt: --key <32hex> oder env KAIFA_GUEK setzen.")

    try:
        key16 = bytes.fromhex(key_hex)
    except ValueError as exc:
        raise SystemExit(f"Ungültiger Key-HEX: {exc}") from exc

    if len(key16) != 16:
        raise SystemExit("Key muss 16 bytes (32 hex) sein")

    bridge_state = BridgeState()
    mq = MqttBridge(args, bridge_state)
    mq.connect()
    ser = open_serial_forever(args, bridge_state)

    buf = bytearray()
    pending_long: Optional[bytes] = None

    try:
        while True:
            now = time.monotonic()
            maybe_mark_offline(mq, bridge_state, args)

            if pending_long is not None and bridge_state.pending_long_since > 0:
                if now - bridge_state.pending_long_since >= args.pending_frame_timeout:
                    LOG.warning("Zweites Teilframe fehlt seit %.1fs – pending long frame verworfen", now - bridge_state.pending_long_since)
                    pending_long = None
                    bridge_state.pending_long_since = 0.0

            if now - bridge_state.last_serial_byte_monotonic >= args.serial_stall_seconds:
                LOG.warning("Keine seriellen Daten seit %.0fs – Port wird neu geöffnet", now - bridge_state.last_serial_byte_monotonic)
                try:
                    ser.close()
                except Exception:
                    pass
                buf.clear()
                pending_long = None
                bridge_state.pending_long_since = 0.0
                ser = open_serial_forever(args, bridge_state)
                continue

            try:
                chunk = ser.read(512)
            except serial.SerialException as exc:
                bridge_state.serial_error_counter += 1
                LOG.error("Serial error: %s – Port wird neu geöffnet", exc)
                try:
                    ser.close()
                except Exception:
                    pass
                buf.clear()
                pending_long = None
                bridge_state.pending_long_since = 0.0
                time.sleep(args.reopen_delay_seconds)
                ser = open_serial_forever(args, bridge_state)
                continue

            if chunk:
                buf.extend(chunk)
                bridge_state.last_serial_byte_monotonic = time.monotonic()

            while True:
                fr = extract_mbus_frame(buf)
                if fr is None:
                    break

                bridge_state.last_frame_monotonic = time.monotonic()

                if args.debug:
                    LOG.debug("frame total=%d L=0x%02X head=%s", len(fr), fr[1], fr[:4].hex())

                if fr[1] == 0xFA:
                    pending_long = fr
                    bridge_state.pending_long_since = time.monotonic()
                    continue

                if pending_long is not None and fr[1] == 0x14:
                    pkt = process_packet(pending_long, fr, key16, args.debug)
                    pending_long = None
                    bridge_state.pending_long_since = 0.0

                    if not pkt:
                        bridge_state.decode_error_counter += 1
                        continue

                    st = pkt["system_title"]
                    if bridge_state.device_id is None:
                        bridge_state.device_id = stable_device_id(st)
                        LOG.info("Device erkannt: %s (SystemTitle=%s)", bridge_state.device_id, st.hex().upper())

                    if bridge_state.connected and not bridge_state.service_online:
                        try:
                            mq.publish_service_availability(True)
                        except Exception as exc:
                            bridge_state.mqtt_error_counter += 1
                            LOG.warning("Availability online publish fehlgeschlagen: %s", exc)

                    if bridge_state.connected and bridge_state.device_id and not bridge_state.discovery_sent:
                        try:
                            mq.publish_discovery(
                                bridge_state.device_id,
                                device_name=f"Smartmeter {bridge_state.device_id}",
                            )
                        except Exception as exc:
                            bridge_state.mqtt_error_counter += 1
                            LOG.warning("Discovery publish fehlgeschlagen: %s", exc)

                    obis_map = pkt["obis"]
                    state = build_state_payload(obis_map)
                    bridge_state.packet_counter += 1
                    bridge_state.last_good_packet_monotonic = time.monotonic()

                    state["_meta"] = {
                        "timestamp": pkt["timestamp_raw"],
                        "timestamp_utc": utc_now_iso(),
                        "invoke": pkt["invoke"],
                        "system_title": st.hex().upper(),
                        "packet_counter": bridge_state.packet_counter,
                        "decode_error_counter": bridge_state.decode_error_counter,
                        "serial_error_counter": bridge_state.serial_error_counter,
                        "mqtt_error_counter": bridge_state.mqtt_error_counter,
                    }

                    raw_payload = {"obis": state["obis_raw"], "_meta": state["_meta"]}

                    can_publish = True
                    if args.publish_interval_seconds > 0 and bridge_state.last_state_publish_monotonic > 0:
                        age = time.monotonic() - bridge_state.last_state_publish_monotonic
                        if age < args.publish_interval_seconds:
                            can_publish = False

                    if bridge_state.device_id and bridge_state.connected and can_publish:
                        try:
                            mq.publish_state(bridge_state.device_id, state, raw_payload)
                        except Exception as exc:
                            bridge_state.mqtt_error_counter += 1
                            LOG.warning("State publish fehlgeschlagen: %s", exc)
                    continue

                pending_long = None
                bridge_state.pending_long_since = 0.0

    except KeyboardInterrupt:
        LOG.info("Stop via KeyboardInterrupt")
    finally:
        try:
            ser.close()
        except Exception:
            pass
        mq.stop()


if __name__ == "__main__":
    main()
