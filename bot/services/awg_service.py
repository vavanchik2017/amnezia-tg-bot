import base64
import io
import ipaddress
import json
import struct
import time
import zlib
from typing import Dict, List, Optional, Tuple, Any
import qrcode
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from bot.config import settings


class AWGService:
    @staticmethod
    def generate_keypair() -> Tuple[str, str]:
        """Generates X25519 WireGuard private and public key in base64."""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()

        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        priv_b64 = base64.b64encode(priv_bytes).decode("utf-8")
        pub_b64 = base64.b64encode(pub_bytes).decode("utf-8")
        return priv_b64, pub_b64

    @staticmethod
    def allocate_next_ip(existing_ips: List[str], subnet_cidr: Optional[str] = None) -> str:
        """Finds next available IP address in the subnet."""
        cidr = subnet_cidr or settings.client_ip_subnet
        network = ipaddress.ip_network(cidr, strict=False)
        used = set(ip.split("/")[0].strip() for ip in existing_ips if ip)

        # Skip .0 (network) and .1 (usual server gateway)
        for host in network.hosts():
            ip_str = str(host)
            if ip_str.endswith(".1"):
                continue
            if ip_str not in used:
                return ip_str

        raise RuntimeError(f"No available IP addresses in subnet {cidr}")

    @staticmethod
    def build_native_conf(
        client_privkey: str,
        client_ip: str,
        server_pubkey: str,
        host: str,
        port: int,
        awg_params: Dict[str, Any],
        dns: Optional[str] = None,
        preshared_key: Optional[str] = None
    ) -> str:
        """
        Builds standard, universally compatible AmneziaWG 1.0 .conf file.
        Strictly supported by AmneziaWG apps on Windows, Android, iOS, macOS,
        Linux, and routers (Keenetic, OpenWrt, etc.).
        """
        dns_str = dns or settings.client_dns

        lines = [
            "[Interface]",
            f"Address = {client_ip}/32",
            f"DNS = {dns_str}",
            f"PrivateKey = {client_privkey}"
        ]

        # Standard AWG 1.0 parameters strictly supported by all AmneziaWG clients.
        # S3, S4, and I1-I5 are CPS / AWG 2.0 extensions that must NOT be present in standard .conf,
        # as they trigger 'Unknown attribute in Interface' or 'Initpacketmagic' parse errors.
        keys_order = ["Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"]
        defaults = {
            "Jc": 4, "Jmin": 10, "Jmax": 50,
            "S1": 137, "S2": 125,
            "H1": 1310492814,
            "H2": 2113096957,
            "H3": 2140553016,
            "H4": 2146569343
        }

        for k in keys_order:
            val = awg_params.get(k)
            if val is None or str(val).strip() == "":
                val = defaults.get(k)
            val_str = str(val).strip()

            # For H1-H4, standard AmneziaWG clients only accept a single integer.
            # If server params specify a range (e.g. '1310492814-1344318976'), take the first integer.
            if k in ["H1", "H2", "H3", "H4"] and "-" in val_str:
                val_str = val_str.split("-")[0].strip()

            lines.append(f"{k} = {val_str}")

        lines.append("")
        lines.append("[Peer]")
        lines.append(f"PublicKey = {server_pubkey}")
        if preshared_key and preshared_key.strip() and preshared_key.strip() != "(none)":
            lines.append(f"PresharedKey = {preshared_key.strip()}")
        lines.append("AllowedIPs = 0.0.0.0/0, ::/0")
        lines.append(f"Endpoint = {host}:{port}")
        lines.append("PersistentKeepalive = 25\n")

        return "\n".join(lines)

    @staticmethod
    def build_awg2_conf(
        client_privkey: str,
        client_ip: str,
        server_pubkey: str,
        host: str,
        port: int,
        awg_params: Dict[str, Any],
        dns: Optional[str] = None,
        preshared_key: Optional[str] = None
    ) -> str:
        """
        Builds modern AmneziaWG 2.0 .conf file (with S3/S4, header ranges, and I1 if present).
        Crucially omits empty fields (I2-I5) to prevent syntax errors on Android and Windows clients.
        """
        dns_str = dns or settings.client_dns

        lines = [
            "[Interface]",
            f"Address = {client_ip}/32",
            f"DNS = {dns_str}",
            f"PrivateKey = {client_privkey}"
        ]

        keys_order = [
            "Jc", "Jmin", "Jmax",
            "S1", "S2", "S3", "S4",
            "H1", "H2", "H3", "H4",
            "I1", "I2", "I3", "I4", "I5"
        ]
        defaults = {
            "Jc": 4, "Jmin": 10, "Jmax": 50,
            "S1": 137, "S2": 125, "S3": 62, "S4": 10,
            "H1": "1310492814-1344318976",
            "H2": "2113096957-2126172807",
            "H3": "2140553016-2146460046",
            "H4": "2146569343-2147347247"
        }

        for k in keys_order:
            val = awg_params.get(k)
            if val is None or str(val).strip() == "":
                val = defaults.get(k)
            if val is not None:
                val_str = str(val).strip()
                # Do NOT emit empty lines like 'I2 = '
                if val_str:
                    lines.append(f"{k} = {val_str}")

        lines.append("")
        lines.append("[Peer]")
        lines.append(f"PublicKey = {server_pubkey}")
        if preshared_key and preshared_key.strip() and preshared_key.strip() != "(none)":
            lines.append(f"PresharedKey = {preshared_key.strip()}")
        lines.append("AllowedIPs = 0.0.0.0/0, ::/0")
        lines.append(f"Endpoint = {host}:{port}")
        lines.append("PersistentKeepalive = 25\n")

        return "\n".join(lines)


    @staticmethod
    def encode_vpn_uri(profile: dict) -> str:
        """
        Encodes server profile JSON into Amnezia's official vpn://<base64url> format:
        4-byte Big-Endian length header + zlib deflate (level 8) + URL-safe base64.
        """
        raw_data = json.dumps(profile, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        header = struct.pack(">I", len(raw_data))
        compressed = zlib.compress(raw_data, level=8)
        payload = header + compressed
        b64url = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
        return f"vpn://{b64url}"

    @staticmethod
    def build_amnezia_vpn_json(
        client_name: str,
        client_privkey: str,
        client_pubkey: str,
        client_ip: str,
        server_pubkey: str,
        host: str,
        port: int,
        awg_params: Dict[str, Any],
        dns: Optional[str] = None,
        preshared_key: Optional[str] = None,
        container_name: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Builds Amnezia VPN (.vpn) JSON profile and vpn:// connection link.
        Uses modern AmneziaWG 2.0 / 3.x schema and official Amnezia vpn:// encoding.
        Returns: (json_string, vpn_uri)
        """
        target_container = container_name or settings.vpn_container_name or "amnezia-awg2"
        dns_str = dns or settings.client_dns
        dns_parts = [d.strip() for d in dns_str.split(",") if d.strip()]
        dns1 = dns_parts[0] if len(dns_parts) > 0 else "1.1.1.1"
        dns2 = dns_parts[1] if len(dns_parts) > 1 else "1.0.0.1"

        native_conf = AWGService.build_native_conf(
            client_privkey=client_privkey,
            client_ip=client_ip,
            server_pubkey=server_pubkey,
            host=host,
            port=port,
            awg_params=awg_params,
            dns=dns_str,
            preshared_key=preshared_key
        )

        keys_order = [
            "Jc", "Jmin", "Jmax",
            "S1", "S2", "S3", "S4",
            "H1", "H2", "H3", "H4",
            "I1", "I2", "I3", "I4", "I5"
        ]
        defaults = {
            "Jc": "4", "Jmin": "10", "Jmax": "50",
            "S1": "137", "S2": "125", "S3": "62", "S4": "10",
            "H1": "1310492814-1344318976",
            "H2": "2113096957-2126172807",
            "H3": "2140553016-2146460046",
            "H4": "2146569343-2147347247",
            "I1": "<b 0x084481800001000300000000077469636b65747306776964676574096b696e6f706f69736b0272750000010001c00c0005000100000039001806776964676574077469636b6574730679616e646578c025c0390005000100000039002b1765787465726e616c2d7469636b6574732d776964676574066166697368610679616e646578036e657400c05d000100010000001c000457fafe25>",
            "I2": "", "I3": "", "I4": "", "I5": ""
        }
        json_awg_params = {}
        for k in keys_order:
            if k in awg_params and awg_params[k] is not None and str(awg_params[k]).strip() != "":
                json_awg_params[k] = str(awg_params[k]).strip()
            elif k in defaults and defaults[k]:
                json_awg_params[k] = defaults[k]

        awg_last_config = {
            **json_awg_params,
            "allowed_ips": ["0.0.0.0/0", "::/0"],
            "clientId": client_pubkey,
            "client_ip": client_ip,
            "client_priv_key": client_privkey,
            "client_pub_key": client_pubkey,
            "config": native_conf,
            "hostName": host,
            "mtu": "1376",
            "persistent_keep_alive": 25,
            "port": int(port),
            "server_pub_key": server_pubkey,
            "transport_proto": "udp"
        }
        if preshared_key and preshared_key.strip():
            awg_last_config["psk_key"] = preshared_key.strip()

        # Protocol version: "3.1" if v3 params exist, else "2"
        has_v3 = any(k in awg_params for k in ["HeaderProtectionKey", "RekeyAfterTime", "RandomTrailers", "DisableCookies"])
        protocol_version = "3.1" if has_v3 else "2"

        awg_block = {
            **json_awg_params,
            "protocol_version": protocol_version,
            "last_config": json.dumps(awg_last_config, ensure_ascii=False),
            "port": str(port),
            "transport_proto": "udp"
        }

        # Ensure both 'awg' and 'awg2' keys are present in container_obj.
        # The official Amnezia VPN client resolves the protocol config under 'awg' (ProtocolUtils::key_proto_config_data).
        # Omitting 'awg' causes client ErrorCode 101 (Internal error / protocol missing).
        container_obj = {
            "container": target_container,
            "awg": awg_block,
            "awg2": awg_block
        }

        profile = {
            "containers": [container_obj],
            "defaultContainer": target_container,
            "description": client_name,
            "dns1": dns1,
            "dns2": dns2,
            "hostName": host
        }

        json_str = json.dumps(profile, indent=2, ensure_ascii=False)
        vpn_uri = AWGService.encode_vpn_uri(profile)

        return json_str, vpn_uri

    @staticmethod
    def generate_qr_code(data: str) -> io.BytesIO:
        """Renders string data into a crisp PNG QR-code BytesIO buffer."""
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=8,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        bio = io.BytesIO()
        bio.name = "qr.png"
        img.save(bio, "PNG")
        bio.seek(0)
        return bio

    @staticmethod
    def format_bytes(num_bytes: int) -> str:
        """Formats byte count into human-readable string."""
        if num_bytes < 1024:
            return f"{num_bytes} B"
        elif num_bytes < 1024 ** 2:
            return f"{num_bytes / 1024:.2f} KB"
        elif num_bytes < 1024 ** 3:
            return f"{num_bytes / (1024 ** 2):.2f} MB"
        else:
            return f"{num_bytes / (1024 ** 3):.2f} GB"

    @staticmethod
    def format_handshake(epoch_ts: int) -> str:
        """Formats handshake timestamp into human-readable relative time."""
        if not epoch_ts or epoch_ts <= 0:
            return "Никогда"
        now = int(time.time())
        diff = now - epoch_ts
        if diff < 60:
            return f"{diff} сек. назад"
        elif diff < 3600:
            return f"{diff // 60} мин. назад"
        elif diff < 86400:
            return f"{diff // 3600} ч. назад"
        else:
            return f"{diff // 86400} дн. назад"


awg_service = AWGService()
