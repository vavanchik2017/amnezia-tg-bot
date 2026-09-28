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
        """Builds standard AmneziaWG .conf file."""
        dns_str = dns or settings.client_dns

        lines = [
            "[Interface]",
            f"Address = {client_ip}/32",
            f"PrivateKey = {client_privkey}",
            f"DNS = {dns_str}"
        ]

        # Standard AWG parameters strictly supported by standalone AmneziaWG apps.
        # S3 and S4 must NOT be included in .conf as they trigger 'Unknown attribute in Interface' in clients.
        keys_order = ["Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"]
        defaults = {
            "Jc": 3, "Jmin": 40, "Jmax": 70, "S1": 15, "S2": 57,
            "H1": 1, "H2": 2, "H3": 3, "H4": 4
        }

        for k in keys_order:
            if k in awg_params and awg_params[k] is not None and str(awg_params[k]).strip() != "":
                lines.append(f"{k} = {awg_params[k]}")
            elif k in defaults:
                lines.append(f"{k} = {defaults[k]}")

        lines.append("")
        lines.append("[Peer]")
        lines.append(f"PublicKey = {server_pubkey}")
        if preshared_key and preshared_key.strip():
            lines.append(f"PresharedKey = {preshared_key.strip()}")
        lines.append(f"Endpoint = {host}:{port}")
        lines.append("AllowedIPs = 0.0.0.0/0, ::/0")
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

        keys_order = ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"]
        json_awg_params = {}
        for k in keys_order:
            if k in awg_params and awg_params[k] is not None and str(awg_params[k]).strip() != "":
                json_awg_params[k] = str(awg_params[k])

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

        # For amnezia-awg2 container, specify 'awg2' block only.
        # If 'awg' is present, the Amnezia VPN app labels it as 'Amnezia Legacy (версия 2)'.
        # Setting 'awg2' causes Amnezia VPN to correctly recognize it as modern AmneziaWG (without Legacy).
        if target_container == "amnezia-awg2":
            container_obj = {
                "container": target_container,
                "awg2": awg_block
            }
        else:
            container_obj = {
                "container": target_container,
                "awg": awg_block
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
