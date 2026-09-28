import base64
import io
import ipaddress
import json
import time
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
        used = set(existing_ips)

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
        dns: Optional[str] = None
    ) -> str:
        """Builds standard AmneziaWG .conf file."""
        dns_str = dns or settings.client_dns
        return (
            f"[Interface]\n"
            f"Address = {client_ip}/32\n"
            f"PrivateKey = {client_privkey}\n"
            f"DNS = {dns_str}\n"
            f"Jc = {awg_params.get('Jc', 3)}\n"
            f"Jmin = {awg_params.get('Jmin', 40)}\n"
            f"Jmax = {awg_params.get('Jmax', 70)}\n"
            f"S1 = {awg_params.get('S1', 15)}\n"
            f"S2 = {awg_params.get('S2', 57)}\n"
            f"H1 = {awg_params.get('H1', 1)}\n"
            f"H2 = {awg_params.get('H2', 2)}\n"
            f"H3 = {awg_params.get('H3', 3)}\n"
            f"H4 = {awg_params.get('H4', 4)}\n\n"
            f"[Peer]\n"
            f"PublicKey = {server_pubkey}\n"
            f"Endpoint = {host}:{port}\n"
            f"AllowedIPs = 0.0.0.0/0, ::/0\n"
            f"PersistentKeepalive = 25\n"
        )

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
        dns: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Builds Amnezia VPN (.vpn) JSON profile and vpn:// connection link.
        Returns: (json_string, vpn_uri)
        """
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
            dns=dns_str
        )

        awg_last_config = {
            "H1": str(awg_params.get("H1", 1)),
            "H2": str(awg_params.get("H2", 2)),
            "H3": str(awg_params.get("H3", 3)),
            "H4": str(awg_params.get("H4", 4)),
            "Jc": str(awg_params.get("Jc", 3)),
            "Jmin": str(awg_params.get("Jmin", 40)),
            "Jmax": str(awg_params.get("Jmax", 70)),
            "S1": str(awg_params.get("S1", 15)),
            "S2": str(awg_params.get("S2", 57)),
            "client_ip": client_ip,
            "client_priv_key": client_privkey,
            "client_pub_key": client_pubkey,
            "config": native_conf,
            "hostName": host,
            "port": str(port),
            "server_pub_key": server_pubkey,
            "transport_proto": "udp"
        }

        profile = {
            "containers": [
                {
                    "container": "amnezia-awg",
                    "awg": {
                        "last_config": json.dumps(awg_last_config, ensure_ascii=False),
                        "port": str(port),
                        "transport_proto": "udp",
                        **awg_last_config
                    }
                }
            ],
            "defaultContainer": "amnezia-awg",
            "description": client_name,
            "dns1": dns1,
            "dns2": dns2,
            "hostName": host
        }

        json_str = json.dumps(profile, indent=2, ensure_ascii=False)
        # vpn:// link format used by Amnezia
        b64_json = base64.b64encode(json.dumps(profile).encode("utf-8")).decode("utf-8")
        vpn_uri = f"vpn://{b64_json}"

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
