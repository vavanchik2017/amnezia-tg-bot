import asyncio
import base64
import ipaddress
import json
import logging
import re
import time
import urllib.request
from typing import Dict, List, Optional, Tuple, Any
import docker
from bot.config import settings
from bot.database import models

logger = logging.getLogger(__name__)


class DockerService:
    def __init__(self):
        self._client = None
        self._cached_server_info: Optional[Dict[str, Any]] = None
        self._cached_psk: Optional[str] = None
        self._cached_subnet: Optional[str] = None
        self._config_file_path: Optional[str] = None
        self._wg_bin = "wg"

    def _get_client(self) -> docker.DockerClient:
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    async def get_container(self):
        def _get():
            client = self._get_client()
            return client.containers.get(settings.vpn_container_name)
        return await asyncio.to_thread(_get)

    async def exec_cmd(self, cmd: str) -> Tuple[int, str]:
        def _run():
            try:
                container = self._get_client().containers.get(settings.vpn_container_name)
                # Ensure execution through sh -c for proper environment and argument parsing
                exec_cmd = ["sh", "-c", cmd] if isinstance(cmd, str) else cmd
                res = container.exec_run(exec_cmd)
                output = res.output.decode("utf-8", errors="replace").strip()
                return res.exit_code, output
            except docker.errors.NotFound:
                try:
                    all_c = [c.name for c in self._get_client().containers.list()]
                except Exception:
                    all_c = []
                err = f"Контейнер '{settings.vpn_container_name}' не найден в Docker! Запущенные контейнеры: {all_c}"
                logger.error(err)
                return -1, err
            except Exception as e:
                logger.error(f"Error executing command in container '{settings.vpn_container_name}': {e}")
                return -1, str(e)
        return await asyncio.to_thread(_run)

    async def check_health(self) -> Dict[str, Any]:
        """Check if Docker socket and VPN container are reachable."""
        try:
            container = await self.get_container()
            status = container.status
            # Check wg tool
            code, out = await self.exec_cmd("which awg || which wg")
            bin_name = out.split("/")[-1].strip() if code == 0 else "wg"
            if bin_name in ["awg", "wg"]:
                self._wg_bin = bin_name

            return {
                "ok": status == "running",
                "status": status,
                "container": settings.vpn_container_name,
                "tool": self._wg_bin
            }
        except Exception as e:
            return {
                "ok": False,
                "error": str(e)
            }

    async def get_wg_dump(self) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Executes 'wg show all dump' (or 'awg show all dump') inside container.
        Returns: (interface_info_dict, list_of_peers_dict)
        """
        dump_commands = [
            f"{self._wg_bin} show all dump",
            "awg show all dump",
            "wg show all dump",
            f"{self._wg_bin} show dump",
            "awg show dump",
            "wg show dump"
        ]

        out = ""
        code = -1
        last_out = ""
        for cmd in dump_commands:
            code, out = await self.exec_cmd(cmd)
            if code == 0 and out.strip():
                if "awg" in cmd:
                    self._wg_bin = "awg"
                elif "wg" in cmd and self._wg_bin != "awg":
                    self._wg_bin = "wg"
                break
            else:
                last_out = out

        if code != 0 or not out.strip():
            self._last_error = f"Код {code}: {last_out or out or 'пустой ответ'}"
            logger.error(f"Failed to get wg dump. Exit code: {code}, output: {last_out or out}")
            return None, []

        lines = [line.strip() for line in out.splitlines() if line.strip()]
        if not lines:
            return None, []

        # The first line of WireGuard/AmneziaWG dump is ALWAYS the interface definition
        first_line = lines[0]
        parts = [p.strip() for p in first_line.split("\t") if p.strip()]
        if len(parts) < 3:
            parts = first_line.split()

        if len(parts) < 3:
            self._last_error = f"Некорректная первая строка дампа: {first_line[:50]}"
            logger.error(self._last_error)
            return None, []

        # Check if first column is interface name or base64 key
        if len(parts[0]) == 44 and parts[0].endswith("="):
            # Format: <privkey> <pubkey> <port> [<fwmark>] [<awg_params...>]
            iface = settings.wg_interface or "awg0"
            privkey = parts[0]
            pubkey = parts[1]
            port = int(parts[2]) if parts[2].isdigit() else parts[2]
            fwmark = parts[3] if len(parts) > 3 else "off"
        else:
            # Format: <iface> <privkey> <pubkey> <port> [<fwmark>] [<awg_params...>]
            iface = parts[0]
            privkey = parts[1]
            pubkey = parts[2]
            port = int(parts[3]) if parts[3].isdigit() else parts[3]
            fwmark = parts[4] if len(parts) > 4 else "off"

        def _parse_p(val_str: str):
            val_str = val_str.strip()
            return int(val_str) if val_str.isdigit() else val_str

        awg_dump_params = {}
        start_awg_idx = 4 if (len(parts[0]) == 44 and parts[0].endswith("=")) else 5
        # If AWG parameters are present in dump: jc, jmin, jmax, s1, s2, s3, s4, h1, h2, h3, h4
        if len(parts) >= start_awg_idx + 11:
            try:
                awg_dump_params = {
                    "Jc": _parse_p(parts[start_awg_idx]),
                    "Jmin": _parse_p(parts[start_awg_idx + 1]),
                    "Jmax": _parse_p(parts[start_awg_idx + 2]),
                    "S1": _parse_p(parts[start_awg_idx + 3]),
                    "S2": _parse_p(parts[start_awg_idx + 4]),
                    "S3": _parse_p(parts[start_awg_idx + 5]),
                    "S4": _parse_p(parts[start_awg_idx + 6]),
                    "H1": _parse_p(parts[start_awg_idx + 7]),
                    "H2": _parse_p(parts[start_awg_idx + 8]),
                    "H3": _parse_p(parts[start_awg_idx + 9]),
                    "H4": _parse_p(parts[start_awg_idx + 10])
                }
                logger.info(f"Loaded live AWG params from dump line: {awg_dump_params}")
            except Exception as e:
                logger.warning(f"Could not parse AWG params from dump line: {e}")
        elif len(parts) >= start_awg_idx + 9:
            # Fallback for AWG 1.0 (without s3/s4): jc, jmin, jmax, s1, s2, h1, h2, h3, h4
            try:
                awg_dump_params = {
                    "Jc": _parse_p(parts[start_awg_idx]),
                    "Jmin": _parse_p(parts[start_awg_idx + 1]),
                    "Jmax": _parse_p(parts[start_awg_idx + 2]),
                    "S1": _parse_p(parts[start_awg_idx + 3]),
                    "S2": _parse_p(parts[start_awg_idx + 4]),
                    "H1": _parse_p(parts[start_awg_idx + 5]),
                    "H2": _parse_p(parts[start_awg_idx + 6]),
                    "H3": _parse_p(parts[start_awg_idx + 7]),
                    "H4": _parse_p(parts[start_awg_idx + 8])
                }
                logger.info(f"Loaded live AWG 1.0 params from dump line: {awg_dump_params}")
            except Exception as e:
                logger.warning(f"Could not parse AWG params from dump line: {e}")

        interface_info = {
            "interface": iface,
            "private_key": privkey,
            "public_key": pubkey,
            "listen_port": port,
            "fwmark": fwmark,
            "awg_params": awg_dump_params
        }

        # Subsequent lines are peers
        peers = []
        for line in lines[1:]:
            p_parts = [p.strip() for p in line.split("\t") if p.strip()]
            if len(p_parts) < 4:
                p_parts = line.split()

            # Skip secondary interface lines if any
            if len(p_parts) >= 2 and len(p_parts[1]) == 44 and p_parts[1].endswith("=") and len(p_parts) < 8:
                continue

            if len(p_parts) >= 6:
                has_iface_col = len(p_parts) >= 8 and not (len(p_parts[0]) == 44 and p_parts[0].endswith("="))
                if has_iface_col:
                    p_iface = p_parts[0]
                    p_pubkey = p_parts[1]
                    p_psk = p_parts[2]
                    p_endpoint = p_parts[3]
                    p_ips = p_parts[4]
                    p_hs = int(p_parts[5]) if len(p_parts) > 5 and p_parts[5].isdigit() else 0
                    p_rx = int(p_parts[6]) if len(p_parts) > 6 and p_parts[6].isdigit() else 0
                    p_tx = int(p_parts[7]) if len(p_parts) > 7 and p_parts[7].isdigit() else 0
                    p_keepalive = int(p_parts[8]) if len(p_parts) > 8 and p_parts[8].isdigit() else 0
                else:
                    p_iface = iface
                    p_pubkey = p_parts[0]
                    p_psk = p_parts[1]
                    p_endpoint = p_parts[2]
                    p_ips = p_parts[3]
                    p_hs = int(p_parts[4]) if len(p_parts) > 4 and p_parts[4].isdigit() else 0
                    p_rx = int(p_parts[5]) if len(p_parts) > 5 and p_parts[5].isdigit() else 0
                    p_tx = int(p_parts[6]) if len(p_parts) > 6 and p_parts[6].isdigit() else 0
                    p_keepalive = int(p_parts[7]) if len(p_parts) > 7 and p_parts[7].isdigit() else 0

                peer = {
                    "interface": p_iface,
                    "public_key": p_pubkey,
                    "preshared_key": p_psk,
                    "endpoint": p_endpoint,
                    "allowed_ips": p_ips,
                    "latest_handshake": p_hs,
                    "rx_bytes": p_rx,
                    "tx_bytes": p_tx,
                    "persistent_keepalive": p_keepalive
                }
                peers.append(peer)

        return interface_info, peers

    async def find_config_file(self, iface: str) -> Optional[str]:
        """Finds the .conf file inside container (e.g. /etc/amnezia/amneziawg/awg0.conf)."""
        if self._config_file_path:
            return self._config_file_path

        candidates = [
            f"/etc/amnezia/amneziawg/{iface}.conf",
            f"/etc/wireguard/{iface}.conf",
            f"/opt/amnezia/awg/{iface}.conf",
            f"/etc/amnezia/amneziawg/awg0.conf",
            f"/etc/wireguard/wg0.conf"
        ]

        for path in candidates:
            code, _ = await self.exec_cmd(f"test -f {path}")
            if code == 0:
                self._config_file_path = path
                return path

        # Try searching with grep for H1 or Jc in /etc and /opt
        code, out = await self.exec_cmd("grep -l -E 'H1|Jc' /etc/*.conf /etc/*/*.conf /etc/*/*/*.conf /opt/*/*.conf /opt/*/*/*.conf 2>/dev/null")
        if code == 0 and out.strip():
            first_found = out.splitlines()[0].strip()
            self._config_file_path = first_found
            logger.info(f"Located AWG config file: {first_found}")
            return first_found

        # Try searching with find
        code, out = await self.exec_cmd("find /etc /opt -name '*.conf' 2>/dev/null")
        if code == 0 and out:
            for line in out.splitlines():
                if iface in line or "awg" in line or "wg" in line:
                    self._config_file_path = line.strip()
                    return self._config_file_path

        return None

    async def get_awg_params(self, iface: str) -> Dict[str, Any]:
        """Extracts standard AmneziaWG obfuscation parameters from server config file."""
        config_path = await self.find_config_file(iface)
        params = {
            "Jc": 3,
            "Jmin": 40,
            "Jmax": 70,
            "S1": 15,
            "S2": 57,
            "H1": 1,
            "H2": 2,
            "H3": 3,
            "H4": 4
        }

        if not config_path:
            logger.warning(f"Config file for interface {iface} not found. Using default AWG params.")
            return params

        code, content = await self.exec_cmd(f"cat {config_path}")
        if code != 0 or not content:
            return params

        standard_keys = {
            "JC": "Jc", "JMIN": "Jmin", "JMAX": "Jmax",
            "S1": "S1", "S2": "S2", "S3": "S3", "S4": "S4",
            "H1": "H1", "H2": "H2", "H3": "H3", "H4": "H4"
        }

        in_interface = False
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("[Interface]"):
                in_interface = True
                continue
            if line.startswith("[") and not line.startswith("[Interface]"):
                in_interface = False
                break
            if not in_interface:
                continue

            # Strictly skip commented lines - do not parse inactive parameters like '# I1 = ...'
            if line.startswith("#") or line.startswith(";"):
                continue

            if "=" in line:
                k, v = [p.strip() for p in line.split("=", 1)]
                v = v.split("#", 1)[0].split(";", 1)[0].strip()
                real_key = standard_keys.get(k.upper())
                if real_key and v:
                    try:
                        params[real_key] = int(v)
                    except ValueError:
                        params[real_key] = v

        logger.info(f"Loaded AWG params from {config_path}: {params}")
        return params

    async def get_preshared_key(self) -> Optional[str]:
        """Reads server-wide PSK only if active peers or server configuration actually use it."""
        if self._cached_psk:
            return self._cached_psk

        # 1. Inspect existing peers from wg dump — this is the ultimate ground truth
        _, peers = await self.get_wg_dump()
        has_peers = False
        for p in peers:
            psk = p.get("preshared_key")
            if psk:
                has_peers = True
                if psk != "(none)" and len(psk) == 44:
                    logger.info("Loaded server preshared key from active peer in dump")
                    self._cached_psk = psk
                    return psk

        # If existing peers exist and none of them use PSK, the server definitely does NOT use PSK
        if has_peers:
            logger.info("Active peers in dump do not use PSK (preshared-key is none)")
            return None

        # 2. Check if awg0.conf explicitly defines PresharedKey in existing [Peer] blocks
        config_path = await self.find_config_file("awg0")
        if config_path:
            code, content = await self.exec_cmd(f"grep -m 1 -E '^[[:space:]]*PresharedKey' {config_path} 2>/dev/null")
            if code == 0 and content.strip():
                psk_val = content.split("=", 1)[1].strip()
                if len(psk_val) == 44:
                    self._cached_psk = psk_val
                    return psk_val

        # 3. Only if there are no existing peers at all, check wireguard_psk.key file
        candidates = [
            "/opt/amnezia/awg/wireguard_psk.key",
            "/opt/amnezia/awg/psk.key"
        ]
        for path in candidates:
            code, out = await self.exec_cmd(f"cat {path} 2>/dev/null")
            clean_out = out.strip()
            if code == 0 and clean_out and len(clean_out) == 44:
                logger.info(f"Loaded server preshared key from {path}")
                self._cached_psk = clean_out
                return clean_out

        return None

    async def get_server_public_ip(self) -> str:
        """Determines public IP of the host."""
        if settings.server_host and settings.server_host.strip() and settings.server_host.strip() != "127.0.0.1":
            return settings.server_host.strip()

        # Try from inside VPN container (has network access)
        code, out = await self.exec_cmd("curl -4 -s --connect-timeout 2 https://api.ipify.org || wget -qO- --timeout=2 https://api.ipify.org || curl -4 -s --connect-timeout 2 https://ifconfig.me")
        if code == 0 and out.strip() and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", out.strip()):
            ip = out.strip()
            logger.info(f"Detected public IP via container: {ip}")
            return ip

        def _fetch_ip():
            for url in ["https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"]:
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "curl/7.68.0"})
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        res = resp.read().decode("utf-8").strip()
                        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", res):
                            return res
                except Exception:
                    continue
            return "127.0.0.1"

        ip = await asyncio.to_thread(_fetch_ip)
        logger.info(f"Public IP detection result: {ip}")
        return ip

    async def get_mapped_port(self, internal_port: int) -> int:
        """Finds host port mapped to internal container port if Docker port mapping is used."""
        try:
            container = await self.get_container()
            ports = container.attrs.get("NetworkSettings", {}).get("Ports", {}) or {}
            for port_proto, bindings in ports.items():
                if not bindings:
                    continue
                c_port = int(port_proto.split("/")[0])
                if c_port == internal_port:
                    host_p = bindings[0].get("HostPort")
                    if host_p and str(host_p).isdigit():
                        logger.info(f"Detected host mapped port {host_p} for container port {port_proto}")
                        return int(host_p)
            for port_proto, bindings in ports.items():
                if bindings and "udp" in port_proto:
                    host_p = bindings[0].get("HostPort")
                    if host_p and str(host_p).isdigit():
                        logger.info(f"Detected fallback host UDP port {host_p}")
                        return int(host_p)
        except Exception as e:
            logger.warning(f"Could not inspect container port mappings: {e}")
        return internal_port

    async def get_server_subnet(self) -> str:
        """Determines the active subnet (e.g. 10.8.1.0/24) used by the VPN container."""
        if self._cached_subnet:
            return self._cached_subnet

        # 1. Try reading Address from awg0.conf / wg0.conf
        try:
            iface_info, _ = await self.get_wg_dump()
            iface = iface_info["interface"] if iface_info else (settings.wg_interface or "awg0")
            config_path = await self.find_config_file(iface)
            if config_path:
                code, out = await self.exec_cmd(f"grep -i -E '^[[:space:]]*Address' {config_path} 2>/dev/null")
                if code == 0 and out.strip():
                    for part in out.split("=", 1)[1].split(","):
                        clean_addr = part.strip()
                        if "/" in clean_addr and ":" not in clean_addr:
                            net = ipaddress.ip_network(clean_addr, strict=False)
                            self._cached_subnet = str(net)
                            logger.info(f"Detected server subnet from config Address '{clean_addr}': {self._cached_subnet}")
                            return self._cached_subnet
        except Exception as e:
            logger.warning(f"Could not read subnet from config Address: {e}")

        # 2. Try 'ip -4 -o addr show <iface>' inside container
        try:
            iface = settings.wg_interface or "awg0"
            code, out = await self.exec_cmd(f"ip -4 -o addr show {iface} 2>/dev/null || ip -4 -o addr show awg0 2>/dev/null")
            if code == 0 and out.strip():
                match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+/\d+)', out)
                if match:
                    cidr = match.group(1)
                    net = ipaddress.ip_network(cidr, strict=False)
                    self._cached_subnet = str(net)
                    logger.info(f"Detected server subnet from ip addr '{cidr}': {self._cached_subnet}")
                    return self._cached_subnet
        except Exception as e:
            logger.warning(f"Could not read subnet from ip addr: {e}")

        # 3. Try inspecting existing peers in wg dump
        try:
            _, peers = await self.get_wg_dump()
            for p in peers:
                ips = p.get("allowed_ips", "")
                for ip_item in ips.split(","):
                    ip_item = ip_item.strip()
                    if "/" in ip_item and ":" not in ip_item:
                        ip_clean = ip_item.split("/")[0]
                        octets = ip_clean.split(".")
                        if len(octets) == 4 and octets[0] == "10":
                            inferred = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
                            self._cached_subnet = inferred
                            logger.info(f"Inferred server subnet from active peer IP '{ip_item}': {self._cached_subnet}")
                            return self._cached_subnet
        except Exception as e:
            logger.warning(f"Could not infer subnet from existing peers: {e}")

        # 4. Fallback to settings or default
        fallback = settings.client_ip_subnet or "10.8.1.0/24"
        self._cached_subnet = fallback
        return fallback

    async def get_server_info(self) -> Dict[str, Any]:
        """Collects all server parameters needed to issue client configs."""
        if self._cached_server_info and self._cached_server_info.get("public_key") and self._cached_server_info.get("host") != "127.0.0.1":
            return self._cached_server_info

        iface_info, _ = await self.get_wg_dump()
        if not iface_info:
            detail = getattr(self, "_last_error", "не удалось прочитать дамп интерфейса")
            raise RuntimeError(f"Контейнер '{settings.vpn_container_name}': {detail}")

        iface_name = settings.wg_interface or iface_info["interface"]
        internal_port = iface_info.get("listen_port", 51820)
        mapped_port = await self.get_mapped_port(internal_port)
        port = settings.server_port or mapped_port or internal_port

        public_key = iface_info["public_key"]
        public_ip = await self.get_server_public_ip()
        logger.info(f"Server endpoint resolved to: {public_ip}:{port} (internal port: {internal_port}, mapped host port: {mapped_port})")

        # Config file params are the primary ground truth for obfuscation parameters
        config_awg = await self.get_awg_params(iface_name)
        dump_awg = iface_info.get("awg_params") or {}
        awg_params = config_awg.copy() if config_awg else {}
        for k, v in dump_awg.items():
            if k not in awg_params or awg_params[k] is None:
                awg_params[k] = v
        logger.info(f"Resolved server AWG params for issuing configs: {awg_params}")

        # Server-wide PSK if Amnezia uses one
        psk = await self.get_preshared_key()
        server_subnet = await self.get_server_subnet()

        info = {
            "interface": iface_name,
            "port": port,
            "public_key": public_key,
            "host": public_ip,
            "awg_params": awg_params,
            "preshared_key": psk,
            "subnet": server_subnet
        }
        self._cached_server_info = info
        return info

    async def parse_peer_names_from_config(self) -> Dict[str, str]:
        """Tries to read human-readable peer names from config comments."""
        names = {}
        try:
            iface_info, _ = await self.get_wg_dump()
            iface = iface_info["interface"] if iface_info else "awg0"
            config_path = await self.find_config_file(iface)
            if not config_path:
                return names

            code, content = await self.exec_cmd(f"cat {config_path}")
            if code != 0 or not content:
                return names

            current_comment = None
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("#"):
                    clean = line.lstrip("#").strip()
                    if clean and not clean.startswith("Added by") and not clean.startswith("Auto"):
                        if "=" in clean:
                            clean = clean.split("=", 1)[1].strip()
                        elif ":" in clean:
                            clean = clean.split(":", 1)[1].strip()
                        current_comment = clean
                elif line.startswith("[Peer]"):
                    pass
                elif line.startswith("PublicKey"):
                    parts = line.split("=", 1)
                    if len(parts) == 2:
                        pub = parts[1].strip()
                        if current_comment:
                            names[pub] = current_comment
                            current_comment = None
                elif not line:
                    current_comment = None
        except Exception as e:
            logger.warning(f"Could not parse peer names from config: {e}")
        return names

    async def get_amnezia_clients_table_path(self) -> Optional[str]:
        """Finds the path to Amnezia's clientsTable file inside the container."""
        candidates = [
            "/opt/amnezia/awg/clientsTable",
            "/opt/amnezia/awg/clientsTable.json",
            "/opt/amnezia/clientsTable",
            "/opt/amnezia/wireguard/clientsTable",
            "/etc/amnezia/awg/clientsTable"
        ]
        for path in candidates:
            code, _ = await self.exec_cmd(f"test -f {path}")
            if code == 0:
                return path

        code, out = await self.exec_cmd("find /opt /etc -maxdepth 4 -name '*clientsTable*' 2>/dev/null")
        if code == 0 and out.strip():
            found = out.strip().splitlines()[0].strip()
            if found:
                return found
        return None

    async def read_amnezia_clients_table(self) -> List[Dict[str, Any]]:
        """
        Parses client records from Amnezia's clientsTable file inside container.
        Returns a list of dicts with: name, public_key, private_key, ip.
        """
        path = await self.get_amnezia_clients_table_path()
        if not path:
            logger.info("Amnezia clientsTable not found in container.")
            return []

        code, content = await self.exec_cmd(f"cat {path}")
        if code != 0 or not content.strip():
            logger.warning(f"Could not read {path} or file is empty.")
            return []

        try:
            raw_data = json.loads(content)
        except Exception as e:
            logger.warning(f"JSON decode failed for {path}: {e}")
            return []

        items = []
        if isinstance(raw_data, list):
            items = raw_data
        elif isinstance(raw_data, dict):
            for k in ["clientsTable", "clients", "users", "peers", "data"]:
                if k in raw_data and isinstance(raw_data[k], list):
                    items = raw_data[k]
                    break
                elif k in raw_data and isinstance(raw_data[k], dict):
                    items = list(raw_data[k].values())
                    break
            if not items:
                for val in raw_data.values():
                    if isinstance(val, list):
                        items.extend(val)
                    elif isinstance(val, dict):
                        items.append(val)

        results = []
        for item in items:
            if not isinstance(item, dict):
                continue

            user_data = item.get("userData") or item.get("user_data")
            if isinstance(user_data, str) and user_data.strip().startswith("{"):
                try:
                    user_data = json.loads(user_data)
                except Exception:
                    pass

            name = None
            if isinstance(user_data, dict):
                name = (
                    user_data.get("clientName") or
                    user_data.get("client_name") or
                    user_data.get("name") or
                    user_data.get("userName") or
                    user_data.get("user_name")
                )
            elif isinstance(user_data, str) and user_data.strip() and not user_data.strip().startswith("{"):
                name = user_data.strip()

            if not name:
                name = (
                    item.get("clientName") or
                    item.get("client_name") or
                    item.get("name") or
                    item.get("userName") or
                    item.get("user_name") or
                    item.get("comment") or
                    item.get("description")
                )

            pubkey = (
                item.get("client_pub_key") or
                item.get("clientPubKey") or
                item.get("client_public_key") or
                item.get("clientPublicKey") or
                item.get("publicKey") or
                item.get("public_key") or
                item.get("pub_key") or
                item.get("pubkey") or
                item.get("pubKey")
            )
            if not pubkey and isinstance(user_data, dict):
                pubkey = user_data.get("client_pub_key") or user_data.get("publicKey") or user_data.get("public_key")

            privkey = (
                item.get("client_priv_key") or
                item.get("clientPrivKey") or
                item.get("client_private_key") or
                item.get("clientPrivateKey") or
                item.get("privateKey") or
                item.get("private_key") or
                item.get("priv_key") or
                item.get("privkey") or
                item.get("privKey")
            )
            if not privkey and isinstance(user_data, dict):
                privkey = user_data.get("client_priv_key") or user_data.get("privateKey") or user_data.get("private_key")

            ip = (
                item.get("client_ip") or
                item.get("clientIp") or
                item.get("ip") or
                item.get("ip_address") or
                item.get("address") or
                item.get("allowedIps") or
                item.get("allowed_ips")
            )
            if not ip and isinstance(user_data, dict):
                ip = (
                    user_data.get("client_ip") or
                    user_data.get("clientIp") or
                    user_data.get("ip") or
                    user_data.get("ip_address") or
                    user_data.get("allowedIps") or
                    user_data.get("allowed_ips")
                )

            client_id = item.get("clientId")
            if client_id is None and isinstance(user_data, dict):
                client_id = user_data.get("clientId")
            if client_id is None:
                client_id = item.get("id")

            if not pubkey and client_id and isinstance(client_id, str):
                cleaned_cid = client_id.strip()
                if len(cleaned_cid) == 44 and cleaned_cid.endswith("="):
                    pubkey = cleaned_cid

            config_text = item.get("config") or (user_data.get("config") if isinstance(user_data, dict) else None)
            if config_text and not privkey:
                m = re.search(r"PrivateKey\s*=\s*([A-Za-z0-9+/=]{44})", str(config_text))
                if m:
                    privkey = m.group(1)

            name_str = str(name).strip() if name is not None else ""
            pubkey_str = str(pubkey).strip() if pubkey else ""
            privkey_str = str(privkey).strip() if privkey else ""
            ip_str = str(ip).strip() if ip else ""
            if "/" in ip_str:
                ip_str = ip_str.split("/")[0].strip()

            cid_str = str(client_id).strip() if client_id is not None else None

            if pubkey_str or ip_str or name_str or cid_str:
                results.append({
                    "name": name_str,
                    "public_key": pubkey_str,
                    "private_key": privkey_str,
                    "ip": ip_str,
                    "client_id": cid_str
                })

        logger.info(f"Loaded {len(results)} client records from Amnezia clientsTable ({path}). Sample: {[(r['name'], r['ip']) for r in results[:5]]}")
        return results

    async def save_peer_to_amnezia_table(self, name: str, public_key: str, private_key: str, ip_address: str):
        """Appends newly created client to Amnezia's clientsTable if the file exists."""
        try:
            path = await self.get_amnezia_clients_table_path()
            if not path:
                return

            code, content = await self.exec_cmd(f"cat {path}")
            if code != 0 or not content.strip():
                return

            table = json.loads(content)
            now_str = time.ctime()
            new_client = {
                "clientId": public_key,
                "userData": {
                    "allowedIps": f"{ip_address}/32",
                    "allowed_ips": f"{ip_address}/32",
                    "clientName": name,
                    "creationDate": now_str,
                    "dataReceived": "0 B",
                    "dataSent": "0 B",
                    "latestHandshake": "0"
                }
            }

            if isinstance(table, list):
                found = False
                for c in table:
                    if isinstance(c, dict) and (c.get("clientId") == public_key or c.get("client_pub_key") == public_key or c.get("publicKey") == public_key):
                        if isinstance(c.get("userData"), dict):
                            c["userData"]["clientName"] = name
                            c["userData"]["allowedIps"] = f"{ip_address}/32"
                            c["userData"]["allowed_ips"] = f"{ip_address}/32"
                        found = True
                        break
                if not found:
                    table.append(new_client)
            elif isinstance(table, dict):
                if "clients" in table and isinstance(table["clients"], list):
                    table["clients"].append(new_client)
                else:
                    table[public_key] = new_client

            await self.backup_config_file(path)
            new_json = json.dumps(table, indent=2, ensure_ascii=False)
            b64_str = base64.b64encode(new_json.encode("utf-8")).decode("ascii")
            write_cmd = f"echo '{b64_str}' | base64 -d > {path}"
            w_code, w_out = await self.exec_cmd(write_cmd)
            if w_code == 0:
                logger.info(f"Appended client '{name}' to {path}")
            else:
                logger.warning(f"Failed to write to {path}: {w_out}")
        except Exception as e:
            logger.warning(f"Could not update Amnezia clientsTable: {e}")

    async def remove_peer_from_amnezia_table(self, public_key: str):
        """Removes client from Amnezia's clientsTable if the file exists."""
        try:
            path = await self.get_amnezia_clients_table_path()
            if not path:
                return

            code, content = await self.exec_cmd(f"cat {path}")
            if code != 0 or not content.strip():
                return

            table = json.loads(content)
            changed = False

            if isinstance(table, list):
                new_list = [
                    c for c in table
                    if not (isinstance(c, dict) and (
                        c.get("clientId") == public_key or
                        c.get("client_pub_key") == public_key or
                        c.get("publicKey") == public_key
                    ))
                ]
                if len(new_list) != len(table):
                    table = new_list
                    changed = True
            elif isinstance(table, dict):
                if "clients" in table and isinstance(table["clients"], list):
                    new_list = [
                        c for c in table["clients"]
                        if not (isinstance(c, dict) and (
                            c.get("clientId") == public_key or
                            c.get("client_pub_key") == public_key or
                            c.get("publicKey") == public_key
                        ))
                    ]
                    if len(new_list) != len(table["clients"]):
                        table["clients"] = new_list
                        changed = True

            if changed:
                await self.backup_config_file(path)
                b64_str = base64.b64encode(json.dumps(table, indent=2, ensure_ascii=False).encode("utf-8")).decode("ascii")
                await self.exec_cmd(f"echo '{b64_str}' | base64 -d > {path}")
                logger.info(f"Removed client {public_key[:12]} from {path}")
        except Exception as e:
            logger.warning(f"Could not remove from Amnezia clientsTable: {e}")

    async def rename_peer_in_amnezia_table(self, public_key: str, new_name: str):
        """Updates client name in Amnezia's clientsTable."""
        try:
            path = await self.get_amnezia_clients_table_path()
            if not path:
                return

            code, content = await self.exec_cmd(f"cat {path}")
            if code != 0 or not content.strip():
                return

            table = json.loads(content)
            changed = False

            items = table if isinstance(table, list) else (table.get("clients", []) if isinstance(table, dict) and "clients" in table else table.values())
            for c in items:
                if isinstance(c, dict) and (c.get("clientId") == public_key or c.get("client_pub_key") == public_key or c.get("publicKey") == public_key):
                    if isinstance(c.get("userData"), dict):
                        c["userData"]["clientName"] = new_name
                    else:
                        c["userData"] = new_name
                    c["clientName"] = new_name
                    changed = True

            if changed:
                await self.backup_config_file(path)
                b64_str = base64.b64encode(json.dumps(table, indent=2, ensure_ascii=False).encode("utf-8")).decode("ascii")
                await self.exec_cmd(f"echo '{b64_str}' | base64 -d > {path}")
                logger.info(f"Renamed client {public_key[:12]} to '{new_name}' in {path}")
        except Exception as e:
            logger.warning(f"Could not rename in Amnezia clientsTable: {e}")

    async def sync_peers_from_wireguard(self):
        """Syncs all peers currently present in WireGuard interface into the database,
        enriching them with names and private keys from Amnezia's clientsTable or wg0.conf."""
        try:
            _, wg_peers = await self.get_wg_dump()
            amnezia_clients = await self.read_amnezia_clients_table()

            # Index Amnezia clients
            table_by_pubkey = {}
            table_by_ip = {}
            table_by_client_id = {}
            for c in amnezia_clients:
                if c.get("public_key"):
                    table_by_pubkey[c["public_key"]] = c
                if c.get("ip"):
                    table_by_ip[c["ip"]] = c
                if c.get("client_id"):
                    table_by_client_id[c["client_id"]] = c

            config_names = await self.parse_peer_names_from_config()
            synced_pubkeys = set()

            if wg_peers:
                for p in wg_peers:
                    pubkey = p.get("public_key")
                    if not pubkey:
                        continue
                    synced_pubkeys.add(pubkey)

                    raw_ips = p.get("allowed_ips", "")
                    ip = raw_ips.split("/")[0].strip() if "/" in raw_ips else (raw_ips.strip() or "10.8.0.x")

                    # Look up in Amnezia clientsTable first
                    c_info = table_by_pubkey.get(pubkey) or table_by_ip.get(ip) or {}
                    if not c_info and config_names.get(pubkey):
                        comm = config_names.get(pubkey).strip()
                        c_info = table_by_client_id.get(comm) or table_by_client_id.get(comm.replace("clientId:", "").strip()) or {}

                    c_name = c_info.get("name")
                    c_priv = c_info.get("private_key") or ""

                    # Fallback to comment in wg0.conf
                    if not c_name:
                        c_name = config_names.get(pubkey)

                    existing = await models.get_peer_by_pubkey(pubkey)
                    if existing:
                        updates = {}
                        current_db_name = existing.get("name", "")
                        if c_name and (current_db_name.startswith("Client-") or current_db_name != c_name):
                            updates["name"] = c_name
                        if c_priv and not existing.get("private_key"):
                            updates["private_key"] = c_priv
                        if ip and existing.get("ip_address") != ip:
                            updates["ip_address"] = ip

                        if updates:
                            try:
                                await models.update_peer_info(
                                    peer_id=existing["id"],
                                    name=updates.get("name"),
                                    private_key=updates.get("private_key"),
                                    ip_address=updates.get("ip_address")
                                )
                                logger.info(f"Updated peer #{existing['id']} with clientsTable info: {updates}")
                            except Exception as err:
                                logger.warning(f"Could not update peer #{existing['id']}: {err}")
                    else:
                        name = c_name
                        if not name:
                            clean_ip = ip.replace(".", "_")
                            name = f"Client-{clean_ip}"

                        existing_name = await models.get_peer_by_name(name)
                        if existing_name:
                            name = f"{name}-{pubkey[:4]}"

                        try:
                            await models.import_external_peer(name, pubkey, ip, private_key=c_priv)
                            logger.info(f"Imported WireGuard peer into database: {name} (IP: {ip}, has_priv: {bool(c_priv)})")
                        except Exception as err:
                            logger.warning(f"Could not import WireGuard peer {pubkey[:10]}: {err}")

            # Also check clients in clientsTable not seen in wg_dump
            for c in amnezia_clients:
                pubkey = c.get("public_key")
                if not pubkey or pubkey in synced_pubkeys:
                    continue
                ip = c.get("ip") or "10.8.0.x"
                name = c.get("name") or f"Client-{ip.replace('.', '_')}"
                priv = c.get("private_key") or ""

                existing = await models.get_peer_by_pubkey(pubkey)
                if existing:
                    updates = {}
                    if c.get("name") and existing["name"].startswith("Client-"):
                        updates["name"] = c["name"]
                    if priv and not existing.get("private_key"):
                        updates["private_key"] = priv
                    if updates:
                        try:
                            await models.update_peer_info(
                                peer_id=existing["id"],
                                name=updates.get("name"),
                                private_key=updates.get("private_key")
                            )
                        except Exception as err:
                            logger.warning(f"Could not update peer #{existing['id']}: {err}")
                else:
                    existing_name = await models.get_peer_by_name(name)
                    if existing_name:
                        name = f"{name}-{pubkey[:4]}"
                    try:
                        await models.import_external_peer(name, pubkey, ip, private_key=priv)
                        logger.info(f"Imported clientsTable peer: {name} (IP: {ip})")
                    except Exception as err:
                        logger.warning(f"Could not import clientsTable peer {pubkey[:10]}: {err}")

            # Direct sweep of all peers currently in DB to rename any Client-...
            all_db_peers = await models.get_all_peers()
            for db_p in all_db_peers:
                curr_name = db_p.get("name", "")
                if curr_name.startswith("Client-") or not curr_name:
                    p_ip = db_p.get("ip_address", "").split("/")[0].strip()
                    p_pub = db_p.get("public_key", "").strip()

                    match = table_by_pubkey.get(p_pub) or table_by_ip.get(p_ip)
                    if not match and curr_name.startswith("Client-"):
                        # Extract IP from name like Client-10_8_1_19
                        extracted_ip = curr_name.replace("Client-", "").replace("_", ".").split("-")[0]
                        match = table_by_ip.get(extracted_ip)

                    if match and match.get("name"):
                        real_name = match["name"].strip()
                        if real_name:
                            try:
                                await models.update_peer_info(
                                    peer_id=db_p["id"],
                                    name=real_name,
                                    private_key=match.get("private_key") or None
                                )
                                logger.info(f"Fixed peer #{db_p['id']} name: '{curr_name}' -> '{real_name}'")
                            except Exception as err:
                                logger.warning(f"Could not fix peer #{db_p['id']} name: {err}")

        except Exception as e:
            logger.error(f"Error during sync_peers_from_wireguard: {e}", exc_info=True)

    async def backup_config_file(self, config_path: str):
        """Creates a timestamped backup copy of the config file inside container."""
        backup_cmd = f"cp {config_path} {config_path}.bak.$(date +%s)"
        code, _ = await self.exec_cmd(backup_cmd)
        if code == 0:
            logger.info(f"Safety backup created for {config_path}")
        else:
            logger.warning(f"Could not create safety backup for {config_path}")

    async def add_peer_runtime(self, public_key: str, ip_address: str, name: Optional[str] = None, private_key: Optional[str] = None):
        """Adds peer to running WireGuard interface safely without resetting existing connections."""
        server_info = await self.get_server_info()
        iface = server_info["interface"]
        psk = server_info.get("preshared_key")
        logger.info(f"Adding peer {public_key[:12]}... (IP: {ip_address}) to interface {iface} (PSK: {'yes' if psk else 'no'})")

        clean_pk_id = re.sub(r'[^a-zA-Z0-9]', '', public_key[:8]) or "peer"
        if psk:
            tmp_psk_file = f"/tmp/psk_{clean_pk_id}.tmp"
            set_cmd = (
                f"printf '%s' '{psk}' > {tmp_psk_file} && "
                f"{self._wg_bin} set {iface} peer {public_key} preshared-key {tmp_psk_file} allowed-ips {ip_address}/32 && "
                f"rm -f {tmp_psk_file}"
            )
        else:
            set_cmd = f"{self._wg_bin} set {iface} peer {public_key} allowed-ips {ip_address}/32"

        code, out = await self.exec_cmd(set_cmd)
        if code != 0:
            logger.error(f"Failed to add peer in WireGuard: {out}")
            raise RuntimeError(f"Failed to add peer in WireGuard: {out}")

        # Also append to config file if found to persist across reboots
        config_path = await self.find_config_file(iface)
        if config_path:
            await self.backup_config_file(config_path)
            comment = f"# {name}" if name else "# Added by AmneziaBot"
            psk_line = f"PresharedKey = {psk}\n" if psk else ""
            peer_block = f"\n{comment}\n[Peer]\nPublicKey = {public_key}\n{psk_line}AllowedIPs = {ip_address}/32\n"
            append_cmd = f"printf '{peer_block}' >> {config_path}"
            await self.exec_cmd(append_cmd)
            logger.info(f"Peer {public_key[:12]}... appended to {config_path}")

        # Also append to Amnezia clientsTable if it exists
        if name and private_key:
            await self.save_peer_to_amnezia_table(name, public_key, private_key, ip_address)

    async def remove_peer_runtime(self, public_key: str):
        """Removes peer from WireGuard interface, config file, and Amnezia clientsTable safely."""
        server_info = await self.get_server_info()
        iface = server_info["interface"]
        logger.info(f"Removing peer {public_key[:12]}... from interface {iface}")
        cmd = f"{self._wg_bin} set {iface} peer {public_key} remove"
        code, out = await self.exec_cmd(cmd)

        # Remove peer block from config file if found
        config_path = await self.find_config_file(iface)
        if config_path:
            await self.backup_config_file(config_path)
            script = f"sed -i '/PublicKey = {re.escape(public_key)}/{{n;d}}' {config_path} 2>/dev/null; sed -i '/PublicKey = {re.escape(public_key)}/d' {config_path} 2>/dev/null"
            await self.exec_cmd(script)
            logger.info(f"Peer {public_key[:12]}... removed from {config_path}")

        # Also remove from Amnezia clientsTable
        await self.remove_peer_from_amnezia_table(public_key)

    async def disable_peer_runtime(self, public_key: str):
        """Temporarily disconnects peer by removing from running interface."""
        server_info = await self.get_server_info()
        iface = server_info["interface"]
        logger.info(f"Temporarily disabling peer {public_key[:12]}... on interface {iface}")
        cmd = f"{self._wg_bin} set {iface} peer {public_key} remove"
        await self.exec_cmd(cmd)

    async def enable_peer_runtime(self, public_key: str, ip_address: str):
        """Re-enables peer on running interface."""
        server_info = await self.get_server_info()
        iface = server_info["interface"]
        psk = server_info.get("preshared_key")
        logger.info(f"Re-enabling peer {public_key[:12]}... on interface {iface} (PSK: {'yes' if psk else 'no'})")
        clean_pk_id = re.sub(r'[^a-zA-Z0-9]', '', public_key[:8]) or "peer"
        if psk:
            tmp_psk_file = f"/tmp/psk_{clean_pk_id}.tmp"
            cmd = (
                f"printf '%s' '{psk}' > {tmp_psk_file} && "
                f"{self._wg_bin} set {iface} peer {public_key} preshared-key {tmp_psk_file} allowed-ips {ip_address}/32 && "
                f"rm -f {tmp_psk_file}"
            )
        else:
            cmd = f"{self._wg_bin} set {iface} peer {public_key} allowed-ips {ip_address}/32"
        code, out = await self.exec_cmd(cmd)
        if code != 0:
            logger.error(f"Failed to re-enable peer: {out}")
            raise RuntimeError(f"Failed to re-enable peer: {out}")

    async def update_peer_ip_runtime(self, public_key: str, old_ip: str, new_ip: str):
        """Updates peer IP address in WireGuard runtime, config file, and clientsTable."""
        clean_old_ip = old_ip.split("/")[0].strip()
        clean_new_ip = new_ip.split("/")[0].strip()
        server_info = await self.get_server_info()
        iface = server_info["interface"]
        logger.info(f"Updating IP for peer {public_key[:12]}... on interface {iface}: {clean_old_ip} -> {clean_new_ip}")

        # 1. Update live WireGuard runtime
        cmd = f"{self._wg_bin} set {iface} peer {public_key} allowed-ips {clean_new_ip}/32"
        code, out = await self.exec_cmd(cmd)
        if code != 0:
            logger.error(f"Failed to update peer IP in WireGuard runtime: {out}")
            raise RuntimeError(f"WireGuard update failed: {out}")

        # 2. Update server config file if exists
        config_path = await self.find_config_file(iface)
        if config_path:
            await self.backup_config_file(config_path)
            escaped_old = re.escape(clean_old_ip)
            sed_cmd = f"sed -i 's/{escaped_old}\\/32/{clean_new_ip}\\/32/g' {config_path} 2>/dev/null"
            await self.exec_cmd(sed_cmd)
            logger.info(f"Updated IP in {config_path} to {clean_new_ip}")

        # 3. Update Amnezia clientsTable if exists
        try:
            path = await self.get_amnezia_clients_table_path()
            if path:
                code, content = await self.exec_cmd(f"cat {path}")
                if code == 0 and content.strip():
                    table = json.loads(content)
                    changed = False
                    items = table if isinstance(table, list) else (table.get("clients", []) if isinstance(table, dict) and "clients" in table else table.values())
                    for c in items:
                        if isinstance(c, dict) and (c.get("clientId") == public_key or c.get("client_pub_key") == public_key or c.get("publicKey") == public_key):
                            if isinstance(c.get("userData"), dict):
                                c["userData"]["allowedIps"] = f"{clean_new_ip}/32"
                                c["userData"]["allowed_ips"] = f"{clean_new_ip}/32"
                                changed = True
                    if changed:
                        await self.backup_config_file(path)
                        b64_str = base64.b64encode(json.dumps(table, indent=2, ensure_ascii=False).encode("utf-8")).decode("ascii")
                        await self.exec_cmd(f"echo '{b64_str}' | base64 -d > {path}")
                        logger.info(f"Updated IP in {path} to {clean_new_ip}")
        except Exception as e:
            logger.warning(f"Could not update IP in clientsTable: {e}")


docker_service = DockerService()
