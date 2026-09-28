import asyncio
import logging
import re
import urllib.request
from typing import Dict, List, Optional, Tuple, Any
import docker
from bot.config import settings

logger = logging.getLogger(__name__)


class DockerService:
    def __init__(self):
        self._client = None
        self._cached_server_info: Optional[Dict[str, Any]] = None
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

        interface_info = {
            "interface": iface,
            "private_key": privkey,
            "public_key": pubkey,
            "listen_port": port,
            "fwmark": fwmark
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

        # Try searching with find
        code, out = await self.exec_cmd("find /etc /opt -name '*.conf' 2>/dev/null")
        if code == 0 and out:
            for line in out.splitlines():
                if iface in line or "awg" in line or "wg" in line:
                    self._config_file_path = line.strip()
                    return self._config_file_path

        return None

    async def get_awg_params(self, iface: str) -> Dict[str, Any]:
        """Extracts AmneziaWG obfuscation parameters from server config file."""
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

        for line in content.splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                key, val = [p.strip() for p in line.split("=", 1)]
                key_upper = key.upper()
                for k in ["JC", "JMIN", "JMAX", "S1", "S2", "H1", "H2", "H3", "H4"]:
                    if key_upper == k:
                        real_key = "Jc" if k == "JC" else ("Jmin" if k == "JMIN" else ("Jmax" if k == "JMAX" else k.capitalize()))
                        try:
                            params[real_key] = int(val)
                        except ValueError:
                            params[real_key] = val

        return params

    async def get_server_public_ip(self) -> str:
        """Determines public IP of the host."""
        if settings.server_host:
            return settings.server_host

        def _fetch_ip():
            for url in ["https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"]:
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "curl/7.68.0"})
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        return resp.read().decode("utf-8").strip()
                except Exception:
                    continue
            return "127.0.0.1"

        ip = await asyncio.to_thread(_fetch_ip)
        return ip

    async def get_server_info(self) -> Dict[str, Any]:
        """Collects all server parameters needed to issue client configs."""
        if self._cached_server_info and self._cached_server_info.get("public_key"):
            return self._cached_server_info

        iface_info, _ = await self.get_wg_dump()
        if not iface_info:
            detail = getattr(self, "_last_error", "не удалось прочитать дамп интерфейса")
            raise RuntimeError(f"Контейнер '{settings.vpn_container_name}': {detail}")

        iface_name = settings.wg_interface or iface_info["interface"]
        port = settings.server_port or iface_info["listen_port"]
        public_key = iface_info["public_key"]
        public_ip = await self.get_server_public_ip()
        awg_params = await self.get_awg_params(iface_name)

        info = {
            "interface": iface_name,
            "port": port,
            "public_key": public_key,
            "host": public_ip,
            "awg_params": awg_params
        }
        self._cached_server_info = info
        return info

    async def backup_config_file(self, config_path: str):
        """Creates a timestamped backup copy of the config file inside container."""
        backup_cmd = f"cp {config_path} {config_path}.bak.$(date +%s)"
        code, _ = await self.exec_cmd(backup_cmd)
        if code == 0:
            logger.info(f"Safety backup created for {config_path}")
        else:
            logger.warning(f"Could not create safety backup for {config_path}")

    async def add_peer_runtime(self, public_key: str, ip_address: str):
        """Adds peer to running WireGuard interface safely without resetting existing connections."""
        server_info = await self.get_server_info()
        iface = server_info["interface"]
        logger.info(f"Adding peer {public_key[:12]}... (IP: {ip_address}) to interface {iface}")
        cmd = f"{self._wg_bin} set {iface} peer {public_key} allowed-ips {ip_address}/32"
        code, out = await self.exec_cmd(cmd)
        if code != 0:
            logger.error(f"Failed to add peer in WireGuard: {out}")
            raise RuntimeError(f"Failed to add peer in WireGuard: {out}")

        # Also append to config file if found to persist across reboots
        config_path = await self.find_config_file(iface)
        if config_path:
            await self.backup_config_file(config_path)
            peer_block = f"\n# Added by AmneziaBot\n[Peer]\nPublicKey = {public_key}\nAllowedIPs = {ip_address}/32\n"
            append_cmd = f"printf '{peer_block}' >> {config_path}"
            await self.exec_cmd(append_cmd)
            logger.info(f"Peer {public_key[:12]}... appended to {config_path}")

    async def remove_peer_runtime(self, public_key: str):
        """Removes peer from WireGuard interface and config file safely."""
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
        logger.info(f"Re-enabling peer {public_key[:12]}... on interface {iface}")
        cmd = f"{self._wg_bin} set {iface} peer {public_key} allowed-ips {ip_address}/32"
        code, out = await self.exec_cmd(cmd)
        if code != 0:
            logger.error(f"Failed to re-enable peer: {out}")
            raise RuntimeError(f"Failed to re-enable peer: {out}")


docker_service = DockerService()
