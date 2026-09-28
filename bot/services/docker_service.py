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
                res = container.exec_run(cmd)
                output = res.output.decode("utf-8", errors="replace").strip()
                return res.exit_code, output
            except Exception as e:
                logger.error(f"Error executing command in container: {e}")
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
        code, out = await self.exec_cmd(f"{self._wg_bin} show all dump")
        if code != 0 or not out:
            # Try fallback to wg or awg
            alt_bin = "awg" if self._wg_bin == "wg" else "wg"
            code, out = await self.exec_cmd(f"{alt_bin} show all dump")
            if code == 0:
                self._wg_bin = alt_bin
            else:
                logger.error(f"Failed to get wg dump: {out}")
                return None, []

        lines = [line.strip() for line in out.splitlines() if line.strip()]
        if not lines:
            return None, []

        interface_info = None
        peers = []

        for line in lines:
            parts = line.split("\t")
            if len(parts) == 5:
                # Interface line: <iface> <privkey> <pubkey> <port> <fwmark>
                interface_info = {
                    "interface": parts[0],
                    "private_key": parts[1],
                    "public_key": parts[2],
                    "listen_port": int(parts[3]) if parts[3].isdigit() else parts[3],
                    "fwmark": parts[4]
                }
            elif len(parts) >= 8:
                # Peer line: <iface> <pubkey> <preshared_key> <endpoint> <allowed_ips> <latest_handshake> <rx_bytes> <tx_bytes> [<persistent_keepalive>]
                peer = {
                    "interface": parts[0],
                    "public_key": parts[1],
                    "preshared_key": parts[2],
                    "endpoint": parts[3],
                    "allowed_ips": parts[4],
                    "latest_handshake": int(parts[5]) if parts[5].isdigit() else 0,
                    "rx_bytes": int(parts[6]) if parts[6].isdigit() else 0,
                    "tx_bytes": int(parts[7]) if parts[7].isdigit() else 0,
                    "persistent_keepalive": int(parts[8]) if len(parts) > 8 and parts[8].isdigit() else 0
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
            raise RuntimeError(f"Could not connect to {settings.vpn_container_name} or read interface dump.")

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
