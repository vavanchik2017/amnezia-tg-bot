import asyncio
import logging
from bot.config import settings
from bot.services.docker_service import docker_service
from bot.database import models

logger = logging.getLogger(__name__)


class StatsService:
    def __init__(self):
        self._task: asyncio.Task = None
        self._running = False

    async def start(self):
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._poll_loop())
        logger.info(f"Stats polling service started (interval: {settings.stats_poll_interval}s)")

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("Stats polling service stopped")

    async def _poll_loop(self):
        while self._running:
            try:
                await self.collect_stats()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in stats collection loop: {e}", exc_info=True)

            try:
                await asyncio.sleep(settings.stats_poll_interval)
            except asyncio.CancelledError:
                break

    async def collect_stats(self):
        """Polls WireGuard dump and updates DB traffic snapshots."""
        await docker_service.sync_peers_from_wireguard()
        _, peers = await docker_service.get_wg_dump()
        if not peers:
            return

        for p in peers:
            pubkey = p.get("public_key")
            rx = p.get("rx_bytes", 0)
            tx = p.get("tx_bytes", 0)
            handshake = p.get("latest_handshake", 0)
            raw_ips = p.get("allowed_ips", "")
            ip = raw_ips.split("/")[0].strip() if "/" in raw_ips else (raw_ips.strip() or "unknown")
            if pubkey:
                await models.record_traffic_snapshot(pubkey, rx, tx, handshake, fallback_ip=ip)


stats_service = StatsService()
