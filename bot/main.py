import asyncio
import logging
import sys

from aiogram import Bot, Dispatcher
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.enums import ParseMode

from bot.config import settings
from bot.database.db import init_db, close_db
from bot.services.stats_service import stats_service
from bot.handlers import admin_router, peers_router, stats_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("amnezia_bot")


async def on_startup(bot: Bot):
    logger.info("Initializing database...")
    await init_db()

    logger.info("Starting background stats collector...")
    await stats_service.start()

    logger.info(f"Bot started! Admin IDs: {settings.admin_ids}")


async def on_shutdown(bot: Bot):
    logger.info("Stopping background stats collector...")
    await stats_service.stop()

    logger.info("Closing database connection...")
    await close_db()

    logger.info("Bot stopped.")


async def main():
    if not settings.bot_token:
        logger.error("BOT_TOKEN is not configured! Please provide BOT_TOKEN in .env")
        sys.exit(1)

    bot = Bot(token=settings.bot_token)
    dp = Dispatcher(storage=MemoryStorage())

    # Register routers
    dp.include_router(admin_router)
    dp.include_router(peers_router)
    dp.include_router(stats_router)

    # Register lifecycle hooks
    dp.startup.register(on_startup)
    dp.shutdown.register(on_shutdown)

    try:
        await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())
    finally:
        await bot.session.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Execution interrupted. Exiting.")
