import html
from aiogram import Router, F
from aiogram.types import CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton

from bot.handlers.common import IsAdminFilter, safe_edit_message
from bot.database import models
from bot.services.awg_service import awg_service
from bot.services.stats_service import stats_service

stats_router = Router()


def format_stats_block(title: str, rx: int, tx: int) -> str:
    total = rx + tx
    return (
        f"<b>{title}:</b>\n"
        f"  • Входящий (Rx): <code>{awg_service.format_bytes(rx)}</code>\n"
        f"  • Исходящий (Tx): <code>{awg_service.format_bytes(tx)}</code>\n"
        f"  • Всего: <b>{awg_service.format_bytes(total)}</b>\n"
    )


@stats_router.callback_query(IsAdminFilter(), F.data == "server_stats")
async def cb_server_stats(callback: CallbackQuery):
    await callback.answer("Собираем статистику...")
    # Trigger on-demand sync of current counters
    await stats_service.collect_stats()

    stats = await models.get_overall_traffic_summary()

    text = (
        "📊 <b>Сводная статистика трафика сервера:</b>\n\n"
        f"{format_stats_block('За последние 24 часа', stats['day']['rx'], stats['day']['tx'])}\n"
        f"{format_stats_block('За последние 7 дней', stats['week']['rx'], stats['week']['tx'])}\n"
        f"{format_stats_block('За последние 30 дней', stats['month']['rx'], stats['month']['tx'])}\n"
        f"{format_stats_block('За последний год', stats['year']['rx'], stats['year']['tx'])}\n"
        f"{format_stats_block('За всё время', stats['all']['rx'], stats['all']['tx'])}\n"
        "<i>Данные собираются фоновым сервисом с учетом перезапусков интерфейса.</i>"
    )

    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🔄 Обновить", callback_data="server_stats")],
            [InlineKeyboardButton(text="⬅️ Главное меню", callback_data="main_menu")]
        ]
    )
    await safe_edit_message(callback, text, reply_markup=kb, parse_mode="HTML")


@stats_router.callback_query(IsAdminFilter(), F.data.startswith("peer_stats:"))
async def cb_peer_stats(callback: CallbackQuery):
    peer_id = int(callback.data.split(":")[1])
    peer = await models.get_peer_by_id(peer_id)
    if not peer:
        await callback.answer("Конфиг не найден", show_alert=True)
        return

    await callback.answer("Собираем статистику...")
    # Sync latest dump
    await stats_service.collect_stats()

    stats = await models.get_peer_traffic_summary(peer_id)

    text = (
        f"📈 <b>Статистика использования для «{html.escape(peer['name'])}»:</b>\n"
        f"IP: <code>{peer['ip_address']}</code>\n\n"
        f"{format_stats_block('За последние 24 часа', stats['day']['rx'], stats['day']['tx'])}\n"
        f"{format_stats_block('За последние 7 дней', stats['week']['rx'], stats['week']['tx'])}\n"
        f"{format_stats_block('За последние 30 дней', stats['month']['rx'], stats['month']['tx'])}\n"
        f"{format_stats_block('За последний год', stats['year']['rx'], stats['year']['tx'])}\n"
        f"{format_stats_block('За всё время', stats['all']['rx'], stats['all']['tx'])}\n"
    )

    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🔄 Обновить", callback_data=f"peer_stats:{peer_id}")],
            [InlineKeyboardButton(text="👤 К карточке конфига", callback_data=f"view_peer:{peer_id}")],
            [InlineKeyboardButton(text="👥 Список всех конфигов", callback_data="list_peers:0")]
        ]
    )
    await safe_edit_message(callback, text, reply_markup=kb, parse_mode="HTML")
