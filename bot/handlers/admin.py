import html
from aiogram import Router, F
from aiogram.filters import CommandStart, Command
from aiogram.types import Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton

from bot.config import settings
from bot.handlers.common import IsAdminFilter, get_main_menu_keyboard, safe_edit_message
from bot.services.docker_service import docker_service
from bot.database import models

admin_router = Router()


@admin_router.message(~IsAdminFilter())
async def access_denied_message(message: Message):
    user_id = message.from_user.id
    username = f"@{message.from_user.username}" if message.from_user.username else ""
    await message.answer(
        f"⛔️ <b>Доступ запрещен</b>\n\n"
        f"Ваш Telegram ID: <code>{user_id}</code> {html.escape(username)}\n\n"
        f"Чтобы получить доступ, добавьте этот ID в переменную <code>ADMIN_IDS</code> в файле <code>.env</code> на сервере и перезапустите бота.",
        parse_mode="HTML"
    )


@admin_router.callback_query(~IsAdminFilter())
async def access_denied_callback(callback: CallbackQuery):
    await callback.answer(f"⛔️ Доступ запрещен. Ваш ID: {callback.from_user.id}", show_alert=True)


@admin_router.message(IsAdminFilter(), CommandStart())
async def cmd_start(message: Message):
    text = (
        "👋 <b>Добро пожаловать в панель управления AmneziaWG!</b>\n\n"
        "С помощью этого бота вы можете:\n"
        "• Выпускать новые конфиги (.conf и .vpn) с QR-кодами\n"
        "• Просматривать список активных и отключенных пиров\n"
        "• Временно приостанавливать или отзывать доступ\n"
        "• Собирать и анализировать статистику трафика (день/неделя/месяц/год)\n\n"
        "Выберите действие в меню ниже:"
    )
    await message.answer(text, reply_markup=get_main_menu_keyboard(), parse_mode="HTML")


@admin_router.callback_query(IsAdminFilter(), F.data == "main_menu")
async def cb_main_menu(callback: CallbackQuery):
    text = (
        "📋 <b>Главное меню управления AmneziaWG:</b>\n\n"
        "Выберите нужный раздел:"
    )
    await safe_edit_message(callback, text, reply_markup=get_main_menu_keyboard(), parse_mode="HTML")
    await callback.answer()


@admin_router.callback_query(IsAdminFilter(), F.data == "server_status")
async def cb_server_status(callback: CallbackQuery):
    await callback.answer("Проверяем статус...")
    health = await docker_service.check_health()
    if not health.get("ok"):
        error_msg = health.get("error", "Контейнер недоступен")
        text = (
            f"❌ <b>Ошибка подключения к VPN!</b>\n\n"
            f"Контейнер: <code>{settings.vpn_container_name}</code>\n"
            f"Причина: <code>{html.escape(error_msg)}</code>\n\n"
            f"Убедитесь, что контейнер запущен и сокет Docker смонтирован."
        )
        kb = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="⬅️ В меню", callback_data="main_menu")]])
        await safe_edit_message(callback, text, reply_markup=kb, parse_mode="HTML")
        return

    try:
        await docker_service.sync_peers_from_wireguard()
        info = await docker_service.get_server_info()
        all_peers = await models.get_all_peers()
        active_peers = [p for p in all_peers if p.get("is_active")]

        awg_p = info.get("awg_params", {})
        params_str = (
            f"Jc={awg_p.get('Jc')}, Jmin={awg_p.get('Jmin')}, Jmax={awg_p.get('Jmax')}\n"
            f"S1={awg_p.get('S1')}, S2={awg_p.get('S2')}\n"
            f"H1={awg_p.get('H1')}, H2={awg_p.get('H2')}, H3={awg_p.get('H3')}, H4={awg_p.get('H4')}"
        )

        ip_warn = ""
        if info['host'] == "127.0.0.1":
            ip_warn = "\n\n⚠️ <b>Внимание:</b> IP сервера определен как <code>127.0.0.1</code>! Укажите реальный публичный IP в <code>SERVER_HOST</code> в файле <code>.env</code>, чтобы клиенты могли подключаться."

        text = (
            f"🟢 <b>Статус сервера AmneziaWG:</b>\n\n"
            f"• <b>Контейнер:</b> <code>{settings.vpn_container_name}</code> (running)\n"
            f"• <b>Утилита:</b> <code>{health.get('tool', 'wg')}</code>\n"
            f"• <b>Интерфейс:</b> <code>{info['interface']}</code>\n"
            f"• <b>Хост / IP:</b> <code>{info['host']}</code>\n"
            f"• <b>Порт:</b> <code>{info['port']}</code>\n"
            f"• <b>Клиентов на сервере:</b> {len(all_peers)} (активных: {len(active_peers)})\n\n"
            f"<b>Параметры обфускации:</b>\n<code>{params_str}</code>"
            f"{ip_warn}"
        )
    except Exception as e:
        text = f"⚠️ <b>Предупреждение при получении данных:</b>\n<code>{html.escape(str(e))}</code>"

    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🔄 Обновить", callback_data="server_status")],
            [InlineKeyboardButton(text="⬅️ В меню", callback_data="main_menu")]
        ]
    )
    await safe_edit_message(callback, text, reply_markup=kb, parse_mode="HTML")

