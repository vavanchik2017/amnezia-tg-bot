import html
from aiogram import Router, F
from aiogram.filters import CommandStart, Command
from aiogram.types import Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup

from bot.config import settings
from bot.handlers.common import IsAdminFilter, get_main_menu_keyboard, safe_edit_message
from bot.services.docker_service import docker_service
from bot.database import models

admin_router = Router()


class ServerSettingsState(StatesGroup):
    waiting_for_port = State()


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
            [InlineKeyboardButton(text="⚙️ Сменить порт сервера", callback_data="change_server_port")],
            [InlineKeyboardButton(text="🔄 Обновить порт во всех конфигах", callback_data="rebuild_all_ports")],
            [InlineKeyboardButton(text="🔄 Обновить статус", callback_data="server_status")],
            [InlineKeyboardButton(text="⬅️ В меню", callback_data="main_menu")]
        ]
    )
    await safe_edit_message(callback, text, reply_markup=kb, parse_mode="HTML")


@admin_router.callback_query(IsAdminFilter(), F.data == "change_server_port")
async def cb_change_port_prompt(callback: CallbackQuery, state: FSMContext):
    try:
        info = await docker_service.get_server_info()
        current_port = info.get("port", "—")
    except Exception:
        current_port = "—"

    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="❌ Отмена", callback_data="cancel_change_port")]
        ]
    )
    await safe_edit_message(
        callback,
        f"⚙️ <b>Смена рабочего порта VPN сервера</b>\n\n"
        f"• Текущий активный порт: <code>{current_port}</code>\n\n"
        f"Введите новый порт (от <code>1</code> до <code>65535</code>, рекомендуется от <code>1024</code>):\n\n"
        f"<i>При смене порта:\n"
        f"1. Порт обновится на лету в работающем контейнере WireGuard/AmneziaWG.\n"
        f"2. Обновится конфигурационный файл сервера (awg0.conf).\n"
        f"3. Все клиенты в базе Amnezia и новые выдачи будут переведены на этот порт.</i>",
        reply_markup=kb,
        parse_mode="HTML"
    )
    await state.set_state(ServerSettingsState.waiting_for_port)
    await callback.answer()


@admin_router.callback_query(IsAdminFilter(), F.data == "cancel_change_port")
async def cb_cancel_change_port(callback: CallbackQuery, state: FSMContext):
    await state.clear()
    await cb_server_status(callback)


@admin_router.message(IsAdminFilter(), ServerSettingsState.waiting_for_port)
async def process_change_server_port(message: Message, state: FSMContext):
    text = (message.text or "").strip()
    if not text.isdigit():
        await message.answer(
            "⚠️ <b>Некорректный ввод!</b>\n\n"
            "Порт должен быть целым числом от 1 до 65535. Попробуйте еще раз или нажмите отмену.",
            reply_markup=InlineKeyboardMarkup(
                inline_keyboard=[[InlineKeyboardButton(text="❌ Отмена", callback_data="cancel_change_port")]]
            ),
            parse_mode="HTML"
        )
        return

    new_port = int(text)
    if not (1 <= new_port <= 65535):
        await message.answer(
            "⚠️ <b>Порт вне допустимого диапазона!</b>\n\n"
            "Допустимый диапазон портов: 1 – 65535. Попробуйте еще раз:",
            reply_markup=InlineKeyboardMarkup(
                inline_keyboard=[[InlineKeyboardButton(text="❌ Отмена", callback_data="cancel_change_port")]]
            ),
            parse_mode="HTML"
        )
        return

    wait_msg = await message.answer(f"⏳ Применяем порт <code>{new_port}</code> на сервере и обновляем базу конфигов...")
    await state.clear()

    try:
        success, msg = await docker_service.set_server_port(new_port)
        await wait_msg.delete()
        if not success:
            kb = InlineKeyboardMarkup(
                inline_keyboard=[[InlineKeyboardButton(text="⬅️ К статусу сервера", callback_data="server_status")]]
            )
            await message.answer(
                f"❌ <b>Не удалось сменить порт!</b>\n\nПричина: <code>{html.escape(msg)}</code>",
                reply_markup=kb,
                parse_mode="HTML"
            )
            return

        kb = InlineKeyboardMarkup(
            inline_keyboard=[
                [InlineKeyboardButton(text="🔄 Обновить порт во всех конфигах", callback_data="rebuild_all_ports")],
                [InlineKeyboardButton(text="📊 Статус сервера", callback_data="server_status")],
                [InlineKeyboardButton(text="⬅️ В главное меню", callback_data="main_menu")]
            ]
        )
        await message.answer(
            f"✅ <b>Порт сервера успешно изменён на <code>{new_port}</code>!</b>\n\n"
            f"• В рантайме интерфейса VPN порт переключен на <code>{new_port}</code>.\n"
            f"• Файл конфигурации сервера и таблица клиентов обновлены.\n"
            f"• Все выдаваемые ботом файлы (.conf, .vpn, QR) теперь автоматически содержат порт <code>{new_port}</code>!\n\n"
            f"<i>Примечание: если у вас на хосте настроен файрвол (UFW / iptables), убедитесь, что UDP порт <code>{new_port}</code> открыт!</i>",
            reply_markup=kb,
            parse_mode="HTML"
        )
    except Exception as e:
        try:
            await wait_msg.delete()
        except Exception:
            pass
        kb = InlineKeyboardMarkup(
            inline_keyboard=[[InlineKeyboardButton(text="⬅️ К статусу сервера", callback_data="server_status")]]
        )
        await message.answer(
            f"❌ <b>Ошибка при смене порта:</b>\n<code>{html.escape(str(e))}</code>",
            reply_markup=kb,
            parse_mode="HTML"
        )


@admin_router.callback_query(IsAdminFilter(), F.data == "rebuild_all_ports")
async def cb_rebuild_all_ports(callback: CallbackQuery):
    await callback.answer("Актуализируем все конфиги...", show_alert=False)
    try:
        res = await docker_service.regenerate_all_configs()
        if not res.get("ok"):
            await callback.answer(f"Ошибка: {res.get('message')}", show_alert=True)
            return

        active_port = res.get("port")
        count = res.get("count", 0)

        kb = InlineKeyboardMarkup(
            inline_keyboard=[
                [InlineKeyboardButton(text="⚙️ Сменить порт сервера", callback_data="change_server_port")],
                [InlineKeyboardButton(text="🔄 Обновить статус", callback_data="server_status")],
                [InlineKeyboardButton(text="⬅️ В главное меню", callback_data="main_menu")]
            ]
        )

        await safe_edit_message(
            callback,
            f"✅ <b>Все конфигурации успешно актуализированы!</b>\n\n"
            f"• Актуальный рабочий порт: <code>{active_port}</code>\n"
            f"• Обработано клиентов: <b>{count}</b>\n"
            f"• Внутренняя таблица клиентов (clientsTable) и база данных синхронизированы.\n\n"
            f"Все файлы (.conf и .vpn), выдаваемые ботом в меню «👥 Список конфигов», отдаются с портом <code>{active_port}</code>.",
            reply_markup=kb,
            parse_mode="HTML"
        )
    except Exception as e:
        await callback.answer(f"Ошибка: {e}", show_alert=True)

