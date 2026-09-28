import html
import re
from aiogram import Router, F
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import (
    Message,
    CallbackQuery,
    InlineKeyboardMarkup,
    InlineKeyboardButton,
    BufferedInputFile
)

from bot.handlers.common import (
    IsAdminFilter,
    get_main_menu_keyboard,
    get_peer_keyboard,
    get_download_format_keyboard,
    safe_edit_message
)
from bot.database import models
from bot.services.docker_service import docker_service
from bot.services.awg_service import awg_service

peers_router = Router()


class CreatePeerState(StatesGroup):
    waiting_for_name = State()


# --- Создание конфига ---

@peers_router.callback_query(IsAdminFilter(), F.data == "create_peer")
async def cb_create_peer_start(callback: CallbackQuery, state: FSMContext):
    kb = InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text="❌ Отмена", callback_data="cancel_create")]]
    )
    await callback.message.edit_text(
        "✏️ <b>Введите имя для нового конфига:</b>\n\n"
        "<i>Используйте латинские буквы, цифры, дефис или подчеркивание (например: <code>phone-alex</code>, <code>laptop</code>, <code>tv_box</code>).</i>",
        reply_markup=kb,
        parse_mode="HTML"
    )
    await state.set_state(CreatePeerState.waiting_for_name)
    await callback.answer()


@peers_router.callback_query(IsAdminFilter(), F.data == "cancel_create")
async def cb_cancel_create(callback: CallbackQuery, state: FSMContext):
    await state.clear()
    await callback.message.edit_text(
        "❌ Создание конфига отменено.",
        reply_markup=get_main_menu_keyboard(),
        parse_mode="HTML"
    )
    await callback.answer()


@peers_router.message(IsAdminFilter(), CreatePeerState.waiting_for_name)
async def process_create_peer_name(message: Message, state: FSMContext):
    raw_name = message.text.strip()
    if not re.match(r"^[a-zA-Z0-9_\-]{2,32}$", raw_name):
        await message.answer(
            "⚠️ <b>Некорректное имя!</b>\n\n"
            "Имя должно содержать от 2 до 32 символов (только латиница, цифры, <code>-</code> и <code>_</code>).\n"
            "Попробуйте еще раз:"
        )
        return

    # Проверка на уникальность имени
    existing = await models.get_peer_by_name(raw_name)
    if existing:
        await message.answer(
            f"⚠️ Конфиг с именем <code>{html.escape(raw_name)}</code> уже существует!\n"
            "Пожалуйста, выберите другое имя:"
        )
        return

    wait_msg = await message.answer("⏳ Генерируем ключи и настраиваем VPN...")

    try:
        # Получаем данные сервера
        server_info = await docker_service.get_server_info()

        # Выделяем следующий свободный IP
        allocated_ips = await models.get_allocated_ips()
        client_ip = awg_service.allocate_next_ip(allocated_ips)

        # Генерируем пару ключей
        client_priv, client_pub = awg_service.generate_keypair()

        # Добавляем в рантайм WireGuard
        await docker_service.add_peer_runtime(client_pub, client_ip)

        # Сохраняем в базу данных
        peer_id = await models.add_peer(raw_name, client_pub, client_priv, client_ip)

        await state.clear()
        await wait_msg.delete()

        text = (
            f"✅ <b>Конфиг «{html.escape(raw_name)}» успешно создан!</b>\n\n"
            f"• <b>IP адрес:</b> <code>{client_ip}/32</code>\n"
            f"• <b>Публичный ключ:</b> <code>{client_pub[:16]}...</code>\n\n"
            f"Выберите, как вы хотите его получить:"
        )
        await message.answer(text, reply_markup=get_download_format_keyboard(peer_id), parse_mode="HTML")

    except Exception as e:
        await state.clear()
        await wait_msg.edit_text(
            f"❌ <b>Ошибка при создании конфига:</b>\n<code>{html.escape(str(e))}</code>",
            reply_markup=get_main_menu_keyboard(),
            parse_mode="HTML"
        )


# --- Выдача файлов и QR-кодов ---

@peers_router.callback_query(IsAdminFilter(), F.data.startswith("download_choice:"))
async def cb_download_choice(callback: CallbackQuery):
    peer_id = int(callback.data.split(":")[1])
    peer = await models.get_peer_by_id(peer_id)
    if not peer:
        await callback.answer("Конфиг не найден", show_alert=True)
        return

    text = f"📥 <b>Получение конфигурации для «{html.escape(peer['name'])}»</b>\n\nВыберите формат выдачи:"
    await callback.message.edit_text(text, reply_markup=get_download_format_keyboard(peer_id), parse_mode="HTML")
    await callback.answer()


@peers_router.callback_query(IsAdminFilter(), F.data.startswith("get_files:"))
async def cb_get_files(callback: CallbackQuery):
    peer_id = int(callback.data.split(":")[1])
    await send_peer_materials(callback, peer_id, send_files=True, send_qr=False)


@peers_router.callback_query(IsAdminFilter(), F.data.startswith("get_qr:"))
async def cb_get_qr(callback: CallbackQuery):
    peer_id = int(callback.data.split(":")[1])
    await send_peer_materials(callback, peer_id, send_files=False, send_qr=True)


@peers_router.callback_query(IsAdminFilter(), F.data.startswith("get_all:"))
async def cb_get_all(callback: CallbackQuery):
    peer_id = int(callback.data.split(":")[1])
    await send_peer_materials(callback, peer_id, send_files=True, send_qr=True)


async def send_peer_materials(callback: CallbackQuery, peer_id: int, send_files: bool, send_qr: bool):
    await callback.answer("Подготовка данных...")
    peer = await models.get_peer_by_id(peer_id)
    if not peer:
        await callback.message.answer("Конфиг не найден.")
        return

    try:
        server_info = await docker_service.get_server_info()
    except Exception as e:
        await callback.message.answer(f"❌ Ошибка получения параметров сервера: {e}")
        return

    name = peer["name"]
    client_ip = peer["ip_address"]
    client_priv = peer["private_key"]
    client_pub = peer["public_key"]
    host = server_info["host"]
    port = server_info["port"]
    server_pub = server_info["public_key"]
    awg_params = server_info["awg_params"]

    # Формируем Native Conf
    native_conf = awg_service.build_native_conf(
        client_privkey=client_priv,
        client_ip=client_ip,
        server_pubkey=server_pub,
        host=host,
        port=port,
        awg_params=awg_params
    )

    # Формируем Amnezia VPN (.vpn) JSON и ссылку
    vpn_json, vpn_uri = awg_service.build_amnezia_vpn_json(
        client_name=name,
        client_privkey=client_priv,
        client_pubkey=client_pub,
        client_ip=client_ip,
        server_pubkey=server_pub,
        host=host,
        port=port,
        awg_params=awg_params
    )

    # Отправка файлов
    if send_files:
        conf_file = BufferedInputFile(native_conf.encode("utf-8"), filename=f"{name}-native.conf")
        vpn_file = BufferedInputFile(vpn_json.encode("utf-8"), filename=f"{name}.vpn")

        await callback.message.answer_document(
            document=conf_file,
            caption=f"📄 <b>Native AmneziaWG</b> конфиг для <code>{html.escape(name)}</code>\nИмпортируйте в WireGuard или AmneziaWG.",
            parse_mode="HTML"
        )
        await callback.message.answer_document(
            document=vpn_file,
            caption=f"🛡 <b>Amnezia VPN</b> файл для <code>{html.escape(name)}</code>\nИмпортируйте в официальное приложение Amnezia VPN.",
            parse_mode="HTML"
        )

    # Отправка QR-кодов
    if send_qr:
        # QR для Native Conf
        qr_conf_bio = awg_service.generate_qr_code(native_conf)
        qr_conf_file = BufferedInputFile(qr_conf_bio.read(), filename="qr_native.png")
        await callback.message.answer_photo(
            photo=qr_conf_file,
            caption=f"📱 <b>QR-код Native AmneziaWG</b>\nДля приложения WireGuard / AmneziaWG на смартфоне.",
            parse_mode="HTML"
        )

        # QR для Amnezia VPN
        qr_vpn_bio = awg_service.generate_qr_code(vpn_uri)
        qr_vpn_file = BufferedInputFile(qr_vpn_bio.read(), filename="qr_amnezia.png")
        await callback.message.answer_photo(
            photo=qr_vpn_file,
            caption=f"🛡 <b>QR-код Amnezia VPN</b>\nДля официального приложения Amnezia VPN на смартфоне.",
            parse_mode="HTML"
        )

    # Завершающая кнопка возврата
    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="👤 К карточке конфига", callback_data=f"view_peer:{peer_id}")],
            [InlineKeyboardButton(text="👥 Список всех конфигов", callback_data="list_peers:0")]
        ]
    )
    await callback.message.answer("Готово! Выберите дальнейшее действие:", reply_markup=kb)


# --- Список и просмотр пиров ---

@peers_router.callback_query(IsAdminFilter(), F.data.startswith("list_peers:"))
async def cb_list_peers(callback: CallbackQuery):
    page = int(callback.data.split(":")[1])
    peers = await models.get_all_peers()

    if not peers:
        text = "📭 <b>Список выпущенных конфигов пуст.</b>\n\nВы можете создать свой первый конфиг:"
        kb = InlineKeyboardMarkup(
            inline_keyboard=[
                [InlineKeyboardButton(text="➕ Выпустить конфиг", callback_data="create_peer")],
                [InlineKeyboardButton(text="⬅️ Главное меню", callback_data="main_menu")]
            ]
        )
        await callback.message.edit_text(text, reply_markup=kb, parse_mode="HTML")
        await callback.answer()
        return

    page_size = 6
    total_pages = (len(peers) + page_size - 1) // page_size
    page = max(0, min(page, total_pages - 1))

    current_slice = peers[page * page_size : (page + 1) * page_size]

    keyboard_rows = []
    for p in current_slice:
        is_active = p.get("is_active", 1)
        handshake = p.get("last_handshake", 0)
        # Статус
        if not is_active:
            status_icon = "⏸"
        elif handshake > 0 and (int(handshake) > 0 and (import_time := handshake)):
            # Handshake активен?
            status_icon = "🟢"
        else:
            status_icon = "🟡"

        btn_text = f"{status_icon} {p['name']} ({p['ip_address']})"
        keyboard_rows.append([InlineKeyboardButton(text=btn_text, callback_data=f"view_peer:{p['id']}")])

    # Пагинация
    nav_row = []
    if page > 0:
        nav_row.append(InlineKeyboardButton(text="⬅️", callback_data=f"list_peers:{page - 1}"))
    nav_row.append(InlineKeyboardButton(text=f"Стр. {page + 1}/{total_pages}", callback_data="noop"))
    if page < total_pages - 1:
        nav_row.append(InlineKeyboardButton(text="➡️", callback_data=f"list_peers:{page + 1}"))
    keyboard_rows.append(nav_row)

    # Нижние кнопки
    keyboard_rows.append([
        InlineKeyboardButton(text="➕ Выпустить конфиг", callback_data="create_peer"),
        InlineKeyboardButton(text="⬅️ В меню", callback_data="main_menu")
    ])

    text = (
        f"👥 <b>Список выпущенных конфигов ({len(peers)} всего):</b>\n\n"
        f"🟢 — онлайн / недавний трафик\n"
        f"🟡 — активен, нет связи\n"
        f"⏸ — временно отключен\n\n"
        f"<i>Нажмите на конфиг для управления:</i>"
    )
    await safe_edit_message(callback, text, reply_markup=InlineKeyboardMarkup(inline_keyboard=keyboard_rows), parse_mode="HTML")
    await callback.answer()


@peers_router.callback_query(IsAdminFilter(), F.data.startswith("view_peer:"))
async def cb_view_peer(callback: CallbackQuery):
    peer_id = int(callback.data.split(":")[1])
    peer = await models.get_peer_by_id(peer_id)
    if not peer:
        await callback.answer("Конфиг не найден", show_alert=True)
        return

    is_active = bool(peer.get("is_active", 1))
    handshake = peer.get("last_handshake", 0)
    hs_str = awg_service.format_handshake(handshake)
    status_str = "🟢 Активен" if is_active else "⏸ Временно отключен"

    last_rx = peer.get("last_rx", 0)
    last_tx = peer.get("last_tx", 0)
    traffic_str = f"📥 {awg_service.format_bytes(last_rx)} / 📤 {awg_service.format_bytes(last_tx)}"

    text = (
        f"👤 <b>Карточка конфига: «{html.escape(peer['name'])}»</b>\n\n"
        f"• <b>Статус:</b> {status_str}\n"
        f"• <b>IP адрес:</b> <code>{peer['ip_address']}</code>\n"
        f"• <b>Последнее подключение:</b> {hs_str}\n"
        f"• <b>Текущий счетчик WG:</b> {traffic_str}\n"
        f"• <b>Дата создания:</b> <code>{peer['created_at']}</code>\n"
        f"• <b>Публичный ключ:</b>\n<code>{peer['public_key']}</code>\n"
    )

    await safe_edit_message(
        callback,
        text,
        reply_markup=get_peer_keyboard(peer_id, is_active),
        parse_mode="HTML"
    )
    await callback.answer()


# --- Отключение / Включение пира ---

@peers_router.callback_query(IsAdminFilter(), F.data.startswith("toggle_peer:"))
async def cb_toggle_peer(callback: CallbackQuery):
    peer_id = int(callback.data.split(":")[1])
    peer = await models.get_peer_by_id(peer_id)
    if not peer:
        await callback.answer("Конфиг не найден", show_alert=True)
        return

    is_active = bool(peer.get("is_active", 1))
    new_state = not is_active

    try:
        if new_state:
            # Включаем пир обратно
            await docker_service.enable_peer_runtime(peer["public_key"], peer["ip_address"])
            await callback.answer("▶️ Пир успешно включен!")
        else:
            # Отключаем пир
            await docker_service.disable_peer_runtime(peer["public_key"])
            await callback.answer("⏸ Пир временно отключен!")

        await models.toggle_peer_status(peer_id, new_state)
    except Exception as e:
        await callback.answer(f"Ошибка: {e}", show_alert=True)
        return

    # Перерисовываем карточку
    await cb_view_peer(callback)


# --- Удаление / Отзыв конфига ---

@peers_router.callback_query(IsAdminFilter(), F.data.startswith("delete_confirm:"))
async def cb_delete_confirm(callback: CallbackQuery):
    peer_id = int(callback.data.split(":")[1])
    peer = await models.get_peer_by_id(peer_id)
    if not peer:
        await callback.answer("Конфиг не найден", show_alert=True)
        return

    text = (
        f"⚠️ <b>Подтверждение отзыва конфига:</b>\n\n"
        f"Вы действительно хотите навсегда отозвать и удалить конфиг <b>«{html.escape(peer['name'])}»</b>?\n\n"
        f"<i>Пир будет удален из WireGuard и базы данных бота. Клиент больше не сможет подключаться.</i>"
    )
    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🗑 Да, удалить навсегда", callback_data=f"delete_exec:{peer_id}")],
            [InlineKeyboardButton(text="❌ Отмена", callback_data=f"view_peer:{peer_id}")]
        ]
    )
    await callback.message.edit_text(text, reply_markup=kb, parse_mode="HTML")
    await callback.answer()


@peers_router.callback_query(IsAdminFilter(), F.data.startswith("delete_exec:"))
async def cb_delete_exec(callback: CallbackQuery):
    peer_id = int(callback.data.split(":")[1])
    peer = await models.get_peer_by_id(peer_id)
    if not peer:
        await callback.answer("Конфиг не найден", show_alert=True)
        return

    try:
        await docker_service.remove_peer_runtime(peer["public_key"])
        await models.delete_peer(peer_id)
        await callback.answer("🗑 Конфиг успешно удален!", show_alert=True)
    except Exception as e:
        await callback.answer(f"Ошибка при удалении: {e}", show_alert=True)
        return

    # Возврат к списку
    await cb_list_peers(callback)


@peers_router.callback_query(F.data == "noop")
async def cb_noop(callback: CallbackQuery):
    await callback.answer()
