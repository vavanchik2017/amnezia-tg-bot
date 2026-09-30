import html
import ipaddress
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
    get_format_choice_keyboard,
    get_native_delivery_keyboard,
    get_vpn_delivery_keyboard,
    get_delivery_result_keyboard,
    get_download_format_keyboard,
    safe_edit_message
)
from bot.config import settings
from bot.database import models
from bot.services.docker_service import docker_service
from bot.services.awg_service import awg_service

peers_router = Router()


class CreatePeerState(StatesGroup):
    waiting_for_name = State()


class RenamePeerState(StatesGroup):
    waiting_for_name = State()


# --- Создание конфига ---

@peers_router.callback_query(IsAdminFilter(), F.data == "create_peer")
async def cb_create_peer_start(callback: CallbackQuery, state: FSMContext):
    kb = InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text="❌ Отмена", callback_data="cancel_create")]]
    )
    await callback.message.edit_text(
        "✏️ <b>Введите имя для нового конфига:</b>\n\n"
        "<i>Например: <code>phone-alex</code>, <code>iPhone Вани</code>, <code>laptop</code>, <code>tv_box</code>.</i>",
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
    if len(raw_name) < 2 or len(raw_name) > 36 or any(c in raw_name for c in "\n\r\t`$\"';/\\<>|"):
        await message.answer(
            "⚠️ <b>Некорректное имя!</b>\n\n"
            "Имя должно содержать от 2 до 36 символов и не содержать спецсимволов кавычек и слэшей.\n"
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
        # Получаем данные сервера и актуальную подсеть
        server_info = await docker_service.get_server_info()
        server_subnet = server_info.get("subnet") or await docker_service.get_server_subnet()

        # Выделяем следующий свободный IP в правильной подсети
        allocated_ips = await models.get_allocated_ips()
        try:
            _, live_peers = await docker_service.get_wg_dump()
            for lp in live_peers:
                lp_ip = lp.get("allowed_ips", "").split("/")[0].strip()
                if lp_ip and lp_ip not in allocated_ips:
                    allocated_ips.append(lp_ip)
        except Exception:
            pass

        client_ip = awg_service.allocate_next_ip(allocated_ips, subnet_cidr=server_subnet)

        # Генерируем пару ключей
        client_priv, client_pub = awg_service.generate_keypair()

        # Добавляем в рантайм WireGuard и Amnezia clientsTable
        await docker_service.add_peer_runtime(client_pub, client_ip, name=raw_name, private_key=client_priv)

        # Сохраняем в базу данных
        peer_id = await models.add_peer(raw_name, client_pub, client_priv, client_ip)

        await state.clear()
        await wait_msg.delete()

        text = (
            f"✅ <b>Конфиг «{html.escape(raw_name)}» успешно создан!</b>\n\n"
            f"• <b>IP адрес:</b> <code>{client_ip}/32</code>\n"
            f"• <b>Публичный ключ:</b> <code>{client_pub[:16]}...</code>\n\n"
            f"Выберите тип клиентского приложения:"
        )
        await message.answer(text, reply_markup=get_format_choice_keyboard(peer_id), parse_mode="HTML")

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

    text = (
        f"📥 <b>Получение конфигурации для «{html.escape(peer['name'])}»</b>\n\n"
        "Выберите тип клиентского приложения:"
    )
    await safe_edit_message(callback, text, reply_markup=get_format_choice_keyboard(peer_id), parse_mode="HTML")
    await callback.answer()


@peers_router.callback_query(IsAdminFilter(), F.data.startswith("fmt:awg:"))
async def cb_fmt_awg(callback: CallbackQuery):
    peer_id = int(callback.data.split(":")[2])
    peer = await models.get_peer_by_id(peer_id)
    if not peer:
        await callback.answer("Конфиг не найден", show_alert=True)
        return

    text = (
        f"⚡️ <b>Native AmneziaWG</b> для «{html.escape(peer['name'])}»\n\n"
        "Конфигурация для официального клиента <b>AmneziaWG</b> (Android, iOS, Windows, macOS, Linux, роутеры Keenetic/OpenWrt).\n\n"
        "Выберите способ получения:"
    )
    await safe_edit_message(callback, text, reply_markup=get_native_delivery_keyboard(peer_id), parse_mode="HTML")
    await callback.answer()


@peers_router.callback_query(IsAdminFilter(), F.data.startswith("fmt:vpn:"))
async def cb_fmt_vpn(callback: CallbackQuery):
    peer_id = int(callback.data.split(":")[2])
    peer = await models.get_peer_by_id(peer_id)
    if not peer:
        await callback.answer("Конфиг не найден", show_alert=True)
        return

    text = (
        f"🛡 <b>Amnezia VPN</b> для «{html.escape(peer['name'])}»\n\n"
        "Конфигурация для официального приложения-комбайна <b>Amnezia VPN</b>.\n\n"
        "Выберите способ получения:"
    )
    await safe_edit_message(callback, text, reply_markup=get_vpn_delivery_keyboard(peer_id), parse_mode="HTML")
    await callback.answer()


async def get_peer_materials_data(peer_id: int):
    peer = await models.get_peer_by_id(peer_id)
    if not peer:
        return None, "Конфиг не найден в базе данных."

    name = peer["name"]
    client_ip = peer["ip_address"]
    client_priv = peer["private_key"]
    client_pub = peer["public_key"]

    if not client_priv or not client_priv.strip():
        return None, (
            f"ℹ️ <b>Конфиг «{html.escape(name)}» был создан вне бота</b> (импортирован с сервера).\n\n"
            "Сервер WireGuard хранит только публичный ключ клиента. Приватный ключ находится исключительно на самом клиентском устройстве.\n\n"
            "Вы можете выпустить новый конфиг через бота, чтобы получить файл или QR-код."
        )

    try:
        server_info = await docker_service.get_server_info()
    except Exception as e:
        return None, f"❌ Ошибка подключения к серверу: {e}"

    host = server_info["host"]
    port = server_info["port"]
    server_pub = server_info["public_key"]
    awg_params = server_info["awg_params"]
    preshared_key = server_info.get("preshared_key")
    target_container = settings.vpn_container_name or "amnezia-awg2"

    native_conf = awg_service.build_native_conf(
        client_privkey=client_priv,
        client_ip=client_ip,
        server_pubkey=server_pub,
        host=host,
        port=port,
        awg_params=awg_params,
        preshared_key=preshared_key
    )

    awg2_conf = awg_service.build_awg2_conf(
        client_privkey=client_priv,
        client_ip=client_ip,
        server_pubkey=server_pub,
        host=host,
        port=port,
        awg_params=awg_params,
        preshared_key=preshared_key
    )

    vpn_json, vpn_uri = awg_service.build_amnezia_vpn_json(
        client_name=name,
        client_privkey=client_priv,
        client_pubkey=client_pub,
        client_ip=client_ip,
        server_pubkey=server_pub,
        host=host,
        port=port,
        awg_params=awg_params,
        preshared_key=preshared_key,
        container_name=target_container
    )

    safe_filename = re.sub(r'[^a-zA-Z0-9_\-]', '_', name).strip('_') or 'client'

    return {
        "peer": peer,
        "name": name,
        "safe_filename": safe_filename,
        "native_conf": native_conf,
        "awg2_conf": awg2_conf,
        "vpn_json": vpn_json,
        "vpn_uri": vpn_uri,
        "host": host
    }, None


@peers_router.callback_query(IsAdminFilter(), F.data.startswith("deliv:awg_qr:"))
async def cb_deliv_awg_qr(callback: CallbackQuery):
    peer_id = int(callback.data.split(":")[2])
    data, err = await get_peer_materials_data(peer_id)
    if err:
        await callback.message.answer(err, parse_mode="HTML")
        await callback.answer()
        return
    await callback.answer("Генерируем QR-код...")

    qr_bio = awg_service.generate_qr_code(data["native_conf"])
    qr_file = BufferedInputFile(qr_bio.read(), filename=f"{data['safe_filename']}_awg.png")

    back_kb = get_delivery_result_keyboard(peer_id, "awg")

    await callback.message.answer_photo(
        photo=qr_file,
        caption=(
            f"📱 <b>QR-код Native AmneziaWG</b> для <code>{html.escape(data['name'])}</code>\n\n"
            "⚠️ Сканируйте именно в приложении <b>AmneziaWG</b> (синий официальный WireGuard не поддерживает обфускацию)!"
        ),
        reply_markup=back_kb,
        parse_mode="HTML"
    )


@peers_router.callback_query(IsAdminFilter(), F.data.startswith("deliv:awg_file:"))
async def cb_deliv_awg_file(callback: CallbackQuery):
    peer_id = int(callback.data.split(":")[2])
    data, err = await get_peer_materials_data(peer_id)
    if err:
        await callback.message.answer(err, parse_mode="HTML")
        await callback.answer()
        return
    await callback.answer("Отправляем файл...")

    conf_file = BufferedInputFile(data["native_conf"].encode("utf-8"), filename=f"{data['safe_filename']}.conf")
    back_kb = get_delivery_result_keyboard(peer_id, "awg")

    await callback.message.answer_document(
        document=conf_file,
        caption=(
            f"📄 <b>Файл Native AmneziaWG (.conf)</b> для <code>{html.escape(data['name'])}</code>\n\n"
            "Импортируйте этот файл в приложение <b>AmneziaWG</b>."
        ),
        reply_markup=back_kb,
        parse_mode="HTML"
    )


@peers_router.callback_query(IsAdminFilter(), F.data.startswith("deliv:awg2_file:"))
async def cb_deliv_awg2_file(callback: CallbackQuery):
    peer_id = int(callback.data.split(":")[2])
    data, err = await get_peer_materials_data(peer_id)
    if err:
        await callback.message.answer(err, parse_mode="HTML")
        await callback.answer()
        return
    await callback.answer("Отправляем файл AWG 2.0...")

    conf_file = BufferedInputFile(data["awg2_conf"].encode("utf-8"), filename=f"{data['safe_filename']}_awg2.conf")
    back_kb = get_delivery_result_keyboard(peer_id, "awg")

    await callback.message.answer_document(
        document=conf_file,
        caption=(
            f"🚀 <b>Файл AmneziaWG 2.0 (.conf)</b> для <code>{html.escape(data['name'])}</code>\n\n"
            "Содержит параметры обфускации AWG 2.0 (CPS, диапазоны заголовков).\n"
            "<i>Примечание: если ваш клиент выдает ошибку неизвестного атрибута, используйте стандартный <b>📄 Файл .conf</b>.</i>"
        ),
        reply_markup=back_kb,
        parse_mode="HTML"
    )


@peers_router.callback_query(IsAdminFilter(), F.data.startswith("deliv:awg_text:"))
async def cb_deliv_awg_text(callback: CallbackQuery):
    peer_id = int(callback.data.split(":")[2])
    data, err = await get_peer_materials_data(peer_id)
    if err:
        await callback.message.answer(err, parse_mode="HTML")
        await callback.answer()
        return
    await callback.answer()

    back_kb = get_delivery_result_keyboard(peer_id, "awg")

    await callback.message.answer(
        f"📋 <b>Конфигурация Native AmneziaWG для «{html.escape(data['name'])}»:</b>\n\n"
        f"<pre><code>{html.escape(data['native_conf'])}</code></pre>\n\n"
        f"<i>💡 Нажмите на текст, чтобы скопировать.</i>",
        reply_markup=back_kb,
        parse_mode="HTML"
    )


@peers_router.callback_query(IsAdminFilter(), F.data.startswith("deliv:vpn_qr:"))
async def cb_deliv_vpn_qr(callback: CallbackQuery):
    peer_id = int(callback.data.split(":")[2])
    data, err = await get_peer_materials_data(peer_id)
    if err:
        await callback.message.answer(err, parse_mode="HTML")
        await callback.answer()
        return
    await callback.answer("Генерируем QR-код...")

    qr_bio = awg_service.generate_qr_code(data["vpn_uri"])
    qr_file = BufferedInputFile(qr_bio.read(), filename=f"{data['safe_filename']}_vpn.png")

    back_kb = get_delivery_result_keyboard(peer_id, "vpn")

    await callback.message.answer_photo(
        photo=qr_file,
        caption=(
            f"🛡 <b>QR-код Amnezia VPN</b> для <code>{html.escape(data['name'])}</code>\n\n"
            "Сканируйте камерой в приложении <b>Amnezia VPN</b>."
        ),
        reply_markup=back_kb,
        parse_mode="HTML"
    )


@peers_router.callback_query(IsAdminFilter(), F.data.startswith("deliv:vpn_file:"))
async def cb_deliv_vpn_file(callback: CallbackQuery):
    peer_id = int(callback.data.split(":")[2])
    data, err = await get_peer_materials_data(peer_id)
    if err:
        await callback.message.answer(err, parse_mode="HTML")
        await callback.answer()
        return
    await callback.answer("Отправляем файл...")

    vpn_file = BufferedInputFile(data["vpn_json"].encode("utf-8"), filename=f"{data['safe_filename']}.vpn")
    back_kb = get_delivery_result_keyboard(peer_id, "vpn")

    await callback.message.answer_document(
        document=vpn_file,
        caption=(
            f"🛡 <b>Файл Amnezia VPN (.vpn)</b> для <code>{html.escape(data['name'])}</code>\n\n"
            "Импортируйте этот файл в приложение <b>Amnezia VPN</b>."
        ),
        reply_markup=back_kb,
        parse_mode="HTML"
    )


@peers_router.callback_query(IsAdminFilter(), F.data.startswith("deliv:vpn_text:"))
async def cb_deliv_vpn_text(callback: CallbackQuery):
    peer_id = int(callback.data.split(":")[2])
    data, err = await get_peer_materials_data(peer_id)
    if err:
        await callback.message.answer(err, parse_mode="HTML")
        await callback.answer()
        return
    await callback.answer()

    back_kb = get_delivery_result_keyboard(peer_id, "vpn")

    await callback.message.answer(
        f"🔗 <b>Ссылка Amnezia VPN для «{html.escape(data['name'])}»:</b>\n\n"
        f"<code>{html.escape(data['vpn_uri'])}</code>\n\n"
        f"<i>💡 Нажмите на ссылку, чтобы скопировать. При открытии приложения Amnezia VPN оно само предложит импортировать её из буфера обмена!</i>",
        reply_markup=back_kb,
        parse_mode="HTML"
    )


@peers_router.callback_query(IsAdminFilter(), F.data.startswith("get_all:"))
async def cb_get_all(callback: CallbackQuery):
    peer_id = int(callback.data.split(":")[1])
    data, err = await get_peer_materials_data(peer_id)
    if err:
        await callback.message.answer(err, parse_mode="HTML")
        await callback.answer()
        return
    await callback.answer("Подготовка данных...")

    conf_file = BufferedInputFile(data["native_conf"].encode("utf-8"), filename=f"{data['safe_filename']}.conf")
    vpn_file = BufferedInputFile(data["vpn_json"].encode("utf-8"), filename=f"{data['safe_filename']}.vpn")

    await callback.message.answer_document(
        document=conf_file,
        caption=f"📄 <b>Native AmneziaWG (.conf)</b> для <code>{html.escape(data['name'])}</code>",
        parse_mode="HTML"
    )
    await callback.message.answer_document(
        document=vpn_file,
        caption=f"🛡 <b>Amnezia VPN (.vpn)</b> для <code>{html.escape(data['name'])}</code>",
        parse_mode="HTML"
    )

    qr_conf_bio = awg_service.generate_qr_code(data["native_conf"])
    qr_conf_file = BufferedInputFile(qr_conf_bio.read(), filename="qr_native.png")
    await callback.message.answer_photo(
        photo=qr_conf_file,
        caption=f"📱 <b>QR Native AmneziaWG</b> для <code>{html.escape(data['name'])}</code>",
        parse_mode="HTML"
    )

    await callback.message.answer(
        f"🔗 <b>Ссылка Amnezia VPN для «{html.escape(data['name'])}»:</b>\n\n"
        f"<code>{html.escape(data['vpn_uri'])}</code>",
        reply_markup=get_delivery_result_keyboard(peer_id, "vpn"),
        parse_mode="HTML"
    )


# --- Список и просмотр пиров ---

async def render_peers_list(callback: CallbackQuery, page: int = 0):
    # Автоматически синхронизируем всех существующих клиентов с сервера
    await docker_service.sync_peers_from_wireguard()
    peers = await models.get_all_peers()

    if not peers:
        text = "📭 <b>Список выпущенных конфигов пуст.</b>\n\nВы можете создать свой первый конфиг:"
        kb = InlineKeyboardMarkup(
            inline_keyboard=[
                [InlineKeyboardButton(text="➕ Выпустить конфиг", callback_data="create_peer")],
                [InlineKeyboardButton(text="🏠 Главное меню", callback_data="main_menu")]
            ]
        )
        await safe_edit_message(callback, text, reply_markup=kb, parse_mode="HTML")
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
        elif handshake > 0 and int(handshake) > 0:
            # Handshake активен
            status_icon = "🟢"
        else:
            status_icon = "🟡"

        btn_text = f"{status_icon} {p['name']}"
        keyboard_rows.append([InlineKeyboardButton(text=btn_text, callback_data=f"view_peer:{p['id']}")])

    # Пагинация
    nav_row = []
    if page > 0:
        nav_row.append(InlineKeyboardButton(text="⬅️", callback_data=f"list_peers:{page - 1}"))
    nav_row.append(InlineKeyboardButton(text=f"Стр. {page + 1}/{total_pages}", callback_data="noop"))
    if page < total_pages - 1:
        nav_row.append(InlineKeyboardButton(text="➡️", callback_data=f"list_peers:{page + 1}"))
    if nav_row:
        keyboard_rows.append(nav_row)

    # Нижние кнопки
    keyboard_rows.append([
        InlineKeyboardButton(text="➕ Выпустить конфиг", callback_data="create_peer"),
        InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")
    ])

    text = (
        f"👥 <b>Список выпущенных конфигов ({len(peers)} всего):</b>\n\n"
        f"🟢 — онлайн / недавний трафик\n"
        f"🟡 — активен, нет связи\n"
        f"⏸ — временно отключен\n\n"
        f"<i>Нажмите на конфиг для управления:</i>"
    )
    await safe_edit_message(callback, text, reply_markup=InlineKeyboardMarkup(inline_keyboard=keyboard_rows), parse_mode="HTML")


@peers_router.callback_query(IsAdminFilter(), F.data.startswith("list_peers:"))
async def cb_list_peers(callback: CallbackQuery):
    page = int(callback.data.split(":")[1])
    await render_peers_list(callback, page=page)
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

    # Проверяем совпадение подсети пира с подсетью сервера
    has_subnet_mismatch = False
    subnet_warning = ""
    try:
        server_subnet = await docker_service.get_server_subnet()
        peer_ip = peer['ip_address'].split("/")[0].strip()
        net = ipaddress.ip_network(server_subnet, strict=False)
        if ipaddress.ip_address(peer_ip) not in net:
            has_subnet_mismatch = True
            subnet_warning = (
                f"\n\n⚠️ <b>Внимание: Несоответствие подсети!</b>\n"
                f"IP конфига (<code>{peer_ip}</code>) не входит в подсеть сервера (<code>{server_subnet}</code>). "
                f"Трафик с сервера сбрасывается фаерволом. Нажмите кнопку <b>«🔄 Исправить подсеть IP»</b> ниже."
            )
    except Exception:
        pass

    text = (
        f"👤 <b>Карточка конфига: «{html.escape(peer['name'])}»</b>\n\n"
        f"• <b>Статус:</b> {status_str}\n"
        f"• <b>IP адрес:</b> <code>{peer['ip_address']}</code>\n"
        f"• <b>Последнее подключение:</b> {hs_str}\n"
        f"• <b>Текущий счетчик WG:</b> {traffic_str}\n"
        f"• <b>Дата создания:</b> <code>{peer['created_at']}</code>\n"
        f"• <b>Публичный ключ:</b>\n<code>{peer['public_key']}</code>"
        f"{subnet_warning}\n"
    )

    await safe_edit_message(
        callback,
        text,
        reply_markup=get_peer_keyboard(peer_id, is_active, has_subnet_mismatch=has_subnet_mismatch),
        parse_mode="HTML"
    )
    await callback.answer()


# --- Исправление подсети IP ---

@peers_router.callback_query(IsAdminFilter(), F.data.startswith("fix_peer_subnet:"))
async def cb_fix_peer_subnet(callback: CallbackQuery):
    peer_id = int(callback.data.split(":")[1])
    peer = await models.get_peer_by_id(peer_id)
    if not peer:
        await callback.answer("Конфиг не найден", show_alert=True)
        return

    try:
        server_subnet = await docker_service.get_server_subnet()
        allocated_ips = await models.get_allocated_ips()
        try:
            _, live_peers = await docker_service.get_wg_dump()
            for lp in live_peers:
                lp_ip = lp.get("allowed_ips", "").split("/")[0].strip()
                if lp_ip and lp_ip not in allocated_ips:
                    allocated_ips.append(lp_ip)
        except Exception:
            pass

        old_ip = peer["ip_address"]
        new_ip = awg_service.allocate_next_ip(allocated_ips, subnet_cidr=server_subnet)

        # 1. Update WireGuard runtime and configs
        await docker_service.update_peer_ip_runtime(peer["public_key"], old_ip, new_ip)

        # 2. Update DB
        await models.update_peer_info(peer_id=peer_id, ip_address=new_ip)

        await callback.answer(f"✅ IP обновлен: {new_ip}! Заново скачайте конфиг.", show_alert=True)
    except Exception as e:
        await callback.answer(f"❌ Ошибка обновления IP: {e}", show_alert=True)
        return

    # Refresh card
    await cb_view_peer(callback)


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
        await callback.answer("🗑 Конфиг успешно удален!")
    except Exception as e:
        await callback.answer(f"Ошибка при удалении: {e}", show_alert=True)
        return

    # Возврат к списку конфигов
    await render_peers_list(callback, page=0)


# --- Переименование конфига ---

@peers_router.callback_query(IsAdminFilter(), F.data.startswith("rename_peer:"))
async def cb_rename_peer_start(callback: CallbackQuery, state: FSMContext):
    peer_id = int(callback.data.split(":")[1])
    peer = await models.get_peer_by_id(peer_id)
    if not peer:
        await callback.answer("Конфиг не найден", show_alert=True)
        return

    await state.update_data(rename_peer_id=peer_id)
    kb = InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text="❌ Отмена", callback_data=f"view_peer:{peer_id}")]]
    )
    await callback.message.edit_text(
        f"✏️ <b>Переименование конфига «{html.escape(peer['name'])}»:</b>\n\n"
        f"Введите новое имя клиента (например: <code>iPhone Вани</code>, <code>Ноутбук</code>, <code>worker-pc</code>):",
        reply_markup=kb,
        parse_mode="HTML"
    )
    await state.set_state(RenamePeerState.waiting_for_name)
    await callback.answer()


@peers_router.message(IsAdminFilter(), RenamePeerState.waiting_for_name)
async def process_rename_peer(message: Message, state: FSMContext):
    new_name = message.text.strip()
    data = await state.get_data()
    peer_id = data.get("rename_peer_id")
    if not peer_id:
        await state.clear()
        return

    peer = await models.get_peer_by_id(peer_id)
    if not peer:
        await state.clear()
        await message.answer("Конфиг не найден.")
        return

    if len(new_name) < 2 or len(new_name) > 36 or any(c in new_name for c in "\n\r\t`$\"';/\\<>|"):
        await message.answer(
            "⚠️ <b>Некорректное имя!</b>\n\n"
            "Имя должно содержать от 2 до 36 символов и не содержать спецсимволов кавычек и слэшей.\n"
            "Попробуйте еще раз:"
        )
        return

    existing = await models.get_peer_by_name(new_name)
    if existing and existing["id"] != peer_id:
        await message.answer(
            f"⚠️ Конфиг с именем <code>{html.escape(new_name)}</code> уже существует!\n"
            "Пожалуйста, выберите другое имя:"
        )
        return

    # Обновляем в SQLite
    await models.update_peer_info(peer_id=peer_id, name=new_name)
    # Обновляем в clientsTable Amnezia если файл есть
    await docker_service.rename_peer_in_amnezia_table(peer["public_key"], new_name)
    await state.clear()

    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="👤 К карточке конфига", callback_data=f"view_peer:{peer_id}")],
            [
                InlineKeyboardButton(text="👥 Список всех конфигов", callback_data="list_peers:0"),
                InlineKeyboardButton(text="🏠 На главную", callback_data="main_menu")
            ]
        ]
    )
    await message.answer(
        f"✅ Конфиг успешно переименован в <b>«{html.escape(new_name)}»</b>!",
        reply_markup=kb,
        parse_mode="HTML"
    )


@peers_router.callback_query(F.data == "noop")
async def cb_noop(callback: CallbackQuery):
    await callback.answer()
