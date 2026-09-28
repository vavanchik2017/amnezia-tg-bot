from aiogram.filters import BaseFilter
from aiogram.types import Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton
from bot.config import settings


class IsAdminFilter(BaseFilter):
    async def __call__(self, event: Message | CallbackQuery) -> bool:
        user_id = event.from_user.id
        if not settings.admin_ids:
            return True
        return user_id in settings.admin_ids


def get_main_menu_keyboard() -> InlineKeyboardMarkup:
    buttons = [
        [
            InlineKeyboardButton(text="➕ Выпустить конфиг", callback_data="create_peer"),
            InlineKeyboardButton(text="👥 Список конфигов", callback_data="list_peers:0")
        ],
        [
            InlineKeyboardButton(text="📊 Статистика сервера", callback_data="server_stats"),
            InlineKeyboardButton(text="📈 Трафик по клиентам", callback_data="clients_ranking:day")
        ],
        [
            InlineKeyboardButton(text="ℹ️ Статус сервера", callback_data="server_status")
        ]
    ]
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def get_peer_keyboard(peer_id: int, is_active: bool) -> InlineKeyboardMarkup:
    toggle_text = "⏸ Отключить" if is_active else "▶️ Включить"
    buttons = [
        [
            InlineKeyboardButton(text="📥 Получить конфиги / QR", callback_data=f"download_choice:{peer_id}")
        ],
        [
            InlineKeyboardButton(text="✏️ Переименовать", callback_data=f"rename_peer:{peer_id}"),
            InlineKeyboardButton(text=toggle_text, callback_data=f"toggle_peer:{peer_id}")
        ],
        [
            InlineKeyboardButton(text="📈 Статистика", callback_data=f"peer_stats:{peer_id}"),
            InlineKeyboardButton(text="🗑 Отозвать", callback_data=f"delete_confirm:{peer_id}")
        ],
        [
            InlineKeyboardButton(text="⬅️ Назад к списку", callback_data="list_peers:0")
        ]
    ]
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def get_format_choice_keyboard(peer_id: int) -> InlineKeyboardMarkup:
    """Step 1: Choose between Native AmneziaWG and Amnezia VPN."""
    buttons = [
        [
            InlineKeyboardButton(text="⚡️ Native AmneziaWG (.conf)", callback_data=f"fmt:awg:{peer_id}")
        ],
        [
            InlineKeyboardButton(text="🛡 Amnezia VPN (.vpn)", callback_data=f"fmt:vpn:{peer_id}")
        ],
        [
            InlineKeyboardButton(text="👤 К карточке конфига", callback_data=f"view_peer:{peer_id}")
        ]
    ]
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def get_native_delivery_keyboard(peer_id: int) -> InlineKeyboardMarkup:
    """Step 2 for Native AmneziaWG: QR, .conf file, or raw text."""
    buttons = [
        [
            InlineKeyboardButton(text="📱 QR-код", callback_data=f"deliv:awg_qr:{peer_id}"),
            InlineKeyboardButton(text="📄 Файл .conf", callback_data=f"deliv:awg_file:{peer_id}")
        ],
        [
            InlineKeyboardButton(text="📋 Скопировать текстом", callback_data=f"deliv:awg_text:{peer_id}")
        ],
        [
            InlineKeyboardButton(text="⬅️ Выбрать другой формат", callback_data=f"download_choice:{peer_id}")
        ]
    ]
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def get_vpn_delivery_keyboard(peer_id: int) -> InlineKeyboardMarkup:
    """Step 2 for Amnezia VPN: QR, .vpn file, or vpn:// string."""
    buttons = [
        [
            InlineKeyboardButton(text="📱 QR-код", callback_data=f"deliv:vpn_qr:{peer_id}"),
            InlineKeyboardButton(text="📄 Файл .vpn", callback_data=f"deliv:vpn_file:{peer_id}")
        ],
        [
            InlineKeyboardButton(text="🔗 Ссылка vpn:// (скопировать)", callback_data=f"deliv:vpn_text:{peer_id}")
        ],
        [
            InlineKeyboardButton(text="⬅️ Выбрать другой формат", callback_data=f"download_choice:{peer_id}")
        ]
    ]
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def get_download_format_keyboard(peer_id: int) -> InlineKeyboardMarkup:
    return get_format_choice_keyboard(peer_id)


async def safe_edit_message(callback: CallbackQuery, text: str, reply_markup: InlineKeyboardMarkup = None, parse_mode: str = "HTML"):
    from aiogram.exceptions import TelegramBadRequest
    try:
        if getattr(callback.message, "photo", None):
            await callback.message.answer(text, reply_markup=reply_markup, parse_mode=parse_mode)
            try:
                await callback.message.delete()
            except Exception:
                pass
        else:
            await callback.message.edit_text(text, reply_markup=reply_markup, parse_mode=parse_mode)
    except TelegramBadRequest as e:
        err = str(e).lower()
        if "message is not modified" in err:
            await callback.answer("Данные уже актуальны! ✅")
        elif "there is no text in the message to edit" in err or "message to edit not found" in err:
            await callback.message.answer(text, reply_markup=reply_markup, parse_mode=parse_mode)
        else:
            raise

