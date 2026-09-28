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
            InlineKeyboardButton(text=toggle_text, callback_data=f"toggle_peer:{peer_id}"),
            InlineKeyboardButton(text="📈 Статистика", callback_data=f"peer_stats:{peer_id}")
        ],
        [
            InlineKeyboardButton(text="🗑 Отозвать (Удалить)", callback_data=f"delete_confirm:{peer_id}")
        ],
        [
            InlineKeyboardButton(text="⬅️ Назад к списку", callback_data="list_peers:0")
        ]
    ]
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def get_download_format_keyboard(peer_id: int) -> InlineKeyboardMarkup:
    buttons = [
        [
            InlineKeyboardButton(text="📄 Файлы (.conf и .vpn)", callback_data=f"get_files:{peer_id}"),
            InlineKeyboardButton(text="📱 QR-коды", callback_data=f"get_qr:{peer_id}")
        ],
        [
            InlineKeyboardButton(text="📦 Всё сразу (файлы + QR)", callback_data=f"get_all:{peer_id}")
        ],
        [
            InlineKeyboardButton(text="⬅️ Назад", callback_data=f"view_peer:{peer_id}")
        ]
    ]
    return InlineKeyboardMarkup(inline_keyboard=buttons)


async def safe_edit_message(callback: CallbackQuery, text: str, reply_markup: InlineKeyboardMarkup = None, parse_mode: str = "HTML"):
    from aiogram.exceptions import TelegramBadRequest
    try:
        await callback.message.edit_text(text, reply_markup=reply_markup, parse_mode=parse_mode)
    except TelegramBadRequest as e:
        if "message is not modified" in str(e).lower():
            await callback.answer("Данные уже актуальны! ✅")
        else:
            raise

