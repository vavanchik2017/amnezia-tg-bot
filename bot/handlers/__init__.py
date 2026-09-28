from .admin import admin_router
from .peers import peers_router
from .stats import stats_router

__all__ = ["admin_router", "peers_router", "stats_router"]
