"""API route exports."""

from mod_sentinel.api.routes.health import router as health_router
from mod_sentinel.api.routes.upload import router as upload_router

__all__ = ["health_router", "upload_router"]
