"""API route exports."""

from mod_sentinel.api.routes.health import router as health_router
from mod_sentinel.api.routes.scan import router as scan_router
from mod_sentinel.api.routes.scans import router as scans_router
from mod_sentinel.api.routes.upload import router as upload_router

__all__ = ["health_router", "upload_router", "scan_router", "scans_router"]
