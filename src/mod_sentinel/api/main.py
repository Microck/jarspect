from __future__ import annotations

from fastapi import FastAPI

from mod_sentinel.api.routes.health import router as health_router
from mod_sentinel.api.routes.scan import router as scan_router
from mod_sentinel.api.routes.scans import router as scans_router
from mod_sentinel.api.routes.upload import router as upload_router
from mod_sentinel.settings import get_settings


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title=settings.service_name,
        version=settings.service_version,
    )
    application.include_router(health_router)
    application.include_router(upload_router)
    application.include_router(scan_router)
    application.include_router(scans_router)
    return application


app = create_app()
