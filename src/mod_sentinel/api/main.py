from __future__ import annotations

from fastapi import FastAPI

from mod_sentinel.api.routes.health import router as health_router
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
    return application


app = create_app()
