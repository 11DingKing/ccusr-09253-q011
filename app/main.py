"""服务端业务模块。"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .db import engine
from .models import Base
from .routers import router


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    # 默认 SQLite 部署下确保业务表（含访问控制策略表）已创建。
    Base.metadata.create_all(engine)
    yield


app = FastAPI(
    title="Practice Hours Guard",
    version="0.1.0",
    description=(
        "Event-sourced practice-hours compliance service. Check-ins, mentor "
        "confirmations and leave corrections are append-only; compliance is "
        "derived by replay and can be frozen into an immutable snapshot."
    ),
    lifespan=lifespan,
)

app.include_router(router)


@app.get("/health", tags=["meta"])
def health() -> dict[str, str]:
    return {"status": "ok"}
