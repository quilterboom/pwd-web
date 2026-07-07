from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from . import seed
from .routers import admin, auth, files, history, keys, passwords
from .routers.keys import orgkeys_router

STATIC_DIR = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动时确保数据库、管理员账号与加解密密钥都已就绪
    seed.seed()
    yield


app = FastAPI(title="passwdpm - 服务端加解密密码管理器", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(admin.mine_router)
app.include_router(admin.users_router)
app.include_router(admin.groups_router)
app.include_router(passwords.router)
app.include_router(files.router)
app.include_router(history.router)
app.include_router(keys.router)
app.include_router(orgkeys_router)

# 挂载前端静态资源（html=True 时 "/" 会返回 index.html）
app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
