"""应用配置。所有可外部化的参数都通过环境变量或本地持久文件提供。"""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent  # backend/
DATA_DIR = Path(os.getenv("DATA_DIR", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "passwdpm.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"

# 文件保险箱：加密后的文件落盘目录（数据库只存元数据）
FILES_DIR = DATA_DIR / "files"
FILES_DIR.mkdir(exist_ok=True)

# JWT 密钥：优先用环境变量，否则在 data/.secret_key 文件持久化（与数据库同目录，
# 便于 Docker 通过同一个卷挂载持久化，避免容器重启后令牌失效）。
SECRET_KEY_FILE = DATA_DIR / ".secret_key"
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    if SECRET_KEY_FILE.exists():
        SECRET_KEY = SECRET_KEY_FILE.read_text().strip()
    else:
        SECRET_KEY = secrets.token_hex(32)
        SECRET_KEY_FILE.write_text(SECRET_KEY)

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("TOKEN_EXPIRE_MINUTES", "1440"))  # 默认 24h

# 首次启动时创建的管理员账号（生产环境务必通过环境变量覆盖）
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

# 首次启动时自动创建的默认分组名称
DEFAULT_GROUP_NAME = os.getenv("DEFAULT_GROUP_NAME", "默认分组")

HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "9010"))
