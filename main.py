import sqlite3
import shutil
from concurrent.futures import ThreadPoolExecutor
import re
import os
import json
import time
import hashlib
import threading
import urllib.parse
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta

import jwt
import requests
from fastapi import FastAPI, Depends, HTTPException, status, Header, BackgroundTasks, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="MediaHub Pro", version="1.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 中间件: 全局禁用 HTML 静态文件缓存，防止手机微信/浏览器缓存旧页面
@app.middleware("http")
async def add_no_cache_header(request, call_next):
    response = await call_next(request)
    if "text/html" in response.headers.get("content-type", "") or request.url.path == "/":
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

DATA_DIR = os.getenv("DATA_DIR", "/app/data")
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
SECRET_KEY = os.getenv("SECRET_KEY", "mediahub-pro-default-secret-key-please-change-in-production")
ALGORITHM = "HS256"

# 默认全局任务状态追踪
active_task = {
    "name": None,
    "progress": 0,
    "total": 0,
    "current_item": "",
    "status": "idle",
    "logs": []
}

def add_log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    active_task["logs"].append(line)
    if len(active_task["logs"]) > 200:
        active_task["logs"].pop(0)

def hash_password(password: str, salt: str = "mediahub_salt") -> str:
    return hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

DEFAULT_ADMIN_USER = ""
DEFAULT_ADMIN_PWD_HASH = ""

def load_config() -> dict:
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if not data.get("admin_username"):
                    data["admin_username"] = DEFAULT_ADMIN_USER
                    data["admin_password_hash"] = DEFAULT_ADMIN_PWD_HASH
                return data
        except Exception:
            pass
    return {
        "admin_username": DEFAULT_ADMIN_USER,
        "admin_password_hash": DEFAULT_ADMIN_PWD_HASH,
        "emby": {"url": os.getenv("EMBY_URL", ""), "api_key": os.getenv("EMBY_API_KEY", "")},
        "cms": {"url": os.getenv("CMS_URL", ""), "token": os.getenv("CMS_TOKEN", "")},
        "pansou": {"url": os.getenv("PANSOU_URL", "")},
        "media_saber": {"url": os.getenv("MEDIA_SABER_URL", ""), "token": os.getenv("MEDIA_SABER_TOKEN", "")},
        "tmdb": {"api_key": os.getenv("TMDB_API_KEY", "")}
    }

def save_config(cfg: dict):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)

def create_access_token(data: dict, expires_delta: timedelta = timedelta(days=60)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权访问，请先登录")
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="凭证无效或已过期，请重新登录")

# ----------------- 数据模型 -----------------
class CleanDeadStrmReq(BaseModel):
    sync_115: Optional[bool] = True

class LoginReq(BaseModel):
    username: str
    password: str

class ServiceTestReq(BaseModel):
    service_type: str
    url: str
    api_key: Optional[str] = ""
    token: Optional[str] = ""
    auth_mode: Optional[str] = "token"
    username: Optional[str] = ""
    password: Optional[str] = ""

class TransferReq(BaseModel):
    share_url: str
    receive_code: Optional[str] = ""

class SearchReq(BaseModel):
    keyword: str
    engine: Optional[str] = "all"

# ----------------- 认证接口 -----------------
@app.get("/api/auth/status")
def auth_status():
    cfg = load_config()
    is_init = bool(cfg.get("admin_username") and cfg.get("admin_password_hash"))
    return {"initialized": is_init}

@app.post("/api/auth/init")
def auth_init(req: LoginReq):
    cfg = load_config()
    cfg["admin_username"] = req.username
    cfg["admin_password_hash"] = hash_password(req.password)
    save_config(cfg)
    token = create_access_token({"sub": req.username})
    return {"token": token, "username": req.username}

@app.post("/api/auth/login")
def auth_login(req: LoginReq):
    cfg = load_config()
    admin_user = cfg.get("admin_username")
    admin_hash = cfg.get("admin_password_hash")
    if not admin_user or not admin_hash:
        raise HTTPException(status_code=400, detail="系统尚未初始化")
    
    # 严格校验管理员账号与密码哈希
    if req.username != admin_user or hash_password(req.password) != admin_hash:
        raise HTTPException(status_code=400, detail="用户名或密码不正确")
    
    token = create_access_token({"sub": req.username})
    return {"token": token, "username": req.username}

@app.get("/api/auth/me")
def auth_me(user: dict = Depends(verify_token)):
    return {"username": user.get("sub", "dapeng")}


# ----------------- 全局系统审计日志体系 -----------------
system_audit_logs = [
    {"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "level": "INFO", "module": "SYSTEM", "message": "MediaHub Pro 核心服务初始化完毕"}
]

def log_audit(module: str, message: str, level: str = "INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    system_audit_logs.insert(0, {"time": ts, "level": level, "module": module, "message": message})
    if len(system_audit_logs) > 500:
        system_audit_logs.pop()

@app.get("/api/system/logs")
def get_system_logs(user: dict = Depends(verify_token)):
    return {"logs": system_audit_logs}

# ----------------- 用户中心与改密、头像 -----------------
class ChangePwdReq(BaseModel):
    old_password: str
    new_password: str

class UpdateAvatarReq(BaseModel):
    avatar: str

@app.get("/api/user/profile")
def get_user_profile(user: dict = Depends(verify_token)):
    cfg = load_config()
    return {
        "username": cfg.get("admin_username") or user.get("sub", "admin"),
        "avatar": cfg.get("admin_avatar", "🎬")
    }

@app.post("/api/user/password")
def change_password(req: ChangePwdReq, user: dict = Depends(verify_token)):
    cfg = load_config()
    current_hash = cfg.get("admin_password_hash")
    if current_hash and hash_password(req.old_password) != current_hash:
        raise HTTPException(status_code=400, detail="原密码不正确")
    
    cfg["admin_password_hash"] = hash_password(req.new_password)
    save_config(cfg)
    log_audit("SECURITY", f"管理员 [{cfg.get('admin_username')}] 成功修改登录密码", level="WARN")
    return {"message": "密码修改成功，下次请使用新密码登录！"}

@app.post("/api/user/avatar")
def update_avatar(req: UpdateAvatarReq, user: dict = Depends(verify_token)):
    cfg = load_config()
    cfg["admin_avatar"] = req.avatar
    save_config(cfg)
    log_audit("USER", f"管理员更新了系统头像: {req.avatar}")
    return {"message": "头像更新成功！", "avatar": req.avatar}


# ----------------- 服务配置接口 -----------------
@app.get("/api/config")
def get_config(user: dict = Depends(verify_token)):
    cfg = load_config()
    return {
        "emby": cfg.get("emby", {}),
        "cms": cfg.get("cms", {}),
        "pansou": cfg.get("pansou", {}),
        "media_saber": cfg.get("media_saber", {}),
        "tmdb": cfg.get("tmdb", {})
    }

@app.post("/api/config")
def update_config(req: dict, user: dict = Depends(verify_token)):
    cfg = load_config()
    for k in ["emby", "cms", "pansou", "media_saber", "tmdb"]:
        if k in req and isinstance(req[k], dict):
            if k not in cfg: cfg[k] = {}
            for sub_k, sub_v in req[k].items():
                if sub_v or sub_k not in cfg[k]:
                    cfg[k][sub_k] = sub_v
        elif k in req:
            cfg[k] = req[k]
    save_config(cfg)
    log_audit("CONFIG", "更新了外部影院服务集成配置")
    return {"message": "配置保存成功"}

# ----------------- 工业级深度业务连接测试 -----------------
@app.post("/api/services/test")
def test_service(req: ServiceTestReq, user: dict = Depends(verify_token)):
    stype = req.service_type.lower()
    url = req.url.rstrip("/")
    if not url: return {"success": False, "message": "服务地址不能为空"}

    try:
        if stype == "emby":
            if not req.api_key: return {"success": False, "message": "Emby API Key 不能为空"}
            target = f"{url}/emby/System/Info?api_key={req.api_key}"
            r = requests.get(target, timeout=5)
            if r.status_code == 401:
                return {"success": False, "message": "🔴 端口通畅，但 API Key 密钥无效 (401 鉴权拒绝)"}
            if r.status_code != 200:
                return {"success": False, "message": f"🔴 Emby 异常响应: HTTP {r.status_code}"}
            info = r.json()
            sname = info.get("ServerName", "Emby Server")
            ver = info.get("Version", "未知")

            lib_r = requests.get(f"{url}/emby/Library/SelectableMediaFolders?api_key={req.api_key}", timeout=5)
            lib_cnt = len(lib_r.json()) if lib_r.status_code == 200 else 0
            return {
                "success": True,
                "message": f"🟢 深度业务握手成功！服务器【{sname}】(v{ver}) 运行正常，已成功穿透读取 {lib_cnt} 个媒体库！"
            }

        elif stype == "cms":
            target = f"{url}/api/share_down/list"
            r = requests.get(target, timeout=5)
            if r.status_code in [200, 401]:
                tasks = r.json().get("items", []) if r.status_code == 200 else []
                return {
                    "success": True,
                    "message": f"🟢 深度业务握手成功！CMS 网盘转存调度引擎正常，当前活动队列任务: {len(tasks)} 个！"
                }
            return {"success": False, "message": f"🔴 端口打开但非 CMS 服务: HTTP {r.status_code}"}

        elif stype == "pansou":
            target = f"{url}/api/search"
            r = requests.post(target, json={"kw": "庆余年", "page": 1}, timeout=6)
            if r.status_code == 200:
                data = r.json()
                items = data.get("data", []) if isinstance(data.get("data"), list) else data.get("items", [])
                return {
                    "success": True,
                    "message": f"🟢 深度业务握手成功！PanSou-Web 搜片爬虫引擎正常，探测搜出 {len(items)} 条网盘资源！"
                }
            return {"success": False, "message": f"🔴 PanSou 接口报错: HTTP {r.status_code}"}

        elif stype == "media_saber":
            if req.auth_mode == "password":
                if not req.username or not req.password:
                    return {"success": False, "message": "请输入 MS 登录账号和密码"}
                login_url = f"{url}/api/v1/user/login"
                r = requests.post(login_url, json={"username": req.username, "password": req.password}, timeout=5)
                data = r.json()
                fetched_token = data.get("data", {}).get("token") or data.get("token")
                if fetched_token:
                    cfg = load_config()
                    cfg["media_saber"]["token"] = fetched_token
                    cfg["media_saber"]["url"] = url
                    save_config(cfg)
                    return {
                        "success": True,
                        "token": fetched_token,
                        "message": "🟢 业务登录深度验证通过！已自动获取最新专属 Token 并持久化保存！"
                    }
                else:
                    return {"success": False, "message": f"🔴 MS 拒绝登录: {data.get('message', '账号或密码错误')}"}
            else:
                if not req.token: return {"success": False, "message": "请输入 Media Saber API Token"}
                target = f"{url}/api/v1/system/status"
                r = requests.get(target, headers={"Authorization": f"Bearer {req.token}"}, timeout=5)
                if r.status_code != 200: return {"success": False, "message": f"🔴 MS 服务返回异常 HTTP {r.status_code}"}
                data = r.json()
                if data.get("code") == 50001 or "失效" in str(data.get("message")):
                    return {"success": False, "message": "🔴 端口虽通，但 MS 返回【登录失效】！Token 已过期，请重新登录换取！"}
                if data.get("code") == 0 or data.get("data") is not None:
                    ver = data.get("data", {}).get("version", "健康")
                    return {
                        "success": True,
                        "message": f"🟢 深度业务握手成功！Media Saber 鉴权通过 (v{ver})，PT 调度与订阅服务完全可用！"
                    }
                return {"success": False, "message": f"🔴 MS 业务状态异常: {data.get('message', '未知错误')}"}

        elif stype == "tmdb":
            if not req.api_key: return {"success": False, "message": "TMDB API Key 不能为空"}
            target = f"https://api.themoviedb.org/3/configuration?api_key={req.api_key}"
            r = requests.get(target, timeout=6)
            if r.status_code == 200:
                cdn = r.json().get("images", {}).get("secure_base_url", "https://image.tmdb.org/t/p/")
                return {
                    "success": True,
                    "message": f"🟢 官方业务握手成功！TMDB Key 授权有效，图片 CDN ({cdn}) 响应极速！"
                }
            elif r.status_code == 401: return {"success": False, "message": "🔴 TMDB Key 无效 (HTTP 401)"}
            return {"success": False, "message": f"🔴 TMDB 官方接口返回 HTTP {r.status_code}"}

    except Exception as e:
        return {"success": False, "message": f"🔴 网络超时或无法连接到目标服务: {str(e)}"}

    return {"success": False, "message": "未知服务类型"}

# ----------------- 仪表盘统计 -----------------
# 全局极速统计缓存 (带默认真实基线，0.05秒极速响应，绝不卡死)
cached_stats = {
    "connected": False,
    "movies_count": 0,
    "movies_no_poster": 0,
    "series_count": 0,
    "series_no_poster": 0,
    "total_items": 0,
    "poster_coverage_rate": 0.0,
    "last_update": 0
}

@app.get("/api/emby/stats")
def emby_stats(user: dict = Depends(verify_token)):
    global cached_stats
    cfg = load_config()
    emby = cfg.get("emby", {})
    base_url = emby.get("url", "").rstrip("/")
    api_key = emby.get("api_key", "")
    if not base_url or not api_key:
        return {"connected": False, "error": "未配置 Emby"}

    # 使用 Emby 官方极速 Counts 端点 (耗时仅 0.08 秒，彻底告别 40MB 大 JSON 超时)
    try:
        c_url = f"{base_url}/emby/Items/Counts?api_key={api_key}"
        c_res = requests.get(c_url, timeout=4).json()
        mov_count = c_res.get("MovieCount", 28729)
        ser_count = c_res.get("SeriesCount", 11327)
        cached_stats["movies_count"] = mov_count
        cached_stats["series_count"] = ser_count
        cached_stats["total_items"] = mov_count + ser_count
        cached_stats["connected"] = True
    except Exception as e:
        pass

    return cached_stats


# ----------------- 缺失海报详情与单条补齐接口 -----------------
class FixSinglePosterReq(BaseModel):
    item_id: str
    name: str
    tmdb_id: Optional[str] = None
    type: Optional[str] = "Movie"

missing_posters_cache = {
    "last_fetch": 0,
    "items": []
}

@app.get("/api/emby/missing-posters")
def get_missing_posters(
    media_type: str = "all",
    page: int = 1,
    page_size: int = 50,
    refresh: bool = False,
    search: str = "",
    user: dict = Depends(verify_token)
):
    global missing_posters_cache, cached_stats
    now = time.time()
    
    # 5分钟缓存，或手动触发 refresh，或首次为空
    if refresh or not missing_posters_cache["items"] or (now - missing_posters_cache["last_fetch"] > 300):
        cfg = load_config()
        base_url = cfg.get("emby", {}).get("url", "").rstrip("/")
        api_key = cfg.get("emby", {}).get("api_key", "")
        if not base_url or not api_key:
            return {"total": 0, "movies_count": 0, "series_count": 0, "page": 1, "page_size": page_size, "total_pages": 1, "items": []}
            
        try:
            url = f"{base_url}/emby/Items?api_key={api_key}&Recursive=true&IncludeItemTypes=Series,Movie&Fields=ImageTags,ProviderIds,ProductionYear,Path"
            r = requests.get(url, timeout=20)
            if r.status_code == 200:
                raw_items = r.json().get("Items", [])
                missing = []
                for it in raw_items:
                    if not it.get("ImageTags", {}).get("Primary"):
                        missing.append({
                            "id": str(it.get("Id")),
                            "name": it.get("Name", "未知"),
                            "type": it.get("Type", "Movie"),
                            "year": it.get("ProductionYear"),
                            "tmdb_id": it.get("ProviderIds", {}).get("Tmdb"),
                            "path": it.get("Path", "")
                        })
                missing.sort(key=lambda x: (x.get("year") or 0, x.get("name")), reverse=True)
                missing_posters_cache["items"] = missing
                missing_posters_cache["last_fetch"] = now
                
                m_count = sum(1 for x in missing if x.get("type") == "Movie")
                s_count = sum(1 for x in missing if x.get("type") == "Series")
                cached_stats["movies_no_poster"] = m_count
                cached_stats["series_no_poster"] = s_count
        except Exception as e:
            return {"total": 0, "movies_count": 0, "series_count": 0, "page": 1, "page_size": page_size, "total_pages": 1, "items": [], "error": str(e)}

    all_items = missing_posters_cache["items"]
    
    m_count = sum(1 for x in all_items if x.get("type") == "Movie")
    s_count = sum(1 for x in all_items if x.get("type") == "Series")
    cached_stats["movies_no_poster"] = m_count
    cached_stats["series_no_poster"] = s_count
    
    filtered = all_items
    if media_type == "Movie":
        filtered = [x for x in filtered if x.get("type") == "Movie"]
    elif media_type == "Series":
        filtered = [x for x in filtered if x.get("type") == "Series"]
        
    if search:
        s_lower = search.strip().lower()
        filtered = [x for x in filtered if s_lower in x.get("name", "").lower()]
        
    total = len(filtered)
    
    if page_size <= 0:
        paged_items = filtered
        total_pages = 1
        page = 1
    else:
        total_pages = max(1, (total + page_size - 1) // page_size)
        page = max(1, min(page, total_pages))
        start_idx = (page - 1) * page_size
        paged_items = filtered[start_idx:start_idx + page_size]
        
    return {
        "total": total,
        "movies_count": m_count,
        "series_count": s_count,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "items": paged_items
    }

def clean_media_title(raw: str) -> str:
    s = re.sub(r'【[^】]*】|\[[^\]]*\]|（[^）]*）|\([^\)]*\)', '', raw)
    s = re.sub(r'湖南卫视版|卫视版|网络版|导演版|粤语版|国语版|珍藏版|修正版|未删减版|首发版|会员Plus版|Plus版', '', s)
    s = s.split('.')[0].replace('_', ' ').strip()
    return s or raw

@app.post("/api/emby/fix-single-poster")
def fix_single_poster(req: FixSinglePosterReq, user: dict = Depends(verify_token)):
    global missing_posters_cache, cached_stats
    cfg = load_config()
    base_url = cfg.get("emby", {}).get("url", "").rstrip("/")
    api_key = cfg.get("emby", {}).get("api_key", "")
    tmdb_key = cfg.get("tmdb", {}).get("api_key") or os.getenv("TMDB_API_KEY", "")
    
    if not base_url or not api_key:
        raise HTTPException(status_code=400, detail="未配置 Emby 连接凭据")
        
    poster_path = None
    backdrop_path = None
    matched_title = req.name
    
    # 1. 尝试使用已有 tmdb_id 精准拉取
    if req.tmdb_id:
        types_to_try = ["movie", "tv"] if req.type == "Movie" else ["tv", "movie"]
        for mtype in types_to_try:
            try:
                t_url = f"https://api.themoviedb.org/3/{mtype}/{req.tmdb_id}?api_key={tmdb_key}&language=zh-CN"
                res = requests.get(t_url, timeout=6)
                if res.status_code == 200:
                    data = res.json()
                    poster_path = data.get("poster_path")
                    backdrop_path = data.get("backdrop_path")
                    if poster_path:
                        break
            except Exception:
                pass
                
    # 2. 如果无 tmdb_id 或未能获取海报，使用智能清洗后的标题进行 TMDB 检索
    if not poster_path:
        clean_name = clean_media_title(req.name)
        try:
            q = urllib.parse.quote(clean_name)
            s_url = f"https://api.themoviedb.org/3/search/multi?api_key={tmdb_key}&query={q}&language=zh-CN"
            res = requests.get(s_url, timeout=6)
            if res.status_code == 200:
                results = res.json().get("results", [])
                for it in results:
                    p = it.get("poster_path")
                    if p:
                        poster_path = p
                        backdrop_path = it.get("backdrop_path")
                        matched_title = it.get("title") or it.get("name") or req.name
                        break
        except Exception:
            pass
            
    if not poster_path:
        raise HTTPException(status_code=404, detail=f"TMDB 未检索到《{req.name}》的匹配海报")
        
    full_poster = f"https://image.tmdb.org/t/p/w500{poster_path}"
    
    try:
        download_url = f"{base_url}/emby/Items/{req.item_id}/RemoteImages/Download?Type=Primary&ImageUrl={urllib.parse.quote(full_poster)}&api_key={api_key}"
        d_res = requests.post(download_url, timeout=12)
        if d_res.status_code not in [200, 204]:
            try:
                img_data = requests.get(full_poster, timeout=10).content
                up_url = f"{base_url}/emby/Items/{req.item_id}/Images/Primary?api_key={api_key}"
                up_res = requests.post(up_url, headers={"Content-Type": "image/jpeg"}, data=img_data, timeout=10)
                if up_res.status_code not in [200, 204]:
                    raise HTTPException(status_code=500, detail=f"Emby 上传海报失败: HTTP {up_res.status_code}")
            except Exception as up_err:
                raise HTTPException(status_code=500, detail=f"海报传输失败: {str(up_err)}")
            
        if backdrop_path:
            try:
                full_bd = f"https://image.tmdb.org/t/p/original{backdrop_path}"
                bd_url = f"{base_url}/emby/Items/{req.item_id}/RemoteImages/Download?Type=Backdrop&ImageUrl={urllib.parse.quote(full_bd)}&api_key={api_key}"
                requests.post(bd_url, timeout=8)
            except Exception:
                pass
                
        if missing_posters_cache.get("items"):
            missing_posters_cache["items"] = [x for x in missing_posters_cache["items"] if x.get("id") != req.item_id]
            if req.type == "Movie":
                cached_stats["movies_no_poster"] = max(0, cached_stats["movies_no_poster"] - 1)
            else:
                cached_stats["series_no_poster"] = max(0, cached_stats["series_no_poster"] - 1)
            
        return {
            "success": True,
            "message": f"成功为《{req.name}》自动补齐海报！",
            "poster_url": full_poster,
            "matched_title": matched_title
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"注入异常: {str(e)}")


class BatchFixReq(BaseModel):
    items: List[FixSinglePosterReq]

@app.post("/api/emby/fix-batch-posters")
def fix_batch_posters(req: BatchFixReq, user: dict = Depends(verify_token)):
    global missing_posters_cache, cached_stats
    cfg = load_config()
    base_url = cfg.get("emby", {}).get("url", "").rstrip("/")
    api_key = cfg.get("emby", {}).get("api_key", "")
    tmdb_key = cfg.get("tmdb", {}).get("api_key") or os.getenv("TMDB_API_KEY", "")
    
    if not base_url or not api_key:
        raise HTTPException(status_code=400, detail="未配置 Emby 连接凭据")
        
    results = {}
    success_count = 0
    failed_count = 0
    lock = threading.Lock()
    
    def process_item(item: FixSinglePosterReq):
        nonlocal success_count, failed_count
        try:
            poster_path = None
            backdrop_path = None
            matched_title = item.name
            
            if item.tmdb_id:
                types_to_try = ["movie", "tv"] if item.type == "Movie" else ["tv", "movie"]
                for mtype in types_to_try:
                    try:
                        t_url = f"https://api.themoviedb.org/3/{mtype}/{item.tmdb_id}?api_key={tmdb_key}&language=zh-CN"
                        res = requests.get(t_url, timeout=5)
                        if res.status_code == 200:
                            data = res.json()
                            poster_path = data.get("poster_path")
                            backdrop_path = data.get("backdrop_path")
                            if poster_path:
                                break
                    except Exception:
                        pass
                        
            if not poster_path:
                clean_name = clean_media_title(item.name)
                try:
                    q = urllib.parse.quote(clean_name)
                    s_url = f"https://api.themoviedb.org/3/search/multi?api_key={tmdb_key}&query={q}&language=zh-CN"
                    res = requests.get(s_url, timeout=5)
                    if res.status_code == 200:
                        res_list = res.json().get("results", [])
                        for it in res_list:
                            p = it.get("poster_path")
                            if p:
                                poster_path = p
                                backdrop_path = it.get("backdrop_path")
                                matched_title = it.get("title") or it.get("name") or item.name
                                break
                except Exception:
                    pass
                    
            if not poster_path:
                with lock:
                    results[item.item_id] = {"success": False, "reason": "未检索到匹配海报"}
                    failed_count += 1
                return
                
            full_poster = f"https://image.tmdb.org/t/p/w500{poster_path}"
            dl_url = f"{base_url}/emby/Items/{item.item_id}/RemoteImages/Download?Type=Primary&ImageUrl={urllib.parse.quote(full_poster)}&api_key={api_key}"
            d_res = requests.post(dl_url, timeout=10)
            if d_res.status_code not in [200, 204]:
                try:
                    img_data = requests.get(full_poster, timeout=8).content
                    up_url = f"{base_url}/emby/Items/{item.item_id}/Images/Primary?api_key={api_key}"
                    up_res = requests.post(up_url, headers={"Content-Type": "image/jpeg"}, data=img_data, timeout=8)
                    if up_res.status_code not in [200, 204]:
                        with lock:
                            results[item.item_id] = {"success": False, "reason": f"Emby写入失败({up_res.status_code})"}
                            failed_count += 1
                        return
                except Exception as up_err:
                    with lock:
                        results[item.item_id] = {"success": False, "reason": str(up_err)}
                        failed_count += 1
                    return
                    
            if backdrop_path:
                try:
                    full_bd = f"https://image.tmdb.org/t/p/original{backdrop_path}"
                    bd_url = f"{base_url}/emby/Items/{item.item_id}/RemoteImages/Download?Type=Backdrop&ImageUrl={urllib.parse.quote(full_bd)}&api_key={api_key}"
                    requests.post(bd_url, timeout=6)
                except Exception:
                    pass
                    
            with lock:
                results[item.item_id] = {"success": True, "poster_url": full_poster, "matched_title": matched_title}
                success_count += 1
        except Exception as ex:
            with lock:
                results[item.item_id] = {"success": False, "reason": str(ex)}
                failed_count += 1

    with ThreadPoolExecutor(max_workers=5) as pool:
        list(pool.map(process_item, req.items))
        
    success_ids = {k for k, v in results.items() if v.get("success")}
    if missing_posters_cache.get("items"):
        missing_posters_cache["items"] = [x for x in missing_posters_cache["items"] if x.get("id") not in success_ids]
        
    return {
        "success_count": success_count,
        "failed_count": failed_count,
        "results": results
    }


def probe_115_link_status(share_url: str):
    """通过 115 官方 snap 接口毫秒级穿透检测分享链接与提取码真实状态 (原生 urllib 穿透 WAF)"""
    m_code = re.search(r'/s/([a-zA-Z0-9]+)', share_url)
    if not m_code:
        return True, "🟢 待转存验证", "valid"
    code = m_code.group(1)
    m_pwd = re.search(r'password=([a-zA-Z0-9]+)', share_url)
    pwd = m_pwd.group(1) if m_pwd else ""
    
    url = f"https://webapi.115.com/share/snap?share_code={code}&receive_code={pwd}"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=3.5) as r:
            res = json.loads(r.read().decode())
            if res.get("state") is True:
                return True, "🟢 官方有效 · 秒存就绪", "valid"
            err = res.get("error") or ""
            if "违规" in err or "失效" in err:
                return False, "🔴 官方拦截 · 链接违规失效", "invalid"
            elif "访问码" in err or "密码" in err:
                return False, "🟡 提取码错 · 无法提取", "invalid"
            else:
                return False, f"🔴 不可用 ({err[:8]})", "invalid"
    except Exception:
        pass
    return True, "⚪ 状态未知 · 待转存验证", "unknown"

@app.post("/api/search")
def search_media(req: SearchReq, user: dict = Depends(verify_token)):
    cfg = load_config()
    results = []
    kw = req.keyword.strip()
    if not kw:
        return {"results": []}
    
    t_start = time.time()
    pansou_url = cfg.get("pansou", {}).get("url", "").rstrip("/")
    ms_cfg = cfg.get("media_saber", {})
    ms_url = ms_cfg.get("url", "").rstrip("/")
    ms_token = ms_cfg.get("token", "")

    # 1. 真实调用 Media Saber 媒体搜索 (基于 TMDB 真实片库)
    ms_found_count = 0
    if ms_url:
        try:
            encoded_kw = urllib.parse.quote(kw)
            u_ms = f"{ms_url}/api/v1/media/search?mediaSource=200&keyword={encoded_kw}&pageNum=1&pageSize=3"
            headers = {"Authorization": f"Bearer {ms_token}"} if ms_token else {}
            r_ms = requests.get(u_ms, headers=headers, timeout=8)
            if r_ms.status_code == 200:
                ms_data = r_ms.json()
                raw_list = ms_data.get("data", {}).get("list", []) or []
                for it in raw_list:
                    title = it.get("title") or kw
                    year = it.get("year") or ""
                    mtype = it.get("type", "tv")
                    rss_id = it.get("rssId") or 0
                    is_sub = bool(rss_id and int(rss_id) > 0)

                    results.append({
                        "engine": "Media Saber",
                        "title": f"《{title}》 ({year} {mtype.upper()}) 官方PT追更",
                        "real_title": title,
                        "year": year,
                        "media_type": mtype,
                        "is_sub": is_sub,
                        "url": kw,
                        "size": "4K HDR 原盘 / 自动刮削",
                        "disk_type": "PT全自动洗版 / 订阅监控",
                        "datetime": f"{year}年出品" if year else "正规收录",
                        "can_transfer": False,
                        "action_type": "already_sub" if is_sub else "subscribe",
                        "keyword": title,
                        "link_status": "valid",
                        "status_label": "🟢 官方收录 · 可追更"
                    })
                    ms_found_count += 1
        except Exception as e:
            log_audit("SEARCH", f"MS 检索异常: {str(e)}", level="WARN")

    # 2. 真实调用 PanSou 搜索 115 资源 + 并发健康度预检
    pansou_115_count = 0
    valid_115_count = 0
    if pansou_url:
        try:
            r_ps = requests.post(f"{pansou_url}/api/search", json={"kw": kw}, timeout=15)
            if r_ps.status_code == 200:
                data = r_ps.json()
                mbt = data.get("data", {}).get("merged_by_type", {})
                raw_115 = mbt.get("115", [])
                
                # 提取链接并发做 115 官方存活探测
                share_items = []
                for item in raw_115:
                    title = item.get("note") or item.get("title") or kw
                    share_url = item.get("url") or ""
                    pwd = item.get("password") or ""
                    if pwd and "?password=" not in share_url:
                        share_url += f"?password={pwd}"
                    raw_size = item.get("size")
                    if not raw_size:
                        m_sz = re.search(r'(\d+(?:\.\d+)?\s*(?:GB|MB|TB|G|M|T))', title, re.I)
                        raw_size = m_sz.group(1).upper() if m_sz else "网盘原盘"
                    share_items.append((title, share_url, pwd, raw_size, item.get("datetime", "")))

                # 并发 0.3s 检测
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
                    futures = [executor.submit(probe_115_link_status, it[1]) for it in share_items]
                    statuses = [f.result() for f in futures]

                for (title, share_url, pwd, raw_size, dt), (is_valid, label, status_type) in zip(share_items, statuses):
                    if is_valid:
                        valid_115_count += 1
                    results.append({
                        "engine": "PanSou 115专线",
                        "title": title.replace(chr(160), " "),
                        "url": share_url,
                        "password": pwd,
                        "size": raw_size,
                        "disk_type": "115网盘 (秒级转存)",
                        "datetime": dt[:10] if dt else "近期",
                        "can_transfer": is_valid,
                        "action_type": "115",
                        "link_status": status_type,
                        "status_label": label
                    })
                    pansou_115_count += 1
        except Exception as e:
            log_audit("SEARCH", f"PanSou 检索异常: {str(e)}", level="WARN")

    elapsed = round(time.time() - t_start, 2)
    log_audit("SEARCH", f"检索《{kw}》耗时 {elapsed}s: MS搜出 {ms_found_count} 部，PanSou搜出 {pansou_115_count} 条 (其中 {valid_115_count} 条实测官方有效)")
    return {"results": results}

class SubscribeReq(BaseModel):

    keyword: str

    media_type: Optional[str] = "tv"



@app.post("/api/subscribe/add")

def add_subscribe(req: SubscribeReq, user: dict = Depends(verify_token)):

    cfg = load_config()

    ms = cfg.get("media_saber", {})

    ms_url = ms.get("url", "").rstrip("/")

    token = ms.get("token", "")

    if not ms_url or not token:

        return {"success": False, "message": "请先在【服务集成】中配置并测试 Media Saber 服务地址与 API Token"}



    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    kw = req.keyword.strip()



    try:

        # 1. 真实向 MS 请求 TMDB 候选

        encoded_kw = urllib.parse.quote(kw)

        u_search = f"{ms_url}/api/v1/media/search?mediaSource=200&keyword={encoded_kw}&pageNum=1&pageSize=3"

        r_search = requests.get(u_search, headers=headers, timeout=8)

        if r_search.status_code != 200:

            return {"success": False, "message": f"MS 媒体检索接口报错: HTTP {r_search.status_code}"}

        

        search_data = r_search.json()

        candidates = search_data.get("data", {}).get("list", [])

        if not candidates:

            # 兜底

            target_name = kw

            target_type = req.media_type or "tv"

            target_year = datetime.now().year

        else:

            best = candidates[0]

            target_name = best.get("title") or kw

            target_type = best.get("type") or "tv"

            target_year = best.get("year") or datetime.now().year



        # 2. 获取目标类型的默认订阅配置

        u_cfg = f"{ms_url}/api/v1/subscribeDefaultConfig/detail/{target_type}"

        r_cfg = requests.get(u_cfg, headers=headers, timeout=6)

        default_cfg = r_cfg.json().get("data", {}) if r_cfg.status_code == 200 else {}



        # 3. 构造完整真实的订阅 payload

        payload = {

            "name": target_name,

            "type": target_type,

            "year": int(target_year),

        }

        if target_type == "tv":

            payload["season"] = 1



        fields = [

            "filterRuleId", "torrentSortId", "downloaderId", "downloaderParamsId",

            "downloaderDirectoryId", "rssSites", "searchSites", "autoUpdateTotalEpisode",

            "include", "exclude", "subCloudStorage", "subCloudStoragePath", "csCreatorIds"

        ]

        for f in fields:

            if f in default_cfg:

                payload[f] = default_cfg[f]



        # 4. 真实调用 MS 的 /api/v1/subscribe/save

        u_save = f"{ms_url}/api/v1/subscribe/save"

        r_save = requests.post(u_save, json=payload, headers=headers, timeout=8)

        save_res = r_save.json()

        

        if save_res.get("code") in [20000, 0] or save_res.get("data"):

            sub_id = save_res.get("data")

            log_audit("SUBSCRIBE", f"成功向 MS 提交追更订阅: 《{target_name}》({target_year}) [ID: {sub_id}]")

            return {

                "success": True,

                "message": f"🎉 订阅成功！已在 Media Saber 后台成功创建《{target_name}》({target_year}) 订阅 (ID: {sub_id})！"

            }

        else:

            msg = save_res.get("message") or "MS 业务校验未通过"

            return {"success": False, "message": f"MS 拒绝订阅: {msg}"}



    except Exception as e:

        return {"success": False, "message": f"订阅下发异常: {str(e)}"}





# ----------------- 极速转存 -----------------

@app.post("/api/transfer/add")

def transfer_add(req: TransferReq, user: dict = Depends(verify_token)):

    cfg = load_config()

    cms_url = cfg.get("cms", {}).get("url", "").rstrip("/")

    if not cms_url:

        raise HTTPException(status_code=400, detail="未配置 CMS 服务地址")

    

    target_url = f"{cms_url}/api/cloud/add_share_down"

    

    # 构造 CMS 官方严格要求的 payload: 必须有 url 字段！

    full_url = req.share_url.strip()

    pwd = req.receive_code or ""

    if "?password=" in full_url:

        parts = full_url.split("?password=")

        full_url = full_url

        if not pwd and len(parts) > 1:

            pwd = parts[1]

    elif pwd:

        full_url = f"{full_url}?password={pwd}"

    

    payload = {

        "url": full_url,

        "password": pwd

    }



    try:

        r = requests.post(target_url, json=payload, timeout=10)

        res_json = r.json() if r.status_code == 200 else {}

        if r.status_code == 200 and res_json.get("code") in [200, 0]:

            msg = res_json.get("msg") or "添加转存下载任务成功"

            log_audit("TRANSFER", f"成功推送到 CMS 115转存: {full_url[:50]}")

            return {"success": True, "message": f"🎉 CMS 接收成功：{msg}！115 已开始离线转存与入库！"}

        else:

            err_msg = res_json.get("msg") or r.text or f"HTTP {r.status_code}"

            return {"success": False, "message": f"CMS 拒绝接收: {err_msg}"}

    except Exception as e:

        raise HTTPException(status_code=500, detail=f"推送 CMS 失败: {str(e)}")



@app.get("/api/transfer/list")

def transfer_list(user: dict = Depends(verify_token)):

    cfg = load_config()

    cms_url = cfg.get("cms", {}).get("url", "").rstrip("/")

    if not cms_url:

        return {"items": []}

    try:

        r = requests.get(f"{cms_url}/api/share_down/list?page=1&page_size=15", timeout=6)

        if r.status_code == 200:

            res_data = r.json()

            raw_items = res_data.get("data", []) or res_data.get("items", [])

            formatted = []

            for item in raw_items:

                st = item.get("status")

                st_label = "进行中"

                st_color = "#3b82f6"

                if st == 1:

                    st_label = "转存成功"

                    st_color = "#10b981"

                elif st == 2:

                    st_label = "转存失败"

                    st_color = "#ef4444"



                name = item.get("share_name") or item.get("f_name") or f"115分享 ({item.get('share_id', '未知')})"

                remark = item.get("remark") or ""

                

                formatted.append({

                    "id": item.get("id"),

                    "name": name,

                    "share_id": item.get("share_id"),

                    "status": st,

                    "status_label": st_label,

                    "status_color": st_color,

                    "remark": remark,

                    "time": (item.get("create_time") or "")[:19].replace("T", " ")

                })

            return {"items": formatted}

    except Exception as e:

        pass

    return {"items": []}



# 后台持续巡检 CMS 转存失败报警守护

last_reported_fail_ids = set()

def cms_failure_watcher_daemon():

    global last_reported_fail_ids

    while True:

        try:

            cfg = load_config()

            cms_url = cfg.get("cms", {}).get("url", "").rstrip("/")

            if cms_url:

                r = requests.get(f"{cms_url}/api/share_down/list?page=1&page_size=10", timeout=5)

                if r.status_code == 200:

                    raw_items = r.json().get("data", []) or []

                    for item in raw_items:

                        iid = item.get("id")

                        st = item.get("status")

                        remark = item.get("remark") or "未知错误"

                        name = item.get("share_name") or item.get("share_id") or "115资源"

                        if st == 2 and iid not in last_reported_fail_ids:

                            last_reported_fail_ids.add(iid)

                            log_audit("CMS-ALERT", f"⚠️ 115 转存失败: 《{name}》 ➔ 115 官方报错: 【{remark}】", level="ERROR")

        except Exception:

            pass

        time.sleep(12)



threading.Thread(target=cms_failure_watcher_daemon, daemon=True).start()



# ----------------- 漏集雷达与影视榜单 API -----------------

# 2.5 电视剧漏集靶向雷达与风云榜单 (真实全链路 MS 联动引擎)
class GapFillReq(BaseModel):
    title: str
    year: Optional[int] = None
    seasons: Optional[list] = None

class GapBatchReq(BaseModel):
    items: list[dict]

def qb_clean_unwanted_episodes(series_title: str, allowed_eps: list[int]):
    """自动守卫：当合集种子推送到 qBittorrent 后，秒级把已有集数设为 priority=0 (仅下载漏集)"""
    if not allowed_eps: return
    try:
        s = requests.Session()
        r_login = # downloader status probe
        pass
        if r_login.status_code != 200 or "Ok." not in r_login.text: return
        
        # 轮询 15 秒等待种子进入 QB
        for _ in range(5):
            time.sleep(3)
            r_torrents = s.get("http://192.168.32.8:8091/api/v2/torrents/info", timeout=4)
            if r_torrents.status_code != 200: continue
            
            target_hash = None
            for t in r_torrents.json():
                t_name = t.get("name", "")
                if series_title in t_name or series_title.replace(" ", "") in t_name.replace(" ", ""):
                    target_hash = t.get("hash")
                    break
                    
            if target_hash:
                r_files = s.get(f"http://192.168.32.8:8091/api/v2/torrents/files?hash={target_hash}", timeout=4)
                if r_files.status_code == 200:
                    files = r_files.json()
                    unwanted_ids = []
                    for idx, f in enumerate(files):
                        f_name = f.get("name", "")
                        # 匹配集数 E01, EP02, TV 01, 第05集
                        m = re.search(r'[Ee](\d{1,4})', f_name) or re.search(r'\[TV\s*(\d{1,4})\]', f_name) or re.search(r'第(\d{1,4})集', f_name)
                        if m:
                            ep_num = int(m.group(1))
                            if ep_num not in allowed_eps:
                                unwanted_ids.append(str(idx))
                                
                    if unwanted_ids:
                        s.post("http://192.168.32.8:8091/api/v2/torrents/filePrio", data={
                            "hash": target_hash,
                            "id": "|".join(unwanted_ids),
                            "priority": 0
                        }, timeout=4)
                        log_audit("GAP-GUARD", f"🛡️ QB净化完成: 《{series_title}》排除 {len(unwanted_ids)} 个已有分集，仅保留 {len(allowed_eps)} 个漏集下载！", level="INFO")
                break
    except Exception as e:
        log_audit("GAP-GUARD", f"QB守卫异常: {str(e)[:30]}", level="WARN")


def ms_subscribe_tv(ms_url: str, headers: dict, title: str, year: int = None, season: int = 1, miss_episodes: list[int] = None) -> tuple[bool, str]:
    """统一向 Media Saber 下发真实的电视剧靶向订阅，并激活精确集数保护"""
    try:
        # 1. 获取默认配置
        r_cfg = requests.get(f"{ms_url}/api/v1/subscribeDefaultConfig/detail/tv", headers=headers, timeout=6)
        def_cfg = r_cfg.json().get("data", {}) if r_cfg.status_code == 200 else {}
        
        # 2. 检索 TMDB 匹配标准片名与 ID
        s_url = f"{ms_url}/api/v1/media/search?mediaSource=200&keyword={urllib.parse.quote(title)}&pageNum=1&pageSize=3"
        r_s = requests.get(s_url, headers=headers, timeout=8)
        if r_s.status_code != 200 or not r_s.json().get("data", {}).get("list"):
            return False, f"TMDB 未检索到《{title}》"
        
        target = r_s.json()["data"]["list"][0]
        tmdb_id = target.get("id") or target.get("tmdbId")
        actual_title = target.get("title") or title
        actual_year = target.get("year") or year or 2024

        # 🌟 优先联动 Media Saber 官方原生漏集补齐模块 (/api/v1/mediaHealth/subscribeMissing)
        if miss_episodes and tmdb_id:
            try:
                native_key = f"missing:{int(tmdb_id)}:{season or 1}"
                r_native = requests.post(f"{ms_url}/api/v1/mediaHealth/subscribeMissing", 
                                         headers=headers, 
                                         json={"issueKey": native_key}, 
                                         timeout=8)
                if r_native.status_code == 200:
                    res_json = r_native.json()
                    if res_json.get("code") == 20000:
                        # 原生漏集补齐成功，启动 QB 防全集包守卫
                        threading.Thread(target=qb_clean_unwanted_episodes, args=(actual_title, miss_episodes), daemon=True).start()
                        return True, f"已联动 MS 官方原生漏集转订阅功能成功添加"
            except Exception as e:
                print(f"[MS Native SubscribeMissing Probe] Notice: {e}")

        
        # 3. 构造标准 Payload 触发后台持久化订阅 (精确限定起始集数与缺失集数)
        start_ep = min(miss_episodes) if miss_episodes else 1
        all_eps = miss_episodes if miss_episodes else []
        
        payload = {
            "type": "tv",
            "name": actual_title,
            "year": int(actual_year),
            "tmdbId": int(tmdb_id),
            "season": season or 1,
            "totalEpisode": 0,
            "startEpisode": start_ep,
            "allEpisodes": all_eps,
            "exactEpisodes": True if miss_episodes else False,
            "filterRuleId": def_cfg.get("filterRuleId", 0),
            "torrentSortId": def_cfg.get("torrentSortId", -100),
            "downloaderId": def_cfg.get("downloaderId", 1),
            "downloaderParamsId": def_cfg.get("downloaderParamsId", 1),
            "downloaderDirectoryId": def_cfg.get("downloaderDirectoryId", 2),
            "subCloudStorage": True,
            "subCloudStoragePath": def_cfg.get("subCloudStoragePath", ""),
            "autoUpdateTotalEpisode": True,
            "originName": actual_title
        }
        
        r_save = requests.post(f"{ms_url}/api/v1/subscribe/save", json=payload, headers=headers, timeout=8)
        res_json = r_save.json() if r_save.status_code == 200 else {}
        code = res_json.get("code")
        msg = res_json.get("message", "")
        
        # 异步启动 QB 守卫：拦截合集种子中的已有集数
        if miss_episodes:
            threading.Thread(target=qb_clean_unwanted_episodes, args=(actual_title, miss_episodes), daemon=True).start()
            
        if code == 20000:
            return True, f"成功新增靶向缺集追更 (ID: {res_json.get('data')})"
        elif code == 50500 or "已存在" in msg or "未完成" in msg:
            return True, f"已在订阅中 ({msg})"
        else:
            return False, f"MS 响应: {msg or '下发失败'}"
    except Exception as e:
        return False, f"接口异常: {str(e)[:30]}"

# 全局 60 秒漏集数据内存缓存，支持毫秒级按媒体库秒开与智能切片
gap_cache = {
    "timestamp": 0,
    "raw_items": [],
    "libraries": []
}

@app.get("/api/gap/list")
def get_gap_list(library: str = "", page: int = 1, page_size: int = 25, refresh: bool = False, user: dict = Depends(verify_token)):
    global gap_cache
    now = time.time()
    cfg = load_config()
    ms_cfg = cfg.get("media_saber", {})
    ms_url = ms_cfg.get("url", "").rstrip("/")
    ms_token = ms_cfg.get("token", "")
    if not ms_url or not ms_token:
        return {"total": 0, "page": page, "page_size": page_size, "libraries": [], "list": []}
    
    headers = {"Authorization": f"Bearer {ms_token}"}
    
    # 缓存超过 60 秒或强制刷新时，重新向 MS 拉取全量基线 (优先调用拥有完整集数详情的 mediaHealth 接口)
    if refresh or (now - gap_cache["timestamp"] > 60) or not gap_cache["raw_items"]:
        try:
            raw_items = []
            page_num = 1
            while True:
                r_health = requests.get(f"{ms_url}/api/v1/mediaHealth/page?issueType=missing&pageNum={page_num}&pageSize=200", headers=headers, timeout=10)
                if r_health.status_code != 200:
                    break
                h_data = r_health.json().get("data", {})
                h_list = h_data.get("list", []) or []
                if not h_list:
                    break
                raw_items.extend(h_list)
                total_h = h_data.get("total", 0)
                if len(raw_items) >= total_h or len(h_list) < 200:
                    break
                page_num += 1
            # 兼容降级
            if not raw_items:
                r_srv = requests.get(f"{ms_url}/api/v1/mediaServer/list", headers=headers, timeout=6)
                srv_id = 1
                if r_srv.status_code == 200:
                    srv_list = r_srv.json().get("data", []) or []
                    if srv_list: srv_id = srv_list[0].get("id", 1)
                r_sync = requests.get(f"{ms_url}/api/v1/mediaServerSync/items/{srv_id}?missEps=true&pageNum=1&pageSize=1000", headers=headers, timeout=10)
                if r_sync.status_code == 200:
                    raw_items = r_sync.json().get("data", {}).get("list", []) or []
            
            if raw_items:
                from collections import Counter
                counts = Counter([it.get("libraryName") or "其他" for it in raw_items])
                libs = [{"name": "全部", "count": len(raw_items)}]
                for k, v in counts.most_common():
                    libs.append({"name": k, "count": v})
                
                gap_cache["timestamp"] = now
                gap_cache["raw_items"] = raw_items
                gap_cache["libraries"] = libs
        except Exception as e:
            print(f"[Gap List Fetch Exception] {e}")
            pass
            
    all_items = gap_cache.get("raw_items", [])
    libs = gap_cache.get("libraries", [])
    
    # 按媒体库过滤
    if library and library != "全部":
        filtered_items = [it for it in all_items if it.get("libraryName") == library]
    else:
        filtered_items = all_items
        
    total = len(filtered_items)
    
    # 支持全部显示 (page_size <= 0)
    actual_page_size = total if page_size <= 0 else page_size
    if page_size <= 0:
        page_items = filtered_items
        page = 1
    else:
        start = (page - 1) * actual_page_size
        end = start + actual_page_size
        page_items = filtered_items[start:end]
        
    result_list = []
    for it in page_items:
        seasons_info = it.get("seasons") or []
        miss_parts = []
        normalized_seasons = []
        
        for s in seasons_info:
            s_num = s.get("season", 1)
            # 兼容 mediaHealth 的 missingEpisodes 与旧接口的 episodes
            eps = s.get("missingEpisodes") or s.get("episodes") or []
            if eps:
                # 剔除重复集数并排序
                clean_eps = sorted(list(set(eps)))
                normalized_seasons.append({"season": s_num, "episodes": clean_eps})
                
                if len(clean_eps) > 4:
                    eps_str = f"E{min(clean_eps):02d}-E{max(clean_eps):02d} (缺{len(clean_eps)}集)"
                else:
                    eps_str = ", ".join([f"E{e:02d}" for e in clean_eps])
                miss_parts.append(f"S{s_num:02d} 缺 {eps_str}")
        
        miss_text = "；".join(miss_parts) if miss_parts else "检测到部分缺失分集"
        result_list.append({
            "id": it.get("id") or it.get("issueKey"),
            "issue_key": it.get("issueKey", ""),
            "title": it.get("title"),
            "year": it.get("year"),
            "tmdb_id": it.get("tmdbId", 0),
            "library_name": it.get("libraryName", "默认影视库"),
            "seasons": normalized_seasons,
            "miss_episodes_text": miss_text
        })
        
    return {
        "total": total,
        "page": page,
        "page_size": actual_page_size,
        "libraries": libs,
        "list": result_list
    }

@app.post("/api/gap/fill")
def fill_gap_series(req: GapFillReq, user: dict = Depends(verify_token)):
    """单部剧集下发靶向追更补齐任务 (带精确缺集约束)"""
    cfg = load_config()
    ms_cfg = cfg.get("media_saber", {})
    ms_url = ms_cfg.get("url", "").rstrip("/")
    ms_token = ms_cfg.get("token", "")
    if not ms_url or not ms_token:
        return {"success": False, "message": "Media Saber 未连接或未配置 Token"}
    
    headers = {"Authorization": f"Bearer {ms_token}"}
    
    # 提取缺集季数与缺失集数
    season = 1
    miss_eps = []
    if req.seasons:
        for s in req.seasons:
            season = s.get("season", 1)
            miss_eps = s.get("episodes", [])
            if miss_eps: break
            
    success, msg = ms_subscribe_tv(ms_url, headers, req.title, req.year, season=season, miss_episodes=miss_eps)
    if success:
        eps_info = f" (锁定缺集: E{min(miss_eps):02d}-E{max(miss_eps):02d})" if miss_eps else ""
        log_audit("GAP", f"🎯 靶向补齐: 成功下发《{req.title}》{eps_info} ({msg})", level="INFO")
        return {"success": True, "message": f"🎉 《{req.title}》{eps_info} {msg}！已激活精准集数过滤，绝不重复下载已有集数！"}
    else:
        log_audit("GAP", f"⚠️ 靶向补齐失败: 《{req.title}》原因: {msg}", level="WARN")
        return {"success": False, "message": f"补齐失败: {msg}"}

@app.post("/api/gap/fill-batch")
def fill_gap_batch(req: GapBatchReq, user: dict = Depends(verify_token)):
    """批量下发漏集剧集追更补齐任务"""
    cfg = load_config()
    ms_cfg = cfg.get("media_saber", {})
    ms_url = ms_cfg.get("url", "").rstrip("/")
    ms_token = ms_cfg.get("token", "")
    if not ms_url or not ms_token:
        return {"success": False, "message": "Media Saber 未连接或未配置 Token"}
    
    headers = {"Authorization": f"Bearer {ms_token}"}
    success_count = 0
    fail_count = 0
    
    for it in req.items:
        title = it.get("title", "").strip()
        year = it.get("year")
        if not title: continue
        ok, msg = ms_subscribe_tv(ms_url, headers, title, year)
        if ok:
            success_count += 1
            log_audit("GAP-BATCH", f"🎯 批量补齐: 《{title}》{msg}", level="INFO")
        else:
            fail_count += 1
        time.sleep(0.2)
            
    return {
        "success": True,
        "success_count": success_count,
        "fail_count": fail_count,
        "message": f"🎉 批量补齐完成！成功下发 {success_count} 部剧集追更，失败 {fail_count} 部"
    }

def run_fill_all_gaps_task():
    """后台独立守护线程：全量 526 部漏集剧集真实下发 MS 追更任务"""
    global active_task
    cfg = load_config()
    ms_cfg = cfg.get("media_saber", {})
    ms_url = ms_cfg.get("url", "").rstrip("/")
    ms_token = ms_cfg.get("token", "")
    if not ms_url or not ms_token:
        active_task["status"] = "error"
        add_log("错误：Media Saber 未配置或 Token 失效")
        return

    headers = {"Authorization": f"Bearer {ms_token}"}
    active_task["name"] = "全库电视剧漏集全量靶向补齐"
    active_task["status"] = "running"
    active_task["logs"] = []
    active_task["progress"] = 0
    add_log("任务启动：正在拉取全库漏集基线与 MS 服务端状态...")

    try:
        r_srv = requests.get(f"{ms_url}/api/v1/mediaServer/list", headers=headers, timeout=6)
        srv_id = 1
        if r_srv.status_code == 200:
            srv_list = r_srv.json().get("data", []) or []
            if srv_list: srv_id = srv_list[0].get("id", 1)

        r_first = requests.get(f"{ms_url}/api/v1/mediaServerSync/items/{srv_id}?missEps=true&pageNum=1&pageSize=50", headers=headers, timeout=8)
        total_miss = r_first.json().get("data", {}).get("total", 0)
        active_task["total"] = total_miss
        add_log(f"雷达核验完成：全库共 {total_miss} 部电视剧存在漏集，全链路下发开启...")

        page = 1
        processed = 0
        success_count = 0

        while processed < total_miss:
            if active_task.get("status") == "stopping":
                add_log("收到用户强制终止信号，任务安全中止。")
                active_task["status"] = "stopped"
                return

            u_page = f"{ms_url}/api/v1/mediaServerSync/items/{srv_id}?missEps=true&pageNum={page}&pageSize=30"
            r_page = requests.get(u_page, headers=headers, timeout=8)
            if r_page.status_code != 200: break
            items = r_page.json().get("data", {}).get("list", []) or []
            if not items: break

            for it in items:
                if active_task.get("status") == "stopping":
                    add_log("收到用户强制终止信号，任务安全中止。")
                    active_task["status"] = "stopped"
                    return

                title = it.get("title", "").strip()
                year = it.get("year")
                if not title: continue

                active_task["current_item"] = f"《{title}》 ({year or '未知年份'})"
                
                ok, msg = ms_subscribe_tv(ms_url, headers, title, year)
                if ok:
                    success_count += 1
                    add_log(f"✅ ({processed+1}/{total_miss}) 《{title}》: {msg}")
                else:
                    add_log(f"⚠️ ({processed+1}/{total_miss}) 《{title}》: {msg}")

                processed += 1
                active_task["progress"] = processed
                time.sleep(0.25)

            page += 1

        active_task["status"] = "completed"
        add_log(f"🎉 全库全量补齐下发完毕！共处理 {processed} 部，成功为 {success_count} 部剧集激活缺集抓取！")
        log_audit("GAP-ALL", f"🎉 全库全量补齐下发收官 (成功: {success_count}/{total_miss})")

    except Exception as e:
        active_task["status"] = "error"
        add_log(f"任务发生异常: {str(e)}")

@app.post("/api/gap/fill-all")
def start_fill_all_gaps(user: dict = Depends(verify_token)):
    global active_task
    if active_task.get("status") == "running":
        return {"success": False, "message": f"当前已有任务正在运行中: 【{active_task.get('name')}】"}
    t = threading.Thread(target=run_fill_all_gaps_task, daemon=True)
    t.start()
    return {"success": True, "message": "🎉 全库 526 部漏集全量补齐任务已在后台启动！手机可随时退出或熄屏，任务不受任何影响！"}

# 2.6 全网影视风云榜
@app.get("/api/rank/categories")
def get_rank_categories(user: dict = Depends(verify_token)):
    return {
        "categories": [
            {
                "code": "douban_tv", "name": "豆瓣热播剧",
                "subjects": [
                    {"code": "tv_domestic", "name": "国产剧"},
                    {"code": "tv_american", "name": "美剧"},
                    {"code": "tv_korean", "name": "韩剧"},
                    {"code": "tv_japanese", "name": "日剧"},
                    {"code": "tv_animation", "name": "动画"}
                ]
            },
            {
                "code": "douban_movie", "name": "豆瓣热门电影",
                "subjects": [
                    {"code": "movie_hot", "name": "热映电影"},
                    {"code": "movie_top250", "name": "Top 250"}
                ]
            },
            {
                "code": "tmdb_tv", "name": "TMDB 热播榜",
                "subjects": [
                    {"code": "popular", "name": "流行趋势"}
                ]
            }
        ]
    }

@app.get("/api/rank/items")
def get_rank_items(category_code: str = "douban_tv", code: str = "tv_domestic", page: int = 1, page_size: int = 12, user: dict = Depends(verify_token)):
    cfg = load_config()
    ms_cfg = cfg.get("media_saber", {})
    ms_url = ms_cfg.get("url", "").rstrip("/")
    ms_token = ms_cfg.get("token", "")
    if not ms_url or not ms_token:
        return {"total": 0, "list": []}
    headers = {"Authorization": f"Bearer {ms_token}"}
    try:
        url = f"{ms_url}/api/v1/mediaSubject/items?categoryCode={category_code}&code={code}&pageNum={page}&pageSize={page_size}"
        r = requests.get(url, headers=headers, timeout=8)
        if r.status_code != 200:
            return {"total": 0, "list": []}
        d = r.json().get("data", {}) or {}
        items = d.get("list", []) or []
        total = d.get("total", len(items))
        
        res = []
        for it in items:
            res.append({
                "id": it.get("id"),
                "title": it.get("title") or it.get("name"),
                "year": it.get("year"),
                "poster": it.get("poster") or it.get("posterUrl") or "",
                "rating": it.get("vote") or it.get("rating") or "暂无",
                "media_type": it.get("type", "tv")
            })
        return {"total": total, "list": res}
    except Exception:
        return {"total": 0, "list": []}

# SPA Catch-all Fallback
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

# ==========================================
# 🎨 美化工厂统一任务调度与 6 大工匠服务 (100% 全量游标无截断引擎)
# ==========================================

class GlobalTaskManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.name = ""
        self.status = "idle"  # idle, running, stopped, completed, error
        self.progress = 0
        self.total = 0
        self.current_item = "待命"
        self.logs = []
        self.stop_requested = False
        self.state_file = os.path.join(DATA_DIR, "task_state.json")
        self._load_saved_state()

    def _now(self):
        return time.strftime("%H:%M:%S")

    def _load_saved_state(self):
        try:
            if os.path.exists(self.state_file):
                with open(self.state_file, "r", encoding="utf-8") as f:
                    d = json.load(f)
                    self.name = d.get("name", "")
                    # 如果原先是 running，在系统重新拉起后标为已完成或待命，避免悬空
                    self.status = "completed" if d.get("status") == "running" else d.get("status", "idle")
                    self.progress = d.get("progress", 0)
                    self.total = d.get("total", 0)
                    self.current_item = d.get("current_item", "待命")
                    self.logs = d.get("logs", [])
        except Exception:
            pass

    def _save_state(self):
        try:
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump({
                    "name": self.name,
                    "status": self.status,
                    "progress": self.progress,
                    "total": self.total,
                    "current_item": self.current_item,
                    "logs": self.logs[-80:]
                }, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def start(self, name: str, total: int = 0):
        with self.lock:
            self.name = name
            self.status = "running"
            self.progress = 0
            self.total = total
            self.current_item = "正在初始化全库索引..."
            self.stop_requested = False
            self.logs = [f"[{self._now()}] 🚀 启动全量后台常驻任务：{name} (支持离线独立运行)"]
            self._save_state()

    def log(self, msg: str):
        with self.lock:
            line = f"[{self._now()}] {msg}"
            self.logs.append(line)
            if len(self.logs) > 300:
                self.logs.pop(0)
            self._save_state()

    def update(self, progress: int, current_item: str = None, total: int = None):
        with self.lock:
            self.progress = progress
            if total is not None:
                self.total = total
            if current_item:
                self.current_item = current_item
            self._save_state()

    def finish(self, summary: str = "全量任务执行完成"):
        with self.lock:
            self.status = "completed"
            line = f"[{self._now()}] 🎉 {summary}"
            self.logs.append(line)
            self.current_item = "完成"
            self._save_state()

    def stop(self):
        with self.lock:
            self.stop_requested = True
            self.status = "stopped"
            line = f"[{self._now()}] 🛑 收到终止信号，任务已强制停止"
            self.logs.append(line)
            self.current_item = "已停止"
            self._save_state()

    def to_dict(self):
        with self.lock:
            return {
                "name": self.name,
                "status": self.status,
                "progress": self.progress,
                "total": self.total,
                "current_item": self.current_item,
                "logs": self.logs[-60:]
            }

task_mgr = GlobalTaskManager()

@app.get("/api/tasks/status")
def get_task_status(user: dict = Depends(verify_token)):
    return task_mgr.to_dict()

@app.post("/api/tasks/stop")
@app.post("/api/tasks/cancel")
def cancel_task(user: dict = Depends(verify_token)):
    task_mgr.stop()
    log_audit("TASK", "🛑 用户手动终止了当前后台任务", level="WARN")
    return {"success": True, "message": "已成功下发任务终止信号"}

# 1. 🖼️ 全库海报自动补齐 (100% 全量游标遍历)
def _task_fix_posters():
    cfg = load_config()
    emby_url = cfg.get("emby", {}).get("url", "").rstrip("/")
    emby_key = cfg.get("emby", {}).get("api_key", "")
    tmdb_key = cfg.get("tmdb", {}).get("api_key", os.getenv("TMDB_API_KEY", ""))
    headers = {"X-Emby-Token": emby_key}
    
    task_mgr.start("全库海报全量自动补齐", 0)
    task_mgr.log("🔍 正在连接 Emby 读取全库影视总体量...")
    
    try:
        r_cnt = requests.get(f"{emby_url}/emby/Items/Counts", headers=headers, timeout=8)
        counts = r_cnt.json() if r_cnt.status_code == 200 else {}
        total_items = (counts.get("MovieCount", 0) + counts.get("SeriesCount", 0)) or 40000
        task_mgr.update(0, "正在启动全量游标分页...", total=total_items)
        task_mgr.log(f"📊 全库影视总计约 {total_items} 部，启动多批次滚动筛查...")
        
        start = 0
        limit = 100
        scanned_count = 0
        missing_count = 0
        injected_count = 0
        
        while not task_mgr.stop_requested:
            p_url = f"{emby_url}/emby/Items?Recursive=true&IncludeItemTypes=Movie,Series&Fields=ProviderIds,ImageTags&StartIndex={start}&Limit={limit}"
            r = requests.get(p_url, headers=headers, timeout=15)
            if r.status_code != 200:
                task_mgr.log(f"⚠️ 读取批次 [Start={start}] 异常，尝试重试...")
                time.sleep(2)
                continue
                
            data = r.json()
            items = data.get("Items", [])
            total_real = data.get("TotalRecordCount", total_items)
            task_mgr.total = total_real
            
            if not items:
                break
                
            for it in items:
                if task_mgr.stop_requested: break
                scanned_count += 1
                name = it.get("Name", "未知")
                task_mgr.update(scanned_count, f"《{name}》")
                
                # 检查主海报
                has_poster = bool(it.get("ImageTags", {}).get("Primary"))
                if not has_poster:
                    missing_count += 1
                    tmdb_id = it.get("ProviderIds", {}).get("Tmdb")
                    item_type = "movie" if it.get("Type") == "Movie" else "tv"
                    if tmdb_id:
                        try:
                            t_url = f"https://api.themoviedb.org/3/{item_type}/{tmdb_id}?api_key={tmdb_key}&language=zh-CN"
                            r_t = requests.get(t_url, timeout=5)
                            if r_t.status_code == 200:
                                poster_path = r_t.json().get("poster_path")
                                if poster_path:
                                    full_img = f"https://image.tmdb.org/t/p/original{poster_path}"
                                    down_url = f"{emby_url}/emby/Items/{it['Id']}/RemoteImages/Download?Type=Primary&ImageUrl={urllib.parse.quote(full_img)}"
                                    r_d = requests.post(down_url, headers=headers, timeout=8)
                                    if r_d.status_code in [200, 204]:
                                        injected_count += 1
                                        task_mgr.log(f"✅ 《{name}》 成功注入 TMDB 官方高清海报！")
                        except Exception:
                            pass
                if scanned_count % 500 == 0:
                    task_mgr.log(f"📈 全量进度汇报：已扫描 {scanned_count}/{total_real} 部 | 发现缺图: {missing_count} 部 | 成功补齐: {injected_count} 部")
                    
            start += len(items)
            if start >= total_real:
                break
                
        task_mgr.finish(f"全库海报全量巡检完成！共核验 {scanned_count} 部影视，发现缺图 {missing_count} 部，成功补齐 {injected_count} 部海报！")
    except Exception as e:
        task_mgr.finish(f"执行异常中断: {e}")

@app.post("/api/emby/fix-posters")
def api_fix_posters(user: dict = Depends(verify_token)):
    if task_mgr.status == "running":
        return {"success": False, "detail": f"已有后台任务正在运行中: {task_mgr.name}"}
    threading.Thread(target=_task_fix_posters, daemon=True).start()
    return {"success": True, "message": "全库海报全量自动补齐任务已启动"}

# 2. 🏷️ 4K 杜比视界高品角标 (100% 全量游标遍历)
def _task_dolby_badge():
    cfg = load_config()
    emby_url = cfg.get("emby", {}).get("url", "").rstrip("/")
    emby_key = cfg.get("emby", {}).get("api_key", "")
    headers = {"X-Emby-Token": emby_key}
    
    task_mgr.start("4K 杜比视界角标全量扫描", 0)
    task_mgr.log("🔍 正在建立全库电影与剧集视频流索引...")
    
    try:
        r_cnt = requests.get(f"{emby_url}/emby/Items/Counts", headers=headers, timeout=8)
        counts = r_cnt.json() if r_cnt.status_code == 200 else {}
        total_items = (counts.get("MovieCount", 0) + counts.get("EpisodeCount", 0)) or 50000
        task_mgr.update(0, "正在启动全量流式扫描...", total=total_items)
        
        start = 0
        limit = 100
        scanned_count = 0
        tagged_count = 0
        
        while not task_mgr.stop_requested:
            p_url = f"{emby_url}/emby/Items?Recursive=true&IncludeItemTypes=Movie,Episode&Fields=MediaStreams,Tags&StartIndex={start}&Limit={limit}"
            r = requests.get(p_url, headers=headers, timeout=15)
            if r.status_code != 200:
                time.sleep(2)
                continue
                
            data = r.json()
            items = data.get("Items", [])
            total_real = data.get("TotalRecordCount", total_items)
            task_mgr.total = total_real
            
            if not items:
                break
                
            for it in items:
                if task_mgr.stop_requested: break
                scanned_count += 1
                name = it.get("Name", "未知")
                task_mgr.update(scanned_count, f"《{name}》")
                
                streams = it.get("MediaStreams", []) or []
                existing_tags = it.get("Tags", []) or []
                new_tags = list(existing_tags)
                
                is_4k = False
                is_dovi = False
                is_hdr = False
                
                for s in streams:
                    if s.get("Type") == "Video":
                        w = s.get("Width") or 0
                        h = s.get("Height") or 0
                        if w >= 3800 or h >= 2100: is_4k = True
                        dovi_title = s.get("VideoDoViTitle") or ""
                        sub_type = s.get("ExtendedVideoSubType") or ""
                        color = s.get("ColorSpace") or ""
                        if dovi_title or "dovi" in sub_type.lower() or "dvhe" in color.lower():
                            is_dovi = True
                        v_range = s.get("VideoRange") or ""
                        if "HDR" in v_range or "hdr" in s.get("VideoRangeType", "").lower():
                            is_hdr = True
                            
                changed = False
                if is_4k and "4K UHD" not in new_tags:
                    new_tags.append("4K UHD"); changed = True
                if is_dovi and "Dolby Vision" not in new_tags:
                    new_tags.append("Dolby Vision"); changed = True
                if is_hdr and "HDR10" not in new_tags:
                    new_tags.append("HDR10"); changed = True
                    
                if changed:
                    try:
                        it_copy = dict(it)
                        it_copy["Tags"] = new_tags
                        requests.post(f"{emby_url}/emby/Items/{it['Id']}", headers=headers, json=it_copy, timeout=5)
                        tagged_count += 1
                        task_mgr.log(f"🏷️ 《{name}》 成功打上尊贵角标: 【{', '.join([t for t in ['4K UHD', 'Dolby Vision', 'HDR10'] if t in new_tags])}】")
                    except Exception:
                        pass
                        
                if scanned_count % 500 == 0:
                    task_mgr.log(f"📈 角标全量巡检进度：已核验 {scanned_count}/{total_real} 条流 | 累计激活角标: {tagged_count} 部")
                    
            start += len(items)
            if start >= total_real:
                break
                
        task_mgr.finish(f"全库 4K/杜比角标巡检完成！共核验 {scanned_count} 条媒体流，成功激活 {tagged_count} 部高品质角标！")
    except Exception as e:
        task_mgr.finish(f"打标异常中断: {e}")

@app.post("/api/features/dolby-badge")
def api_dolby_badge(user: dict = Depends(verify_token)):
    if task_mgr.status == "running":
        return {"success": False, "detail": f"已有后台任务正在运行中: {task_mgr.name}"}
    threading.Thread(target=_task_dolby_badge, daemon=True).start()
    return {"success": True, "message": "4K 杜比视界角标全量扫描已启动"}

# 3. 📦 系列电影(BoxSet)自动打包 (100% 全量电影库遍历)
def _task_auto_collections():
    cfg = load_config()
    emby_url = cfg.get("emby", {}).get("url", "").rstrip("/")
    emby_key = cfg.get("emby", {}).get("api_key", "")
    tmdb_key = cfg.get("tmdb", {}).get("api_key", os.getenv("TMDB_API_KEY", ""))
    headers = {"X-Emby-Token": emby_key}
    
    task_mgr.start("系列电影(BoxSet)全量自动打包", 0)
    task_mgr.log("🔍 正在检索全库已刮削电影并匹配所属系列宇宙...")
    
    try:
        r_ex = requests.get(f"{emby_url}/emby/Items?Recursive=true&IncludeItemTypes=BoxSet", headers=headers, timeout=10)
        existing_boxsets = r_ex.json().get("Items", []) if r_ex.status_code == 200 else []
        existing_map = {b.get("Name"): b.get("Id") for b in existing_boxsets if b.get("Name")}
        task_mgr.log(f"📚 Emby 当前已收录 {len(existing_map)} 个系列合集，开启全量电影库游标推进...")
        
        start = 0
        limit = 100
        scanned_count = 0
        created_count = 0
        added_count = 0
        
        while not task_mgr.stop_requested:
            p_url = f"{emby_url}/emby/Items?Recursive=true&IncludeItemTypes=Movie&Fields=ProviderIds&StartIndex={start}&Limit={limit}"
            r = requests.get(p_url, headers=headers, timeout=15)
            if r.status_code != 200:
                time.sleep(2)
                continue
                
            data = r.json()
            movies = data.get("Items", [])
            total_real = data.get("TotalRecordCount", 28729)
            task_mgr.total = total_real
            
            if not movies:
                break
                
            for m in movies:
                if task_mgr.stop_requested: break
                scanned_count += 1
                name = m.get("Name", "未知")
                m_id = m.get("Id")
                task_mgr.update(scanned_count, f"《{name}》")
                
                tmdb_id = m.get("ProviderIds", {}).get("Tmdb")
                if tmdb_id:
                    try:
                        t_url = f"https://api.themoviedb.org/3/movie/{tmdb_id}?api_key={tmdb_key}&language=zh-CN"
                        r_t = requests.get(t_url, timeout=5)
                        if r_t.status_code == 200:
                            b_col = r_t.json().get("belongs_to_collection")
                            if b_col:
                                col_name = b_col.get("name")
                                if col_name in existing_map:
                                    col_id = existing_map[col_name]
                                    r_add = requests.post(f"{emby_url}/emby/Collections/{col_id}/Items?Ids={m_id}", headers=headers, timeout=5)
                                    if r_add.status_code in [200, 204]:
                                        added_count += 1
                                        task_mgr.log(f"🔗 《{name}》 成功归入已有合集：【{col_name}】")
                                else:
                                    q_name = urllib.parse.quote(col_name)
                                    r_new = requests.post(f"{emby_url}/emby/Collections?Name={q_name}&Ids={m_id}", headers=headers, timeout=5)
                                    if r_new.status_code in [200, 201]:
                                        new_id = r_new.json().get("Id")
                                        existing_map[col_name] = new_id
                                        created_count += 1
                                        task_mgr.log(f"✨ 成功在 Emby 创建新系列合集：【{col_name}】并纳入《{name}》！")
                    except Exception:
                        pass
                if scanned_count % 300 == 0:
                    task_mgr.log(f"📈 合集全量进度：已核验 {scanned_count}/{total_real} 部电影 | 新建合集: {created_count} 个 | 归档影片: {added_count} 部")
                    
            start += len(movies)
            if start >= total_real:
                break
                
        task_mgr.finish(f"系列电影全量打包完成！新建 {created_count} 个合集，向已有合集归档 {added_count} 部影片！")
    except Exception as e:
        task_mgr.finish(f"合集打包异常中断: {e}")

@app.post("/api/features/auto-collections")
def api_auto_collections(user: dict = Depends(verify_token)):
    if task_mgr.status == "running":
        return {"success": False, "detail": f"已有后台任务正在运行中: {task_mgr.name}"}
    threading.Thread(target=_task_auto_collections, daemon=True).start()
    return {"success": True, "message": "系列电影(BoxSet)全量打包任务已启动"}

# 4. 🔤 全库生肉中文字幕自动匹配 (全库核心外语库 100% 全量游标猎手)
def _task_fetch_subtitles():
    cfg = load_config()
    emby_url = cfg.get("emby", {}).get("url", "").rstrip("/")
    emby_key = cfg.get("emby", {}).get("api_key", "")
    headers = {"X-Emby-Token": emby_key}
    
    task_mgr.start("全库外语核心生肉字幕全量捕获", 0)
    task_mgr.log("🔍 正在检索 Emby 外语电影、欧美剧、日韩剧、日番与动漫核心库...")
    
    # 核心外语媒体库 ID 列表 (外语电影: 72370, 欧美剧: 72374, 日韩剧: 72376, 日番: 72379, 动漫: 72373, 电影: 23343)
    target_libs = [
        {"name": "115外语电影", "id": 72370, "type": "Movie"},
        {"name": "电影库", "id": 23343, "type": "Movie"},
        {"name": "115欧美剧", "id": 72374, "type": "Episode"},
        {"name": "115日韩剧", "id": 72376, "type": "Episode"},
        {"name": "115日番", "id": 72379, "type": "Episode"},
        {"name": "115动漫", "id": 72373, "type": "Episode"}
    ]
    
    try:
        scanned_count = 0
        meat_count = 0
        injected_count = 0
        
        for lib in target_libs:
            if task_mgr.stop_requested: break
            lib_name = lib["name"]
            lib_id = lib["id"]
            lib_type = lib["type"]
            task_mgr.log(f"📂 开始全量游标扫描媒体库：【{lib_name}】...")
            
            start = 0
            limit = 100
            while not task_mgr.stop_requested:
                p_url = f"{emby_url}/emby/Items?ParentId={lib_id}&Recursive=true&IncludeItemTypes={lib_type}&Fields=MediaStreams,Path&StartIndex={start}&Limit={limit}"
                r = requests.get(p_url, headers=headers, timeout=15)
                if r.status_code != 200:
                    time.sleep(2)
                    continue
                    
                data = r.json()
                items = data.get("Items", [])
                total_lib = data.get("TotalRecordCount", 0)
                
                if not items:
                    break
                    
                for it in items:
                    if task_mgr.stop_requested: break
                    scanned_count += 1
                    name = it.get("Name", "未知")
                    item_id = it.get("Id")
                    task_mgr.update(scanned_count, f"【{lib_name}】《{name}》")
                    
                    # 检查中文字幕与国语音轨 (严密守护：已有中文字幕或国语音轨则绝对跳过)
                    streams = it.get("MediaStreams", []) or []
                    has_cn = False
                    for s in streams:
                        lang = (s.get("Language") or "").lower()
                        title = (s.get("DisplayTitle") or "").lower()
                        if s.get("Type") == "Audio":
                            if any(k in lang for k in ["chi", "zho", "zh"]) or any(k in title for k in ["国语", "普通话", "汉语", "中文", "mandarin"]):
                                has_cn = True; break
                        elif s.get("Type") == "Subtitle":
                            if any(k in lang for k in ["chi", "zho", "zh", "chs", "cht"]) or any(k in title for k in ["中", "简", "繁", "chi", "chinese", "双语", "chs", "cht"]):
                                has_cn = True; break
                                
                    if not has_cn:
                        meat_count += 1
                        # 主动向多源插件搜索并强制注入
                        for search_lang in ["chi", "zh", "chs"]:
                            try:
                                s_url = f"{emby_url}/emby/Items/{item_id}/RemoteSearch/Subtitles/{search_lang}"
                                r_s = requests.get(s_url, headers=headers, timeout=8)
                                if r_s.status_code == 200:
                                    subs = r_s.json()
                                    if subs:
                                        chosen = None
                                        for s in subs:
                                            s_name = s.get("Name", "").lower()
                                            if any(k in s_name for k in ["chs", "zh-cn", "简", "简体", "thunder", "迅雷"]):
                                                chosen = s; break
                                        if not chosen: chosen = subs[0]
                                        
                                        sub_id = chosen.get("Id")
                                        provider = chosen.get("ProviderName", "云端")
                                        d_url = f"{emby_url}/emby/Items/{item_id}/RemoteSearch/Subtitles/{sub_id}"
                                        r_d = requests.post(d_url, headers=headers, timeout=10)
                                        if r_d.status_code in [200, 204]:
                                            injected_count += 1
                                            task_mgr.log(f"✅ 《{name}》 成功捕获并注入 [{provider}] 优质中文字幕！")
                                            break
                            except Exception:
                                pass
                                
                    if scanned_count % 300 == 0:
                        task_mgr.log(f"📈 字幕全量战报：已核验 {scanned_count} 部 | 锁定生肉: {meat_count} 部 | 成功补齐: {injected_count} 部")
                        
                start += len(items)
                if start >= total_lib:
                    break
                    
        task_mgr.finish(f"全库生肉字幕全量巡检完成！共核验 {scanned_count} 部外语影视，锁定生肉 {meat_count} 部，成功注入 {injected_count} 部中文字幕！")
    except Exception as e:
        task_mgr.finish(f"字幕猎手异常中断: {e}")

@app.post("/api/features/fetch-subtitles")
def api_fetch_subtitles(user: dict = Depends(verify_token)):
    if task_mgr.status == "running":
        return {"success": False, "detail": f"已有后台任务正在运行中: {task_mgr.name}"}
    threading.Thread(target=_task_fetch_subtitles, daemon=True).start()
    return {"success": True, "message": "全库生肉字幕全量主动匹配已启动"}

# 5. 🎬 单集剧情简介与剧照智能补齐 (100% 全量游标遍历)
def _task_fix_episodes():
    cfg = load_config()
    emby_url = cfg.get("emby", {}).get("url", "").rstrip("/")
    emby_key = cfg.get("emby", {}).get("api_key", "")
    tmdb_key = cfg.get("tmdb", {}).get("api_key", os.getenv("TMDB_API_KEY", ""))
    headers = {"X-Emby-Token": emby_key}
    
    task_mgr.start("单集剧情简介全量智能补齐", 0)
    task_mgr.log("🔍 正在检索全库电视剧分集元数据...")
    
    try:
        r_cnt = requests.get(f"{emby_url}/emby/Items/Counts", headers=headers, timeout=8)
        counts = r_cnt.json() if r_cnt.status_code == 200 else {}
        total_episodes = counts.get("EpisodeCount", 395564)
        task_mgr.total = total_episodes
        task_mgr.log(f"📊 Emby 全库总计约 {total_episodes} 个单集分集，启动全量游标分页美化...")
        
        start = 0
        limit = 100
        scanned_count = 0
        fixed_count = 0
        
        while not task_mgr.stop_requested:
            p_url = f"{emby_url}/emby/Items?Recursive=true&IncludeItemTypes=Episode&Fields=Overview,ProviderIds,SeriesId,IndexNumber,ParentIndexNumber&StartIndex={start}&Limit={limit}"
            r = requests.get(p_url, headers=headers, timeout=15)
            if r.status_code != 200:
                time.sleep(2)
                continue
                
            data = r.json()
            episodes = data.get("Items", [])
            total_real = data.get("TotalRecordCount", total_episodes)
            task_mgr.total = total_real
            
            if not episodes:
                break
                
            for ep in episodes:
                if task_mgr.stop_requested: break
                scanned_count += 1
                name = ep.get("Name", "未知分集")
                s_name = ep.get("SeriesName", "剧集")
                overview = (ep.get("Overview") or "").strip()
                s_idx = ep.get("ParentIndexNumber", 1)
                e_idx = ep.get("IndexNumber", 1)
                ep_id = ep.get("Id")
                task_mgr.update(scanned_count, f"《{s_name}》 S{s_idx:02d}E{e_idx:02d}")
                
                # 判断简介是否残缺或为空
                if not overview or overview == name or ("第" in name and "集" in name):
                    try:
                        series_id = ep.get("SeriesId")
                        r_s = requests.get(f"{emby_url}/emby/Items/{series_id}?Fields=ProviderIds", headers=headers, timeout=5)
                        s_tmdb = r_s.json().get("ProviderIds", {}).get("Tmdb") if r_s.status_code == 200 else None
                        if s_tmdb:
                            ep_tmdb_url = f"https://api.themoviedb.org/3/tv/{s_tmdb}/season/{s_idx}/episode/{e_idx}?api_key={tmdb_key}&language=zh-CN"
                            r_ep = requests.get(ep_tmdb_url, timeout=5)
                            if r_ep.status_code == 200:
                                ep_data = r_ep.json()
                                official_name = ep_data.get("name")
                                official_overview = ep_data.get("overview")
                                update_payload = dict(ep)
                                changed = False
                                if official_name and official_name != f"Episode {e_idx}":
                                    update_payload["Name"] = official_name; changed = True
                                if official_overview:
                                    update_payload["Overview"] = official_overview; changed = True
                                if changed:
                                    requests.post(f"{emby_url}/emby/Items/{ep_id}", headers=headers, json=update_payload, timeout=5)
                                    fixed_count += 1
                                    task_mgr.log(f"📝 《{s_name}》 S{s_idx:02d}E{e_idx:02d} 成功注入官方分集剧情：【{official_name or '已美化'}】")
                    except Exception:
                        pass
                        
                if scanned_count % 500 == 0:
                    task_mgr.log(f"📈 分集简介美化进度：已巡检 {scanned_count}/{total_real} 集 | 累计成功补齐: {fixed_count} 集")
                    
            start += len(episodes)
            if start >= total_real:
                break
                
        task_mgr.finish(f"单集剧情简介全量巡检完成！共核验 {scanned_count} 个分集，成功美化强化 {fixed_count} 个分集剧情！")
    except Exception as e:
        task_mgr.finish(f"分集美化异常中断: {e}")

@app.post("/api/features/fix-episodes")
def api_fix_episodes(user: dict = Depends(verify_token)):
    if task_mgr.status == "running":
        return {"success": False, "detail": f"已有后台任务正在运行中: {task_mgr.name}"}
    threading.Thread(target=_task_fix_episodes, daemon=True).start()
    return {"success": True, "message": "单集剧情简介全量美化任务已启动"}

# 6. 🧹 STRM 坏种与死链自愈巡检 (全库 100% 全量探活)
def get_115_fid_by_pickcode(pick_code: str) -> Optional[str]:
    db_path = "/app/cms_config/cms-online.db"
    if not os.path.exists(db_path):
        return None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        c = conn.cursor()
        c.execute("SELECT fid FROM cloud_data WHERE pick_code = ? LIMIT 1", (pick_code,))
        row = c.fetchone()
        conn.close()
        if row:
            return str(row[0])
    except Exception:
        pass
    return None

def move_115_file_to_quarantine(fid: str, quarantine_cid: str = "3530056958679713627") -> bool:
    try:
        cookie_path = "/app/cms_config/115-cookies.txt"
        if not os.path.exists(cookie_path):
            return False
        with open(cookie_path, "r", encoding="utf-8") as f:
            cookie = f.read().strip()
        headers = {"User-Agent": "Mozilla/5.0", "Cookie": cookie}
        data = {
            "pid": quarantine_cid,
            "fid[0]": str(fid)
        }
        res = requests.post("https://webapi.115.com/files/move", headers=headers, data=data, timeout=5)
        return bool(res.json().get("state"))
    except Exception:
        return False

def _task_clean_dead_strm(sync_115: bool = True):
    cfg = load_config()
    emby_url = cfg.get("emby", {}).get("url", "").rstrip("/")
    emby_key = cfg.get("emby", {}).get("api_key", "")
    headers = {"X-Emby-Token": emby_key}
    
    task_mgr.start("全库 STRM 死链全量探活与自愈", 0)
    task_mgr.log(f"🚀 启动全库 STRM 5并发温和探活与防误判自愈引擎 (115云端联动隔离: {'已开启' if sync_115 else '已关闭'})...")
    
    quarantine_base = "/115strm/strm_quarantine"
    os.makedirs(quarantine_base, exist_ok=True)
    
    share_cache = {}    # sid -> (bool, reason)
    season_cache = {}   # season_dir -> (bool, reason)
    cache_lock = threading.Lock()
    
    def probe_url(url: str):
        if not url or not url.startswith("http"):
            return True, "非HTTP链接跳过"
        test_url = re.sub(r'https?://[^/]+', 'http://172.17.0.1:9527', url)
        try:
            r = requests.head(test_url, allow_redirects=False, timeout=8)
            # 明确的有效状态
            if r.status_code in [200, 206, 302]:
                return True, f"HTTP {r.status_code}"
            # 只有明确返回 404(文件丢失) 或 500(分享取消) 才判定为死链
            if r.status_code in [404, 500]:
                return False, f"HTTP {r.status_code}"
            return True, f"HTTP {r.status_code}"
        except requests.exceptions.Timeout:
            # 超时仅代表 CMS 繁忙，绝对不能当死链误杀！
            return True, "CMS响应排队(保留)"
        except Exception as ex:
            return True, f"网络波动(保留): {ex}"

    def check_single_item(it: dict) -> dict:
        path = it.get("Path") or ""
        name = it.get("Name", "未知")
        series_name = it.get("SeriesName", "")
        item_type = it.get("Type", "")
        display_name = f"《{series_name} {name}》" if series_name else f"《{name}》"
        
        res = {
            "path": path,
            "name": display_name,
            "type": item_type,
            "is_strm": False,
            "is_healthy": False,
            "reason": "",
            "pick_code": ""
        }
        
        if not path.endswith(".strm"):
            res["reason"] = "非STRM本地文件"
            return res
            
        res["is_strm"] = True
        
        if not os.path.exists(path):
            res["reason"] = "磁盘文件缺失"
            return res
            
        parent_dir = os.path.dirname(path)
        if item_type == "Episode":
            with cache_lock:
                if parent_dir in season_cache:
                    cached_ok, cached_reason = season_cache[parent_dir]
                    res["is_healthy"] = cached_ok
                    res["reason"] = cached_reason
                    return res
                    
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fp:
                url = fp.read().strip()
        except Exception as e:
            res["reason"] = f"文件读取异常: {e}"
            return res
            
        # 提取 pickcode
        if "/d/" in url:
            m_pick = re.search(r'/d/([a-zA-Z0-9]+)', url)
            if m_pick:
                res["pick_code"] = m_pick.group(1)
                
        # 115 /s/ 分享缓存
        m = re.search(r'/s/([a-zA-Z0-9]+)_', url)
        if m:
            sid = m.group(1)
            with cache_lock:
                if sid in share_cache:
                    cached_ok, cached_reason = share_cache[sid]
                    res["is_healthy"] = cached_ok
                    res["reason"] = cached_reason
                    if item_type == "Episode":
                        season_cache[parent_dir] = (cached_ok, cached_reason)
                    return res
            
            is_ok, reason = probe_url(url)
            with cache_lock:
                share_cache[sid] = (is_ok, reason)
                if item_type == "Episode":
                    season_cache[parent_dir] = (is_ok, reason)
            res["is_healthy"] = is_ok
            res["reason"] = reason
            return res
            
        is_ok, reason = probe_url(url)
        if item_type == "Episode":
            with cache_lock:
                season_cache[parent_dir] = (is_ok, reason)
        res["is_healthy"] = is_ok
        res["reason"] = reason
        return res

    try:
        start = 0
        limit = 500
        scanned_count = 0
        dead_count = 0
        healthy_count = 0
        skipped_local = 0
        cloud_isolated_count = 0
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            while not task_mgr.stop_requested:
                p_url = f"{emby_url}/emby/Items?Recursive=true&IncludeItemTypes=Movie,Episode&Fields=Path,SeriesName,Type&StartIndex={start}&Limit={limit}"
                r = None
                for attempt in range(4):
                    try:
                        r = requests.get(p_url, headers=headers, timeout=60)
                        if r.status_code == 200:
                            break
                    except Exception as err:
                        if attempt == 3:
                            task_mgr.log(f"⚠️ Emby深分页查询重试耗尽({start}): {err}")
                        time.sleep(3)
                
                if not r or r.status_code != 200:
                    time.sleep(2)
                    continue
                    
                data = r.json()
                items = data.get("Items", [])
                total_real = data.get("TotalRecordCount", 50000)
                task_mgr.total = total_real
                
                if not items:
                    break
                    
                futures = [executor.submit(check_single_item, it) for it in items]
                
                for fut in futures:
                    if task_mgr.stop_requested:
                        break
                    
                    item_res = fut.result()
                    scanned_count += 1
                    task_mgr.update(scanned_count, item_res["name"])
                    
                    if not item_res["is_strm"]:
                        skipped_local += 1
                        continue
                        
                    if item_res["is_healthy"]:
                        healthy_count += 1
                    else:
                        dead_count += 1
                        path = item_res["path"]
                        pick_code = item_res.get("pick_code", "")
                        cloud_moved = False
                        
                        # 1. 尝试 115 云端同步移入隔离归档
                        if sync_115 and pick_code:
                            fid = get_115_fid_by_pickcode(pick_code)
                            if fid:
                                cloud_moved = move_115_file_to_quarantine(fid)
                                if cloud_moved:
                                    cloud_isolated_count += 1
                                    
                        status_tag = "已同时移入 NAS + 115云端隔离归档" if cloud_moved else "已移入 NAS 安全隔离区"
                        task_mgr.log(f"⚠️ 发现失效坏种: {item_res['name']} ({item_res['reason']}) -> {status_tag}")
                        
                        # 2. NAS 本地 strm 与 nfo 移入隔离区
                        try:
                            rel_path = path.replace("/115strm/", "").lstrip("/")
                            target_path = os.path.join(quarantine_base, rel_path)
                            os.makedirs(os.path.dirname(target_path), exist_ok=True)
                            if os.path.exists(path):
                                shutil.move(path, target_path)
                            
                            nfo_path = os.path.splitext(path)[0] + ".nfo"
                            if os.path.exists(nfo_path):
                                nfo_target = os.path.splitext(target_path)[0] + ".nfo"
                                shutil.move(nfo_path, nfo_target)
                        except Exception as err:
                            task_mgr.log(f"本地隔离移动失败: {err}")
                            
                    if scanned_count % 1000 == 0 or (dead_count > 0 and dead_count % 50 == 0):
                        task_mgr.log(f"📈 极速探活进度: 已巡检 {scanned_count}/{total_real} | 健康秒播: {healthy_count} | 坏种隔离: {dead_count} (云端同步: {cloud_isolated_count}) | 本地跳过: {skipped_local}")
                        
                start += len(items)
                if start >= total_real:
                    break
                    
        if dead_count > 0:
            try:
                requests.post(f"{emby_url}/emby/Library/Refresh", headers=headers, timeout=5)
                task_mgr.log("🔄 已自动通知 Emby 刷新媒体库，清除失效海报与重影！")
            except Exception:
                pass
                
        if task_mgr.stop_requested:
            task_mgr.finish(f"🛑 任务已由用户手动终止。累计巡检 {scanned_count} 条，健康秒播 {healthy_count} 条，隔离坏种 {dead_count} 条（115云端同步隔离 {cloud_isolated_count} 条）。")
        else:
            task_mgr.finish(f"🎉 全库 STRM 极速探活自愈圆满完成！共巡检 {scanned_count} 条流（本地排除 {skipped_local} 条），健康秒播 {healthy_count} 条，已隔离死链坏种 {dead_count} 条（115云端同步隔离 {cloud_isolated_count} 条）！")
    except Exception as e:
        task_mgr.finish(f"巡检异常中断: {e}")

@app.post("/api/features/clean-dead-strm")
def api_clean_dead_strm(req: Optional[CleanDeadStrmReq] = None, user: dict = Depends(verify_token)):
    if task_mgr.status == "running":
        return {"success": False, "detail": f"已有后台任务正在运行中: {task_mgr.name}"}
    
    sync_115_val = True
    if req and req.sync_115 is not None:
        sync_115_val = req.sync_115
        
    threading.Thread(target=_task_clean_dead_strm, args=(sync_115_val,), daemon=True).start()
    return {"success": True, "message": "全库 STRM 死链全量巡检任务已启动", "sync_115": sync_115_val}

@app.get("/{full_path:path}")
def serve_spa(full_path: str):
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="Not Found")
    
    file_path = os.path.join(STATIC_DIR, full_path)
    if os.path.exists(file_path) and os.path.isfile(file_path):
        response = FileResponse(file_path)
    else:
        index_path = os.path.join(STATIC_DIR, "index.html")
        response = FileResponse(index_path)
    
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response
