# 🎬 MediaHub Pro

> **开箱即用型全自动化家庭影院中枢系统**  
> 一站式打通 **PanSou 智能搜片 ➔ CMS 网盘秒级转存 ➔ Emby 资产智能美化 ➔ STRM 坏种死链双端自愈** 工业级完整全链路闭环！

---

## 🌟 核心特性与架构矩阵

### 1. 🔍 智能全网搜片大厅
* 整合 PanSou 与多源检索，直出纯净 115 官方网盘分享链接；
* 原生自带 115 官方 Snap 提取码穿透验证，自动标记违规失效链接与提取码错误，秒级避坑。

### 2. ⚡ CMS 115 极速转存与实时看板
* 直连 Cloud-Media-Sync (CMS)，一键下发 115 离线转存与 STRM 自动生成任务；
* 实时轮询转存状态看板，失败报警并提供一键换源。

### 3. 📊 影院总览与缺失海报补齐矩阵
* 实时统计 Emby 电影/电视剧资产总数与全库海报覆盖率；
* **缺失海报全景清单**：精准定位未刮削生肉条目，支持按电影/电视剧筛选与片名即时搜索；
* **单部/批量一键自动补齐**：智能清洗长标题后缀，精准命中 TMDB 官方高清海报与背景图并无缝注入 Emby；
* **全规格分页**：支持 50 / 100 / 200 / 500 / 全量连续翻页与序号连续计算。

### 4. 🎨 美化工厂 (Cinematic Beautifier)
* **全库海报自动补齐**：一键修复生肉条目与缺失封面；
* **4K 杜比视界高品角标**：探测 4K UHD、HDR10 与 Dolby Vision 并打上尊贵认证标；
* **系列电影(BoxSet)自动打包**：漫威、哈利波特、指环王等大 IP 自动打包成精美合集；
* **中文字幕自动匹配**：精准匹配中文字幕插件并调度补齐；
* **单集剧情与剧照补齐**：补充分集概述，拒绝空白截图；
* **STRM 坏种与死链自愈巡检**：
  * 高性能多线程并发探活，识别 HTTP 404 与已失效外部分享；
  * **非破坏性双端隔离安全机制**：自动将坏种及伴生 NFO 软移入 NAS 安全隔离区，并联动 115 云端将源文件安全移入「115cms_重复隔离归档」，零物理抹除，保留完整反悔撤销期！

---

## 🚀 极速部署指南

### 方式一：Docker Compose（强烈推荐）

创建 `docker-compose.yml`：

```yaml
services:
  mediahub-pro:
    image: ghcr.io/zp21123465/mediahub-pro:latest
    container_name: mediahub-pro
    restart: unless-stopped
    ports:
      - "18888:18888"
    volumes:
      # 持久化存储数据 (系统配置、任务日志等)
      - ./data:/app/data
      # 挂载您的 STRM 媒体目录 (用于本地坏种探活与自愈，根据实际路径修改)
      - /volume1/影视strm/115strm:/115strm
      # 挂载 CMS 的配置目录 (只读，用于直读 cms-online.db 映射 115 云端文件)
      - /volume1/docker/cms/config:/app/cms_config:ro
    environment:
      - TZ=Asia/Shanghai
```

启动容器：
```bash
docker compose up -d
```

### 方式二：Docker CLI 单行运行

```bash
docker run -d \
  --name mediahub-pro \
  --restart unless-stopped \
  -p 18888:18888 \
  -v $(pwd)/data:/app/data \
  -v /volume1/影视strm/115strm:/115strm \
  -v /volume1/docker/cms/config:/app/cms_config:ro \
  -e TZ=Asia/Shanghai \
  ghcr.io/zp21123465/mediahub-pro:latest
```

---

## 🛠️ 首次启动与配置流程

1. 浏览器访问：`http://<您的NAS或服务器IP>:18888`；
2. **首次登录**：系统检测到未初始化时，会引导您设定自己的 **管理员用户名与密码**（严格哈希加密保存，杜绝明文暴露）；
3. **服务互联配置**：进入顶部【系统设置】，根据您的网络填入对应的容器端口与密钥：
   * **Emby 服务器**：如 `http://192.168.1.100:8096` 及 Emby API Key
   * **CMS (Cloud-Media-Sync)**：如 `http://192.168.1.100:9527`
   * **PanSou-Web**：如 `http://192.168.1.100:18933`
   * **Media Saber (可选)**：如 `http://192.168.1.100:18512`
   * **TMDB API Key**：您的 TMDB 开发者密钥（用于高清海报匹配，留空支持自动公共引擎）
4. 点击【保存设置并连通测试】，绿灯亮起即可开启全自动影院中枢体验！

---

## 🛡️ 安全规范与免责声明

* **纯净零追踪**：本项目不收集、不出境任何用户数据与媒体元数据；
* **非破坏性保障**：死链自愈采用隔离区机制，绝不直接物理抹除任何云端或本地媒体文件；
* 本项目仅用于个人合法媒体库管理与学习交流，请支持正版影视内容。

---

## 📄 开源许可证

本项目遵循 [MIT License](LICENSE) 开源协议。
