# Clash Config Generator (Personal Maintenance Guide)

这是为 `10000ge10000/clash-config-gen` 项目生成的维护指南。本项目已修改为**纯离线/单机版本**，移除了所有数据库依赖。

## 📂 项目结构

- `src/web_app.py`: 主程序 (Streamlit UI)
- `src/clash_meta_gen.py`: 核心配置生成逻辑
- `src/api.py`: 仅用于健康检查的 API 存根
- `.github/workflows/docker-publish.yml`: GitHub Actions 自动构建脚本

## 🚀 快速启动 (本地开发)

确保已安装 Python 3.11+。

```bash
# 1. 激活虚拟环境
.\.venv\Scripts\Activate.ps1

# 2. 运行应用
streamlit run src\web_app.py
```

## 🐳 Docker 部署说明

本项目已配置 GitHub Actions 自动构建，推荐使用 Docker Compose 部署。

### 1. 准备 docker-compose.yml

在服务器创建 `docker-compose.yml` 文件：

```yaml
services:
  clash-gen:
    image: ghcr.io/10000ge10000/clash-config-gen:main
    container_name: clash-gen
    restart: always
    ports:
      - "8501:8501" # Web UI 面板
      - "8000:8000" # 订阅链接 API
    volumes:
      - ./ruleset:/app/ruleset # 自定义规则集目录 (确保本地目录存在)
```

### 2. 启动服务

```bash
# 登录 GitHub Container Registry (如果镜像是私有的)
# echo $CR_PAT | docker login ghcr.io -u 10000ge10000 --password-stdin

# 启动容器
docker-compose up -d
```

> **提示**: 镜像由 GitHub Actions 自动构建，地址为: `ghcr.io/10000ge10000/clash-config-gen:main`

## ⬆️ 如何上传/更新代码

在 VS Code 终端中执行以下命令：

```powershell
# 1. 添加全部修改
git add .

# 2. 提交修改 (修改引号内的说明)
git commit -m "更新说明"

# 3. 推送到 GitHub
# (第一次需要运行: git push -u origin main)
git push
```

## 🛠️ 维护备忘

- **修改配置生成逻辑**: 编辑 `src/clash_meta_gen.py`.
- **修改界面**: 编辑 `src/web_app.py`.
- **依赖管理**: 如果安装了新库，记得运行 `pip freeze > src/requirements.txt` 更新列表（或者手动编辑 `src/requirements.txt`）。
