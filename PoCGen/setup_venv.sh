#!/usr/bin/env bash
# 用途：在 PoCGen 根目录创建并初始化虚拟环境，安装全部依赖。
# 使用方法：
#   1) chmod +x ./setup_venv.sh
#   2) ./setup_venv.sh
# 可选：指定 Python 解释器路径（默认 python3）：
#   PYTHON_BIN=/usr/bin/python3 ./setup_venv.sh
# 可选：安装后测试运行：
#   PYTHONNOUSERSITE=1 ./PoCGen/.venv/bin/python -m PoCGen.cli --help

set -euo pipefail

POCGEN_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$POCGEN_ROOT/.venv"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "未找到 Python 解释器: $PYTHON_BIN" >&2
  exit 1
fi

if [ -d "$VENV_DIR" ]; then
  echo "已存在虚拟环境：$VENV_DIR"
else
  "$PYTHON_BIN" -m venv "$VENV_DIR"
  echo "已创建虚拟环境：$VENV_DIR"
fi

"$VENV_DIR/bin/python" -m pip install --upgrade pip
"$VENV_DIR/bin/python" -m pip install -r "$POCGEN_ROOT/requirements.txt"

# 运行时所需的额外依赖（补齐 PoCGen 实际使用的模块）
"$VENV_DIR/bin/python" -m pip install "numpy<1.25" "scipy<1.11" langchain_classic websocket-client

echo "完成。建议使用："
echo "  PYTHONNOUSERSITE=1 $VENV_DIR/bin/python -m PoCGen.cli ..."
