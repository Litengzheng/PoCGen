from __future__ import annotations
import re
from pathlib import Path
from typing import List, Optional
import os


def split_messages(raw: str) -> List[str]:
    """Split raw output into separate messages."""
    if not raw.strip():
        return []
    messages = [msg.strip() for msg in raw.strip().split("\n---\n")]
    return [msg for msg in messages if msg]


def save_messages(messages: List[str], output_dir: str) -> List[str]:
    """Save HTTP request messages to files."""
    saved_paths = []
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    for idx, content in enumerate(messages, start=1):
        filename = f"poc_request_{idx}.txt"
        filepath = output_path / filename
        
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            saved_paths.append(str(filepath))
        except Exception as e:
            print(f"Error saving file {filename}: {e}")
    
    return saved_paths


# def save_python_code(code_content: str, output_dir: str, attempt_index: int) -> List[str]:
#     """保存Python代码到文件"""
#     import re
    
#     # 确保output_dir是Path对象
#     if isinstance(output_dir, str):
#         output_dir = Path(output_dir)
    
#     # 确保目录存在
#     output_dir.mkdir(parents=True, exist_ok=True)
    
#     # 清理代码内容，提取Python代码块
#     python_blocks = []
    
#     # 尝试匹配 ```python ... ``` 代码块
#     python_pattern = r'```(?:python)?\s*(.*?)\s*```'
#     matches = re.findall(python_pattern, code_content, re.DOTALL | re.IGNORECASE)
    
#     if matches:
#         python_blocks = matches
#     else:
#         # 如果没有代码块标记，检查内容是否像Python代码
#         if ("import " in code_content or "def " in code_content or 
#             "class " in code_content or "requests." in code_content):
#             # 移除可能的前导标记
#             clean_content = re.sub(r'^```(?:python)?\s*', '', code_content, flags=re.IGNORECASE)
#             clean_content = re.sub(r'\s*```$', '', clean_content, flags=re.IGNORECASE)
#             python_blocks = [clean_content]
    
#     if not python_blocks:
#         # 如果还没有找到，尝试整个内容
#         python_blocks = [code_content]
    
#     saved_paths = []
#     for i, block in enumerate(python_blocks, 1):
#         # 清理代码块
#         block = block.strip()
        
#         # 移除可能的前导/尾随的```标记
#         block = re.sub(r'^```(?:python)?\s*', '', block, flags=re.IGNORECASE)
#         block = re.sub(r'\s*```$', '', block, flags=re.IGNORECASE)
        
#         if not block.strip():
#             continue
            
#         # 生成文件名
#         filename = f"stack_overflow_poc_attempt{attempt_index+1}_{i}.py"
#         filepath = output_dir / filename  # 现在output_dir是Path对象
        
#         try:
#             with open(filepath, "w", encoding="utf-8", errors="ignore") as f:
#                 f.write(block)
#             saved_paths.append(str(filepath))
#             print(f"保存Python脚本: {filepath}")
#         except Exception as e:
#             print(f"保存Python文件时出错 {filename}: {e}")
    
#     return saved_paths


def save_python_code(code_content: str, output_dir: str, timestamp: str, attempt_index: int) -> List[str]:
    """保存Python代码到文件，使用时间戳命名"""
    import re
    
    # 确保output_dir是Path对象
    if isinstance(output_dir, str):
        output_dir = Path(output_dir)
    
    # 确保目录存在
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 清理代码内容，提取Python代码块
    python_blocks = []
    
    # 尝试匹配 ```python ... ``` 代码块
    python_pattern = r'```(?:python)?\s*(.*?)\s*```'
    matches = re.findall(python_pattern, code_content, re.DOTALL | re.IGNORECASE)
    
    if matches:
        python_blocks = matches
    else:
        # 如果没有代码块标记，检查内容是否像Python代码
        if ("import " in code_content or "def " in code_content or 
            "class " in code_content or "requests." in code_content):
            # 移除可能的前导标记
            clean_content = re.sub(r'^```(?:python)?\s*', '', code_content, flags=re.IGNORECASE)
            clean_content = re.sub(r'\s*```$', '', clean_content, flags=re.IGNORECASE)
            python_blocks = [clean_content]
    
    if not python_blocks:
        # 如果还没有找到，尝试整个内容
        python_blocks = [code_content]
    
    saved_paths = []
    for i, block in enumerate(python_blocks, 1):
        # 清理代码块
        block = block.strip()
        
        # 移除可能的前导/尾随的```标记
        block = re.sub(r'^```(?:python)?\s*', '', block, flags=re.IGNORECASE)
        block = re.sub(r'\s*```$', '', block, flags=re.IGNORECASE)
        
        if not block.strip():
            continue
            
        # 生成文件名，使用时间戳和尝试序号
        # 格式: stack_overflow_poc_YYYYMMDD_HHMMSS_NN.py
        attempt_num = attempt_index + 1
        filename = f"stack_overflow_poc_{timestamp}_{attempt_num:02d}.py"
        filepath = output_dir / filename
        
        try:
            with open(filepath, "w", encoding="utf-8", errors="ignore") as f:
                f.write(block)
            saved_paths.append(str(filepath))
            print(f"保存Python脚本: {filepath}")
        except Exception as e:
            print(f"保存Python文件时出错 {filename}: {e}")
    
    return saved_paths



def extract_python_from_response(response: str) -> List[str]:
    """从大模型响应中提取Python代码块"""
    python_blocks = []
    
    # 模式1: 带```python标记的代码块
    pattern1 = r'```(?:python)?\s*(.*?)\s*```'
    matches1 = re.findall(pattern1, response, re.DOTALL | re.IGNORECASE)
    
    if matches1:
        for match in matches1:
            if "import " in match or "def " in match or "requests" in match:
                python_blocks.append(match)
    
    # 模式2: 不带标记但看起来像Python代码的块
    if not python_blocks:
        lines = response.split('\n')
        in_code_block = False
        current_block = []
        
        for line in lines:
            if line.strip().startswith('import ') or 'requests.' in line or 'def ' in line:
                in_code_block = True
                current_block.append(line)
            elif in_code_block and (line.strip() == '' or line.strip().startswith(' ') or line.strip().startswith('\t')):
                current_block.append(line)
            elif in_code_block and current_block:
                python_blocks.append('\n'.join(current_block))
                current_block = []
                in_code_block = False
        
        if current_block:
            python_blocks.append('\n'.join(current_block))
    
    return python_blocks


def parse_http_request(raw: str) -> Optional[dict]:
    """Parse raw HTTP request text into structured data."""
    if not raw or not raw.strip():
        return None
    
    lines = raw.strip().splitlines()
    if not lines:
        return None
    
    # Parse request line
    request_line = lines[0]
    parts = request_line.split()
    if len(parts) < 3:
        return None
    
    method, path, version = parts[0], parts[1], parts[2]
    
    # Parse headers
    headers = {}
    body_lines = []
    in_body = False
    
    for line in lines[1:]:
        if not in_body:
            if not line.strip():  # Empty line indicates end of headers
                in_body = True
            elif ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        else:
            body_lines.append(line)
    
    body = '\n'.join(body_lines) if body_lines else ''
    
    return {
        'method': method,
        'path': path,
        'version': version,
        'headers': headers,
        'body': body
    }