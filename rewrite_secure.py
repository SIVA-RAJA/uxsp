import re
from pathlib import Path

content = Path('uxsp/secure.py').read_text()

# Add Generator to imports if missing
if 'from typing import ' in content and 'Generator' not in content[:1000]:
    content = content.replace('from typing import Any', 'from typing import Any, Generator')

funcs_to_patch = ['SendVideo', 'SendAudio', 'SendPhoto', 'SendDocument', 'SendPDF', 'SendFile', 'SendArchive', 'SendVoice']

for func in funcs_to_patch:
    # Patch return type annotation
    pattern_sig = re.compile(r'def ' + func + r'\((.*?)\) -> SecurePackage:', re.DOTALL)
    content = pattern_sig.sub(r'def ' + func + r'(\1) -> SecurePackage | Generator[SecurePackage, None, None]:', content)
    
    # We need to insert the size check inside the `if isinstance(..., (str, Path)):` block
    # Example block:
    #     if isinstance(video_path_or_bytes, (str, Path)):
    #         if not _safe_is_file(video_path_or_bytes):
    #             raise SecureSendError(f"File not found: {video_path_or_bytes}")
    #         p = Path(video_path_or_bytes)
    
    var_name = re.search(r'def ' + func + r'\([^)]*?\n    ([a-zA-Z0-9_]+_path_or_bytes)', content, re.DOTALL)
    if var_name:
        var = var_name.group(1)
        search_block = f"""    if isinstance({var}, (str, Path)):
        if not _safe_is_file({var}):
            raise SecureSendError(f"File not found: {{{var}}}")
        p = Path({var})"""
        
        data_type = func.replace('Send', '').lower()
        if data_type == 'document': data_type = 'document'
        if data_type == 'archive': data_type = 'archive'
        
        replace_block = search_block + f"""
        if p.stat().st_size > 64 * 1024 * 1024:
            return SendStream(
                receiver_id=receiver_id,
                file_path=p,
                receiver=receiver,
                sender=sender,
                sender_identity=sender_identity,
                data_type="{data_type}",
                metadata=metadata,
            )"""
            
        content = content.replace(search_block, replace_block)

Path('uxsp/secure.py').write_text(content)
