import re
from pathlib import Path

content = Path('uxsp/contrib/django.py').read_text()

# 1. Add max_response_size to init
init_search = r"""    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response"""
init_replace = r"""    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response
        self.max_response_size: int = getattr(settings, "UXSP_MAX_RESPONSE_SIZE", 16 * 1024 * 1024)"""
content = content.replace(init_search, init_replace)

# 2. Add StreamingHttpResponse handling
streaming_search = r"""        if should_encrypt and sender_card is not None:
            content = response.content"""
streaming_replace = r"""        if should_encrypt and sender_card is not None:
            from django.http import StreamingHttpResponse
            if getattr(response, "streaming", False):
                def encrypt_stream():
                    for chunk in response.streaming_content:
                        if not chunk: continue
                        out_pkg = Send(
                            receiver=sender_card,
                            item=chunk,
                            sender=server_identity,
                            data_type="binary"
                        )
                        yield out_pkg.to_json().encode("utf-8") + b"\n"
                
                encrypted_response = StreamingHttpResponse(
                    encrypt_stream(),
                    status=response.status_code,
                    content_type="application/x-ndjson"
                )
                for k, v in response.items():
                    if k.lower() not in ("content-length", "content-type"):
                        encrypted_response[k] = v
                encrypted_response["X-UXSP-Package"] = "1"
                encrypted_response["X-UXSP-Sender"] = server_identity.entity_id
                encrypted_response["X-UXSP-Recipient"] = getattr(request, "uxsp_sender_id", "") or ""
                return encrypted_response

            content = response.content
            if len(content) > self.max_response_size:
                raise ValueError(f"Response exceeds max_response_size of {self.max_response_size} bytes. Use StreamingHttpResponse.")"""
content = content.replace(streaming_search, streaming_replace)

# 3. Add decorator check
protect_search = r"""        def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
            request.uxsp_force_encrypt = True
            return view_func(request, *args, **kwargs)"""
protect_replace = r"""        def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
            if not hasattr(request, "uxsp_encrypted"):
                raise RuntimeError("@protect_view decorator requires UXSPDjangoMiddleware to be installed.")
            request.uxsp_force_encrypt = True
            return view_func(request, *args, **kwargs)"""
content = content.replace(protect_search, protect_replace)

Path('uxsp/contrib/django.py').write_text(content)
