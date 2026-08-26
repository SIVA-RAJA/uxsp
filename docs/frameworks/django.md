# Protecting Django Applications (`uxsp.contrib.django`)

The `uxsp.contrib.django` module enables 1-line post-quantum encryption for Django views and API backends.

---

## 1. Installation

Install UXSP with Django support:
```bash
pip install uxsp[django]
```

---

## 2. Using `UXSPDjangoMiddleware`

Add `UXSPDjangoMiddleware` to your `MIDDLEWARE` setting in `settings.py`:

```python
# settings.py
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'uxsp.contrib.django.UXSPDjangoMiddleware', # Add UXSP Middleware
    'django.middleware.common.CommonMiddleware',
    # ...
]

# Set your Django server identity in settings or via uxsp.secure.set_identity()
UXSP_IDENTITY = "server_secret_key_or_identity"
UXSP_REQUIRE_ENCRYPTION = True
```

In your views (`views.py`):

```python
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def secure_view(request):
    # Retrieve decrypted payload attached to request.uxsp_payload
    payload = getattr(request, 'uxsp_payload', None)
    sender_id = getattr(request, 'uxsp_sender_id', None)
    
    return JsonResponse({
        "status": "ok",
        "received": payload,
        "sender": sender_id
    })
```

---

## 3. Protecting Views with `@protect_django` Decorator

Decorate specific Django views for explicit protection:

```python
from django.http import JsonResponse
import uxsp
from uxsp.contrib.django import protect_django

server_identity = uxsp.create_identity("Django Server", role="SERVER")

@protect_django(server_identity=server_identity)
def my_protected_view(request):
    payload = request.uxsp_payload
    return JsonResponse({"message": "Decrypted payload received", "payload": payload})
```
