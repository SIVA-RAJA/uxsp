# Django Middleware & Protection Guide

UXSP provides a 1-line middleware for Django that automatically handles request decryption and response encryption. It seamlessly integrates with Django's request lifecycle.

---

## 1. Setting up the Middleware

To use UXSP in Django, you do **not** need to add it to `INSTALLED_APPS`. You only need to add the Middleware to your `settings.py`.

### Middleware Ordering (CRITICAL)

The order of `MIDDLEWARE` in Django is very important. 
You must place `UXSPDjangoMiddleware` **AFTER** the standard Security/Session middlewares, but **BEFORE** the CSRF middleware.

Why? Because UXSP inherently replaces the need for CSRF! By placing it before `CsrfViewMiddleware`, UXSP can decrypt the request and verify the cryptographic signature (which acts as the ultimate CSRF protection) before Django's CSRF checker gets angry about missing tokens.

```python
# settings.py

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    
    # PUT UXSP HERE!
    'uxsp.contrib.django.UXSPDjangoMiddleware',
    
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
```

### Configuration Options
You can configure the middleware in `settings.py`:
```python
# Force every single request to be encrypted? (Default: False)
UXSP_REQUIRE_ENCRYPTION = False 

# Exclude certain paths from decryption attempts (like Django Admin)
UXSP_EXCLUDE_PATHS = ["/admin/", "/static/"]
```

---

## 2. What happens if I only use the Middleware?

If you only install the middleware and don't use any decorators, here is what happens:
1. **If a user sends an ENCRYPTED request**: The middleware automatically decrypts it. Your Django view will receive the decrypted data in `request.uxsp_payload`.
2. **If a user sends a PLAIN TEXT request**: The middleware ignores it and lets it pass through normally.
3. **Outbound Responses**: The middleware will *only* encrypt the response if the incoming request was encrypted.

This "opportunistic" encryption is great for mixed APIs, but if you want to strictly enforce security on specific views, you must use the Decorator.

---

## 3. The `@protect` Decorator

The `@protect` (or `@protect_view`) decorator is used to enforce UXSP on a specific view. 

### Why do programmers need to use decorators?
If you have a highly sensitive endpoint (like `/transfer_funds`), you **do not** want anyone to access it using plain text. 

By adding the `@protect` decorator, you are telling Django: *"If someone tries to access this endpoint without UXSP encryption, block them immediately!"* Furthermore, it guarantees that whatever you return from that view will be encrypted.

### How and Where to Use It
You place it right above your view function!

```python
from django.http import JsonResponse
from uxsp.contrib.django import protect

@protect()
def secure_transfer(request):
    # Because of @protect, we GUARANTEE that request.uxsp_payload exists
    # and was cryptographically verified.
    data = request.uxsp_payload
    
    amount = data.get("amount")
    to_account = data.get("to_account")
    
    # Process the transfer...
    
    # The dictionary returned here will be AUTOMATICALLY encrypted
    # by the middleware before it leaves the server!
    return JsonResponse({"status": "Success", "transferred": amount})
```

If a hacker tries to send a standard HTTP POST to `/secure_transfer`, the `@protect` decorator will intercept it and throw an error because the request was not encrypted by UXSP.
