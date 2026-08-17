from slowapi import Limiter
from slowapi.util import get_remote_address

# Shared instance: imported by main.py (middleware/exception handler wiring)
# and by individual route modules (per-route @limiter.limit(...) decorators).
# Kept in its own module to avoid a circular import between main.py and app.api.*.
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])
