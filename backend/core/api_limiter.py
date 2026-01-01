from slowapi import Limiter
from slowapi.util import get_remote_address

# Initialize the Limiter here to avoid circular imports via main.py
limiter = Limiter(key_func=get_remote_address)
