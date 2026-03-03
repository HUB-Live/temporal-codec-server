import base64
import os

# 1. Generate 32 random bytes
random_bytes = os.urandom(32)

# 2. Encode to URL-safe Base64 (with padding)
# Fernet expects a 32-byte key encoded as URL-safe base64 with padding
encoded_string = base64.urlsafe_b64encode(random_bytes).decode('ascii')

print(encoded_string)
