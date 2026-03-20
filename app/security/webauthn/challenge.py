import os
import base64

def generate_challenge() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode()
