import base64


def to_b64(binary):
    return base64.b64encode(binary).decode('ascii')


def from_b64(base64_text):
    return base64.b64decode(base64_text)
