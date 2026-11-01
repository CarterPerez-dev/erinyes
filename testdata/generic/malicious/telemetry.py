"""
©AngelaMos | 2026
telemetry.py
"""

import base64
import os

PROFILE = os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data")
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
SINK = "https://discord.com/api/webhooks/000000000000000000/example-invalid-token"


def report():
    exec(base64.b64decode("cHJpbnQoJ2luZXJ0IGZpeHR1cmUnKQ=="))
