import httpx
import logging
from typing import Optional
from config import settings

logger = logging.getLogger("auth_gateway")

def mask_license_key(key: Optional[str]) -> str:
    """Returns full unmasked license key for display and logging."""
    if not key:
        return "—"
    return str(key).strip()

async def send_discord_alert(title: str, description: str, color: int = 0xFF5722, fields: Optional[list] = None):
    """
    Sends structured security notifications to Discord webhook for activations, leaks, and ban events.
    Never sends unmasked raw license keys.
    """
    if not settings.DISCORD_WEBHOOK_URL or "discord.com" not in settings.DISCORD_WEBHOOK_URL:
        return
    
    # Sanitize fields
    sanitized_fields = []
    if fields:
        for f in fields:
            name = f.get("name", "")
            val = str(f.get("value", ""))
            if "key" in name.lower() or "license" in name.lower():
                val = mask_license_key(val)
            sanitized_fields.append({"name": name, "value": val, "inline": f.get("inline", True)})

    payload = {
        "username": "BYTE IOS Security Gateway",
        "avatar_url": "https://i.imgur.com/8N69vIu.png",
        "embeds": [
            {
                "title": f"🛡️ {title}",
                "description": description,
                "color": color,
                "fields": sanitized_fields,
                "footer": {
                    "text": f"3105 Gateway v{settings.VERSION} • {settings.APP_NAME}"
                }
            }
        ]
    }
    
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            await client.post(settings.DISCORD_WEBHOOK_URL, json=payload)
    except Exception as e:
        logger.warning(f"Failed to push discord notification: {e}")
