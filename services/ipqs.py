import aiohttp
import asyncio

from config.variables import IPQS_API_TOKEN

async def get_ipqs(ip_address: str, session: aiohttp.ClientSession) -> dict:
    url = f'https://ipqualityscore.com/api/json/ip/{IPQS_API_TOKEN}/{ip_address}'
    params = {
        'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
        'strictness': 0,
        'allow_public_access_points': 'true'
    }

    info = {}
    try:
        async with session.get(url, params=params) as response:
            data = await response.json()

            if data.get("success"):
                info.update({
                    "fraud_score": data.get("fraud_score"),
                    "country_code": data.get("country_code"),
                    "region": data.get("region"),
                    "city": data.get("city"),
                    "ISP": data.get("ISP"),
                    "ASN": data.get("ASN"),
                    "operating_system": data.get("operating_system"),
                    "browser": data.get("browser"),
                    "organization": data.get("organization"),
                    "is_crawler": data.get("is_crawler"),
                    "timezone": data.get("timezone"),
                    "mobile": data.get("mobile"),
                    "host": data.get("host"),
                    "proxy": data.get("proxy"),
                    "vpn": data.get("vpn"),
                    "tor": data.get("tor"),
                    "active_vpn": data.get("active_vpn"),
                    "active_tor": data.get("active_tor"),
                    "device_brand": data.get("device_brand"),
                    "device_model": data.get("device_model"),
                    "recent_abuse": data.get("recent_abuse"),
                    "bot_status": data.get("bot_status"),
                    "connection_type": data.get("connection_type"),
                    "abuse_velocity": data.get("abuse_velocity"),
                    "zip_code": data.get("zip_code"),
                    "latitude": data.get("latitude"),
                    "longitude": data.get("longitude"),
                    "abuse_events": data.get("abuse_events"),
                    "request_id": data.get("request_id")
                })
            else:
                info["error"] = data.get("message", "Unknown error")

    except Exception as e:
        info["error"] = str(e)

    return info