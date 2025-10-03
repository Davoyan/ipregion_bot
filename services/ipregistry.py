import aiohttp
import asyncio

from config.variables import IPREGISTRY_API_TOKEN

async def get_ipregistry_info(ip: str, session: aiohttp.ClientSession) -> dict:
    url = f"https://api.ipregistry.co/{ip}?key={IPREGISTRY_API_TOKEN}"

    info = {
        "ip": ip,
        "type": None,
        "hostname": None,
        "city": None,
        "region": None,
        "region_code": None,
        "country": None,
        "country_code": None,
        "latitude": None,
        "longitude": None,
        "asn_number": None,
        "asn_org": None,
        "network": None,
        "security": {
            "is_abuser": False,
            "is_attacker": False,
            "is_bogon": False,
            "is_cloud_provider": False,
            "is_proxy": False,
            "is_relay": False,
            "is_tor": False,
            "is_tor_exit": False,
            "is_vpn": False,
            "is_anonymous": False,
            "is_threat": False
        },
        "request_error": None
    }

    try:
        async with session.get(url) as response:
            response.raise_for_status()
            data = await response.json()
            if not isinstance(data, dict):
                info["request_error"] = "Invalid JSON response"
                return info

            location = data.get("location", {})
            region = location.get("region", {})
            info.update({
                "type": data.get("type"),
                "hostname": data.get("hostname"),
                "city": location.get("city"),
                "region": region.get("name"),
                "region_code": region.get("code"),
                "country": location.get("country", {}).get("name"),
                "country_code": location.get("country", {}).get("code"),
                "latitude": location.get("latitude"),
                "longitude": location.get("longitude")
            })

            connection = data.get("connection", {})
            info.update({
                "asn_number": connection.get("asn"),
                "asn_org": connection.get("organization"),
                "network": connection.get("route"),
                "type": connection.get("type")
            })

            security = data.get("security", {})
            for key in info["security"].keys():
                info["security"][key] = security.get(key, False)

    except aiohttp.ClientResponseError as e:
        info["request_error"] = f"HTTP error: {e.status} {e.message}"
    except aiohttp.ClientError as e:
        info["request_error"] = f"Client error: {str(e)}"
    except Exception as e:
        info["request_error"] = f"Unexpected error: {str(e)}"

    return info