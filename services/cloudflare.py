import aiohttp
import asyncio

from config.variables import CLOUDFLARE_API_TOKEN

async def get_cloudflare_info(ip: str, session: aiohttp.ClientSession) -> dict:
    url = f"https://api.cloudflare.com/client/v4/radar/entities/ip?ip={ip}"
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json"
    }

    retries = 4
    delay = 1
    info = {}

    for attempt in range(1, retries + 1):
        try:
            async with session.get(url, headers=headers) as response:
                if response.status != 200:
                    if attempt == retries:
                        info["request_error"] = f"HTTP {response.status} after {retries} attempts"
                        break
                    await asyncio.sleep(delay)
                    delay *= 3
                    continue

                data = await response.json()
                result = data.get("result", {})

                if data.get("success") and "ip" in result:
                    ip_info = result["ip"]
                    info.update({
                        "ip": ip_info.get("ip"),
                        "ip_version": ip_info.get("ipVersion"),
                        "country": ip_info.get("location"),
                        "country_name": ip_info.get("locationName"),
                        "asn_number": ip_info.get("asn"),
                        "asn_name": ip_info.get("asnName"),
                        "asn_org": ip_info.get("asnOrgName"),
                        "asn_location": ip_info.get("asnLocation"),
                    })
                else:
                    info["error"] = data.get("errors", "Unknown error")
                break

        except Exception as e:
            if attempt == retries:
                info["request_error"] = str(e)
                break
            await asyncio.sleep(delay)
            delay *= 3

    return info