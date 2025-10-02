import aiohttp
from config.variables import IPINFO_TOKEN


async def get_ipinfo_info(ip: str) -> dict:
    url = f"https://ipinfo.io/{ip}/json"
    headers = {"Authorization": f"Bearer {IPINFO_TOKEN}"} if IPINFO_TOKEN else {}

    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()

                    asn_number = None
                    asn_org = None
                    org = data.get("org")
                    if org and org.startswith("AS"):
                        parts = org.split(" ", 1)
                        asn_number = parts[0]
                        asn_org = parts[1] if len(parts) > 1 else None

                    return {
                        "country": data.get("country"),
                        "region": data.get("region"),
                        "city": data.get("city"),
                        "asn_number": asn_number,
                        "asn_org": asn_org,
                    }
                else:
                    return {"error": f"HTTP {resp.status}"}
        except Exception as e:
            return {"error": str(e)}