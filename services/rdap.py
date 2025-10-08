import aiohttp
import asyncio
import json

from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError

from config.variables import CLOUDFLARE_API_TOKEN

RIR_RDAP_BASE = {
    "arin": "https://rdap.arin.net/registry/ip/",
    "ripe": "https://rdap.db.ripe.net/ip/",
    "apnic": "https://rdap.apnic.net/ip/",
    "lacnic": "https://rdap.lacnic.net/rdap/ip/",
    "afrinic": "https://rdap.afrinic.net/rdap/ip/",
}

async def get_rdap_info(ip: str, session: aiohttp.ClientSession) -> dict:
    info = {}

    try:
        res = await asyncio.to_thread(IPWhois(ip).lookup_rdap)

        network = res.get('network', {})
        asn_number = res.get('asn')
        asn_cird = res.get('asn_cidr')
        asn_org = res.get('asn_description')
        registry = res.get("asn_registry")    
        country = network.get('country')        
        
        registry = (registry or "").lower()
        if registry == "ripencc":
            registry = "ripe"
        elif not registry or registry == "unknown":
            registry = None
        
        info.update({
            "as": asn_number,
            "name": asn_org,
            "cidr": asn_cird,
            "country": country,
            "org": asn_org,
            "source": registry,
        })

    except Exception as e:
        info["error"] = str(e)

    return info


async def get_rdap_cloudflare(asn: str, session: aiohttp.ClientSession) -> dict:
    url = f"https://api.cloudflare.com/client/v4/radar/entities/asns/?asn={asn}"
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
                        info["error"] = f"HTTP {response.status} after {retries} attempts"
                        break
                    await asyncio.sleep(delay)
                    delay *= 3
                    continue

                data = await response.json()
                result = data.get("result", {})

                if data.get("success") and "asns" in result and result["asns"]:
                    asn_info = result["asns"][0]
                    info.update({
                        "number": asn_info.get("asn"),
                        "name": asn_info.get("name"),
                        "website": asn_info.get("website"),
                        "country": asn_info.get("country"),
                        "country_name": asn_info.get("countryName"),
                        "aka": asn_info.get("aka"),
                        "org": asn_info.get("orgName"),
                        "source": asn_info.get("source"),
                    })
                else:
                    info["error"] = data.get("errors", "ASN not found")
                break

        except Exception as e:
            if attempt == retries:
                info["error"] = str(e)
                break
            await asyncio.sleep(delay)
            delay *= 3

    return info
    
'''
async def get_rdap_info(ip: str) -> dict:
    info = {}
    rdap_bootstrap_urls = [
        "https://data.iana.org/rdap/ipv4.json",
        "https://data.iana.org/rdap/ipv6.json",
    ]

    services = []
    timeout = aiohttp.ClientTimeout(total=5)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        for url in rdap_bootstrap_urls:
            try:
                async with session.get(url) as resp:
                    data = await resp.json()
                    services.extend(data.get("services", []))
            except Exception:
                continue

        rdap_url = None
        for service in services:
            cidrs, urls = service
            for u in urls:
                if u.startswith("https://"):
                    rdap_url = u
                    break
            if rdap_url:
                break

        if not rdap_url:
            info["error"] = "RDAP service not found"
            return info

        try:
            async with session.get(f"{rdap_url}ip/{ip}", timeout=10) as resp:
                data = await resp.json()

                info["country"] = data.get("country", None)
                info["name"] = data.get("name") or data.get("handle")

                org = None
                stack = data.get("entities", [])[:]
                registrant_names = []

                while stack:
                    ent = stack.pop(0)
                    roles = ent.get("roles", [])
                    if "registrant" in roles:
                        vcard = ent.get("vcardArray", [])
                        name = None
                        if len(vcard) > 1:
                            for row in vcard[1]:
                                if row[0] == "fn":
                                    name = row[3]
                                    break
                        if not name:
                            vcard_obj = ent.get("vCardObj", {})
                            name = vcard_obj.get("fn")
                        if name:
                            registrant_names.append(name)

                    if "entities" in ent:
                        stack.extend(ent["entities"])

                if registrant_names:
                    org = registrant_names[-1]

                info["org"] = org

        except Exception as e:
            info["error"] = str(e)

    return info
'''