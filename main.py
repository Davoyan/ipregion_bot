import ipaddress
import socket
import aiohttp
import unicodedata
import difflib
import geoip2.database
import asyncio
import os
import uuid
import re
import time
import logging
import requests
import tldextract
from collections import OrderedDict
from aiogram import Bot, Dispatcher, F, types
from aiogram.types import Message
from aiogram.filters import Command
from aiogram.utils.keyboard import InlineKeyboardBuilder
from aiogram.types import InlineQuery, InlineQueryResultArticle, InputTextMessageContent
from urllib.parse import urlparse
from urllib.parse import quote

from config.bogon_ranges import BOGON_RANGES
from config.flags import COUNTRY_FLAGS
from config.countries import COUNTRY_MAP
from config.text_file_extensions import TEXT_FILE_EXTENSIONS

from config.variables import BOT_API_TOKEN
from config.variables import MAXMIND_DB_CITY_URL
from config.variables import MAXMIND_DB_ASN_URL
from config.variables import MAXMIND_DB_CITY
from config.variables import MAXMIND_DB_ASN
from config.variables import IPQS_WHITELIST
from config.variables import IPQS_WHITELIST_USERS

from services.cloudflare import get_cloudflare_info
from services.maxmind import get_maxmind_info
from services.ipinfo import get_ipinfo_info
from services.rdap import get_rdap_info
from services.rdap import get_rdap_cloudflare
from services.ipregistry import get_ipregistry_info
from services.ipqs import get_ipqs

CHECK_INTERVAL = 60 * 60
UPDATE_THRESHOLD = 24 * 60 * 60

BOT_RATE_LIMIT_INTERVAL = 0.05
CHAT_RATE_LIMIT_INTERVAL = 1.1
_rate_limit_lock = asyncio.Lock()
_bot_next_available = 0.0
_chat_next_available: dict[int, float] = {}

bot = Bot(token=BOT_API_TOKEN)
dp = Dispatcher()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

async def _throttle_message(chat_id: int | None) -> None:
    global _bot_next_available
    while True:
        async with _rate_limit_lock:
            now = time.monotonic()
            wait_until = _bot_next_available
            if chat_id is not None:
                wait_until = max(wait_until, _chat_next_available.get(chat_id, 0.0))

            if now >= wait_until:
                next_bot_from = _bot_next_available if _bot_next_available > now else now
                _bot_next_available = next_bot_from + BOT_RATE_LIMIT_INTERVAL
                if chat_id is not None:
                    chat_prev = _chat_next_available.get(chat_id, 0.0)
                    if chat_prev < now:
                        chat_prev = now
                    _chat_next_available[chat_id] = chat_prev + CHAT_RATE_LIMIT_INTERVAL
                return

            delay = wait_until - now

        await asyncio.sleep(delay)


async def answer_with_rate_limit(message: types.Message, *args, **kwargs):
    chat_id = message.chat.id if message.chat else None
    await _throttle_message(chat_id)
    return await message.answer(*args, **kwargs)

@dp.startup()
async def on_startup(bot: Bot):
    global bot_id, conn
    me = await bot.get_me()
    bot_id = me.id
    
@dp.message(Command("start"))
async def start(message: Message, command: Command):
    await answer_with_rate_limit(
        message,
        "Hi! Send me an IPv4, IPv6, or domain name, and I’ll show you its geo information."
    )

def get_country_flag(iso_code: str) -> str:
    if not iso_code:
        return ""
    return COUNTRY_FLAGS.get(iso_code.upper(), "") + " "

def get_bogon_description(ip: str) -> str | None:
    ip_obj = ipaddress.ip_address(ip)
    for net, desc in BOGON_RANGES.items():
        if ip_obj in ipaddress.ip_network(net, strict=False):
            return desc
    return None

def get_country_name(country_code: str) -> str:
    return COUNTRY_MAP.get(country_code.upper(), country_code)
    
def similar_enough(a: str, b: str, threshold: float = 0.9) -> bool:
    if not a or not b:
        return False

    def normalize(s: str) -> str:
        s = unicodedata.normalize("NFKD", s)
        s = "".join(c for c in s if not unicodedata.combining(c))
        s = s.lower()
        s = s.replace("-", " ").replace("_", " ").replace(".", " ")
        s = " ".join(s.split())
        return s

    a_norm = normalize(a)
    b_norm = normalize(b)

    if a_norm in b_norm or b_norm in a_norm:
        return True

    ratio = difflib.SequenceMatcher(None, a_norm, b_norm).ratio()
    return ratio >= threshold
    
def loose_contains(a: str, b: str) -> bool:
    if not a or not b:
        return False
    a_norm = a.strip().lower()
    b_norm = b.strip().lower()
    return a_norm in b_norm or b_norm in a_norm

def geo_compatible(a_region, a_city, b_region, b_city) -> bool:
    if not a_region and not a_city:
        return True
    if not b_region and not b_city:
        return True

    return (
        loose_contains(a_region, b_region) or
        loose_contains(a_city, b_city) or
        loose_contains(a_region, b_city) or
        loose_contains(a_city, b_region)
    )

def format_info(
    is_domain: bool,
    host: str,
    ip: str,
    maxmind: dict | None = None,
    ipinfo: dict | None = None,
    radp_cloudflare: dict | None = None,
    radp: dict | None = None,
    cloudflare: dict | None = None,
    ipregistry: dict | None = None,
    ipqs: dict | None = None
) -> tuple[str, str]:
    
    separator = ""
    lines = []
    
    bogon_desc = get_bogon_description(ip)
    if bogon_desc:
        ip_line = f"{separator}<b>IP:</b> <code>{ip}</code>"
        lines.append(f"⚠️ <b>Private Network IP:</b> {bogon_desc}")
        if is_domain: 
            lines.append(f"------------------------")
        return ip_line, "\n".join(lines) 
       
    # IPInfo
    ipi_country = ipinfo.get("country")
    ipi_region = ipinfo.get("region")
    ipi_city = ipinfo.get("city")
    ipi_asn_number = str(ipinfo.get("asn_number")) if ipinfo.get("asn_number") is not None else None
    ipi_asn_org = ipinfo.get("asn_org")
    ipi_error = ipinfo.get("error")
    ipi_anycast = ipinfo.get("anycast")
    
    # MaxMind
    mm_country = maxmind.get("country")
    mm_region = maxmind.get("region")
    mm_city = maxmind.get("city")
    mm_asn_number = maxmind.get("asn_number")
    if mm_asn_number is not None:
        mm_asn_number = f"AS{mm_asn_number}" 
    mm_asn_org = maxmind.get("asn_org")
    mm_error = maxmind.get("error")

    # Cloudflare
    cf_country = cloudflare.get("country")
    cf_asn_number = cloudflare.get("asn_number")
    if cf_asn_number is not None:
        if str(cf_asn_number) == "0":
            cf_asn_number = None
        else:
            cf_asn_number = f"AS{cf_asn_number}" 
    cf_asn_org = cloudflare.get("asn_org")
    cf_error = cloudflare.get("error")
    cf_request_error = cloudflare.get("request_error")    

    # RADP_Cloudflare
    radp_as_source = radp_cloudflare.get("source")
    radp_as_country = radp_cloudflare.get("country")
    radp_as_name = radp_cloudflare.get("name")
    radp_as_aka = radp_cloudflare.get("aka")
    radp_as_org = radp_cloudflare.get("org")
    radp_as_website = radp_cloudflare.get("website")
    radp_as_error = radp_cloudflare.get("error")
    
    # RADP
    radp_as = radp.get("as")
    radp_name = radp.get("name")
    radp_cidr = radp.get("cidr")
    radp_country = radp.get("country")
    radp_org = radp.get("org")
    radp_source = radp.get("source")    
    
    str_anycast = ""
    if ipi_anycast:
        str_anycast = " is anycast 🚀"
    
    bgp_link = f"https://bgp.tools/prefix-selector?ip={ip}"
    
    try:
        if radp_cidr:
            cidr_ip, cidr_mask = radp_cidr.split('/')
            bgp_link = f"https://bgp.tools/prefix/{cidr_ip}/{cidr_mask}"
    except Exception:
        pass
    
    censys_link = f"https://platform.censys.io/hosts/{ip}"
    ipnfo_link = f"https://ipinfo.io/{ip}"
    ipqs_link = f"https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{ip}"
    
    ip_line = f"{separator}<b>IP:</b> <code>{ip}</code>{str_anycast}\n<a href='{bgp_link}'>BGP</a> | <a href='{censys_link}'>Censys</a> | <a href='{ipnfo_link}'>Ipinfo.io</a> | <a href='{ipqs_link}'>IPQS</a>"
    
    maxmind_available = not mm_error
    ipinfo_available = not ipi_error
    cloudflare_available = not cf_error and not cf_request_error
    
    geo_sources = [
        {
            "key": "maxmind",
            "title": "MaxMind",
            "available": maxmind_available,
            "country": mm_country,
            "region": mm_region,
            "city": mm_city,
            "asn_number": mm_asn_number,
            "asn_org": mm_asn_org,
            "geo_rank": 1,
        },
        {
            "key": "ipinfo",
            "title": "IPinfo",
            "available": ipinfo_available,
            "country": ipi_country,
            "region": ipi_region,
            "city": ipi_city,
            "asn_number": ipi_asn_number,
            "asn_org": ipi_asn_org,
            "geo_rank": 0,
        },
        {
            "key": "cloudflare",
            "title": "Cloudflare",
            "available": cloudflare_available,
            "country": cf_country,
            "region": None,
            "city": None,
            "asn_number": cf_asn_number,
            "asn_org": cf_asn_org,
            "geo_rank": 2,
        },
    ]

    def can_merge(a: dict, b: dict) -> bool:
        try:
            if not (a["available"] and b["available"]):
                return False
            if not (a["country"] and b["country"]):
                return False
            if a["country"].strip().lower() != b["country"].strip().lower():
                return False
            if not (a["asn_number"] and b["asn_number"]):
                return False
            if str(a["asn_number"]).strip().lower() != str(b["asn_number"]).strip().lower():
                return False
            if not similar_enough(a["asn_org"] or "", b["asn_org"] or ""):
                return False
            return geo_compatible(a["region"], a["city"], b["region"], b["city"])
        except Exception:
            return False

    by_key = {source["key"]: source for source in geo_sources}

    cloudflare_to_ipinfo = (
        can_merge(by_key["cloudflare"], by_key["ipinfo"])
        and can_merge(by_key["cloudflare"], by_key["maxmind"])
        and not can_merge(by_key["maxmind"], by_key["ipinfo"])
    )

    def can_pair(a: dict, b: dict) -> bool:
        if cloudflare_to_ipinfo and {a["key"], b["key"]} == {"maxmind", "cloudflare"}:
            return False
        return can_merge(a, b)

    groups = []
    grouped = set()
    for i, source in enumerate(geo_sources):
        if i in grouped:
            continue
        group = [source]
        grouped.add(i)
        for j in range(i + 1, len(geo_sources)):
            if j in grouped:
                continue
            if all(can_pair(member, geo_sources[j]) for member in group):
                group.append(geo_sources[j])
                grouped.add(j)
        groups.append(group)

    cloudflare_proceed = False

    for group in groups:
        if not group[0]["available"]:
            key = group[0]["key"]
            if key == "ipinfo":
                if str(ipi_error) == "HTTP 429":
                    lines.append("")
                    lines.append(f"▢ <b>Ipinfo:</b>")
                    lines.append(f"⚠️ Ipinfo error (429)")
                else:
                    lines.append("")
                    lines.append(f"⚠️ Ipinfo error")
            elif key == "cloudflare":
                if str(cf_request_error or cf_error) == "HTTP 429":
                    lines.append("")
                    lines.append(f"▢ <b>Cloudflare:</b>")
                    lines.append(f"⚠️ Cloudflare error (429)")
                else:
                    lines.append("")
                    lines.append(f"⚠️ Cloudflare error")
            continue

        if any(member["key"] == "cloudflare" for member in group):
            cloudflare_proceed = True

        titles = [member["title"] for member in group]
        titles[-1] = f"{titles[-1]}:"

        lines.append("")
        lines.append("▢ " + " & ".join(f"<b>{title}</b>" for title in titles))

        country = next((member["country"] for member in group if member["country"]), None)
        if country:
            country_flag = get_country_flag(country.strip())
            country_name = get_country_name(country)
            line = f"{country_flag}{country}"
            if country.strip().upper() != str(country_name).strip().upper():
                line += f" {country_name}"

            by_geo_rank = sorted(group, key=lambda member: member["geo_rank"])
            region = next((member["region"] for member in by_geo_rank if member["region"]), None)
            city = next((member["city"] for member in by_geo_rank if member["city"]), None)

            if region:
                line += f", {region}"
            if city and (not similar_enough(city, region)):
                line += f", {city}"
            lines.append(line)
        elif group[0]["key"] == "maxmind":
            lines.append(f"🏳 No geo data")

        asn_number = next((member["asn_number"] for member in group if member["asn_number"]), None)
        if asn_number:
            asn_org = max(
                (member["asn_org"] for member in group if member["asn_org"]),
                key=len,
                default=None
            )
            asn_line = f"{asn_number}"
            if asn_org:
                asn_line += f" / {asn_org}"
            lines.append(asn_line)

    # RADP
    radp_as = radp.get("as")
    radp_name = radp.get("name")
    radp_country = radp.get("country")
    radp_org = radp.get("org")
    radp_source = radp.get("source")

    # --- RADP ---
    if not radp_as_error and cloudflare_proceed:
        if radp_as_source:
            
            if radp_source:
                source = str(radp_source)
            else:
                source = str(radp_as_source)
                
            RIR_RDAP_BASE = {
                "arin": "https://rdap.arin.net/registry/ip/",
                "ripe": "https://rdap.db.ripe.net/ip/",
                "apnic": "https://rdap.apnic.net/ip/",
                "lacnic": "https://rdap.lacnic.net/rdap/ip/",
                "afrinic": "https://rdap.afrinic.net/rdap/ip/",
            }
            
            rdap_link_base = RIR_RDAP_BASE.get(source.lower(), "#")
            
            lines.append("")
            lines.append(f"▢ <b>Registration</b> ({source.upper()})<b>:</b>")                        
                       
            radp_error = radp.get("error") 
            if not radp_error:
                if radp_country:
                    country_flag = get_country_flag(radp_country.strip())
                    country_name = get_country_name(radp_country)
                    line = f"{country_flag}{radp_country.upper()} {country_name} (IP)"
                    lines.append(line)
                    if rdap_network_name:
                        line = f"{rdap_network_name}"
                        lines.append(line)
                #else:
                #    country_flag = "🏳"
                #    line = f"{country_flag} Region not specified (IP)"
                #    lines.append(line)
            
            if radp_as_country:
                country_flag = get_country_flag(radp_as_country.strip())
                country_name = get_country_name(radp_as_country)
                line = f"{country_flag}{radp_as_country.upper()} {country_name} (AS)"
                lines.append(line)
            else:
                country_flag = "🏳"
                line = f"{country_flag} Region not specified (AS)"
                lines.append(line)
                
            if radp_as_name:
                if radp_as_website and radp_as_website.lower() != 'none':
                    name_line = f"<a href='{radp_as_website.strip()}'>{radp_as_name.strip()}</a>"
                else:
                    name_line = f"{radp_as_name.strip()}"
                if radp_as_aka:
                    name_line += f" / {radp_as_aka}"
                    
                lines.append(name_line)
    
    ipregistry_proceeded = False    
    if "security" in ipregistry:
        ipregistry_proceeded = True
        lines.append("")
        lines.append("▢ <b>Privacy info</b> (ipregistry<b>․</b>co)<b>:</b>")

        security = ipregistry["security"]

        checks = {           
            "Proxy": security.get("is_proxy") or security.get("is_tor") or security.get("is_tor_exit") or security.get("is_anonymous") or security.get("is_relay") or security.get("is_vpn"),
            "Abuser": security.get("is_abuser") or security.get("is_attacker") or security.get("is_threat"),
            "Server": security.get("is_cloud_provider")
        }

        items = list(checks.items())
        line = ""

        for i, (name, value) in enumerate(items):
            mark = "✅" if value else "❌"
            sep = " / " if i < len(items) - 1 else ""
            line += f"{name}: {mark}{sep}"

        lines.append(line)
        
    if ipqs and "error" not in ipqs:
        lines.append("")
        lines.append("▢ <b>Privacy info</b> (IPQS)<b>:</b>")                
            
        checks = {
            "Proxy": ipqs.get("vpn") or ipqs.get("active_vpn") or ipqs.get("tor") or ipqs.get("active_tor") or ipqs.get("proxy"),
            "Abuser": ipqs.get("recent_abuse") or ipqs.get("is_crawler") or ipqs.get("bot_status")
        }
        
        items = list(checks.items())
        line = ""

        for i, (name, value) in enumerate(items):
            mark = "✅" if value else "❌"
            sep = " / " if i < len(items) - 1 else ""
            line += f"{name}: {mark}{sep}"
        lines.append(line)
        
        mark = ""
        desc = ""
        fraud_score = ipqs.get("fraud_score")
        if fraud_score is not None:
            if 0 <= fraud_score <= 20:
                mark = "🟢"
                desc = "Safe"
            elif 21 <= fraud_score <= 50:
                mark = "🟡"
                desc = "Moderate risk"
            elif 51 <= fraud_score <= 75:
                mark = "🟠"
                desc = "High risk"
            else:
                mark = "🔴"
                desc = "Fraud"

            lines.append(f"Fraud score: <b>{fraud_score}</b> - {mark} {desc}")

    if is_domain:
        lines.append(f"------------------------")
    
    return ip_line, "\n".join(lines)

def normalize_domain(query: str) -> str:
    query = query.strip()
    if not query:
        return ""

    try:
        ipaddress.ip_address(query)
        return query
    except ValueError:
        pass

    if "/" in query:
        base = query.split("/", 1)[0]
        try:
            ipaddress.ip_address(base)
            return base
        except ValueError:
            pass

    if "://" not in query:
        query = "https://" + query

    parsed = urlparse(query)
    host = parsed.hostname or ""

    if host.lower() == "localhost":
        return "127.0.0.1"

    return host

async def _doh_query(session: aiohttp.ClientSession, domain: str, doh_url: str, record_type: str) -> list[str]:
    headers = {"Accept": "application/dns-json"}
    try:
        async with session.get(
            doh_url, params={"name": domain, "type": record_type}, headers=headers
        ) as resp:
            try:
                data = await resp.json(content_type=None)
            except Exception:
                return []
            answers = data.get("Answer") or data.get("answer")
            results = []
            if answers:
                for ans in answers:
                    data = ans.get("data")
                    if data:
                        results.append(data)
            return results
    except Exception:
        return []
    
async def resolve_host(query: str) -> tuple[str, list[str], bool, bool]:
    query = normalize_domain(query)
    ech_status = False
    
    if not query:
        return "", [], False, False

    try:
        ipaddress.ip_address(query)
        return query, [query], False, False
    except ValueError:
        pass

    seen = set()
    to_resolve = [query]
    final_ips = []

    async with aiohttp.ClientSession() as session:
        for doh_url in ["https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query"]:
            new_to_resolve = to_resolve.copy()
            while new_to_resolve:
                domain = to_punycode(str(new_to_resolve.pop(0)).strip())
                if domain in seen:
                    continue
                seen.add(domain)

                record_types = ("A", "AAAA", "CNAME", "HTTPS")
                results_cache = {}

                tasks = [_doh_query(session, domain, doh_url, rt) for rt in record_types]
                results_list = await asyncio.gather(*tasks, return_exceptions=True)
                for rt, res in zip(record_types, results_list):
                    results_cache[rt] = res if not isinstance(res, Exception) else []

                for record_type in ("A", "AAAA"):
                    for ip in results_cache[record_type]:
                        try:
                            ipaddress.ip_address(ip)
                            if ip not in final_ips:                     
                                final_ips.append(ip)
                        except ValueError:
                            continue

                for cname in results_cache["CNAME"]:
                    if cname not in seen:
                        new_to_resolve.append(cname)          

                for https_record in results_cache["HTTPS"]:
                    try:
                        hex_data = ''.join(https_record.split()[2:])
                        rr_bytes = bytes.fromhex(hex_data)
                        if b'cloudflare-ech.com' in rr_bytes:
                            ech_status = True
                    except Exception:
                        pass

            if final_ips:
                break

    return query, final_ips, bool(final_ips), ech_status

def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

class TTLCache:
    def __init__(self, max_size=2000, ttl=21600):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.ttl = ttl
        self.lock = asyncio.Lock()

    async def get(self, key):
        async with self.lock:
            item = self.cache.get(key)
            if not item:
                return None
            value, timestamp = item
            if time.time() - timestamp > self.ttl:
                del self.cache[key]
                return None
            self.cache.move_to_end(key)
            return value

    async def set(self, key, value):
        async with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            self.cache[key] = (value, time.time())
            if len(self.cache) > self.max_size:
                self.cache.popitem(last=False)
                
    async def delete(self, key):
        async with self.lock:
            if key in self.cache:
                del self.cache[key]

asn_cache = TTLCache(max_size=5000, ttl=43200)
maxmind_cache = TTLCache(max_size=5000, ttl=43200)
ipinfo_cache = TTLCache(max_size=5000, ttl=43200)
cloudflare_cache = TTLCache(max_size=5000, ttl=43200)
ipregistry_cache = TTLCache(max_size=5000, ttl=43200)
rdap_cache = TTLCache(max_size=5000, ttl=43200) # 12 hours

ipqs_cache = TTLCache(max_size=10000, ttl=14*24*60*60) # 2 weeks

async def cached_get_maxmind_info(ip):
    cached = await maxmind_cache.get(ip)
    if cached:
        return cached
    data = await get_maxmind_info(ip)
    if isinstance(data, dict) and "error" not in data:
        await maxmind_cache.set(ip, data)
    return data

async def cached_get_ipinfo_info(ip, session):
    cached = await ipinfo_cache.get(ip)
    if cached:
        return cached
    data = await get_ipinfo_info(ip, session)
    if isinstance(data, dict) and "error" not in data:
        await ipinfo_cache.set(ip, data)
    return data

async def cached_get_cloudflare_info(ip, session):
    cached = await cloudflare_cache.get(ip)
    if cached:
        return cached
    data = await get_cloudflare_info(ip, session)
    if isinstance(data, dict) and "error" not in data:
        await cloudflare_cache.set(ip, data)
    return data

async def cached_get_ipregistry_info(ip, session):
    cached = await ipregistry_cache.get(ip)
    if cached:
        return cached
    data = await get_ipregistry_info(ip, session)
    if isinstance(data, dict) and "error" not in data:
        await ipregistry_cache.set(ip, data)
    return data

async def cached_get_rdap_info(ip, session):
    cached = await rdap_cache.get(ip)
    if cached:
        return cached
    data = await get_rdap_info(ip, session)
    if isinstance(data, dict) and "error" not in data:
        await rdap_cache.set(ip, data)
    return data

async def cached_get_ipqs_info(ip, session):
    cached = await ipqs_cache.get(ip)
    if cached:
        return cached
    data = await get_ipqs(ip, session)
    if isinstance(data, dict) and "error" not in data:
        await ipqs_cache.set(ip, data)
    return data

async def _process_ip(
    ip: str,
    session: aiohttp.ClientSession,
    is_domain: bool,
    host: str,
    results: list,
    user_id: int | None = None
):
    try:
        ipqs_whitelist_user = False
        if IPQS_WHITELIST and user_id in IPQS_WHITELIST_USERS:
            ipqs_whitelist_user = True          

        bogon_desc = get_bogon_description(ip)
        if bogon_desc:
            ip_line, info_text = format_info(is_domain, host, ip)
            results.append((ip, info_text, ip_line))
            return

        ipqs = None
        if ipqs_whitelist_user:
            ipqs = await cached_get_ipqs_info(ip, session)
            
        maxmind, ipinfo, cloudflare, ipregistry, radp = await asyncio.gather(
            cached_get_maxmind_info(ip),
            cached_get_ipinfo_info(ip, session),
            cached_get_cloudflare_info(ip, session),
            cached_get_ipregistry_info(ip, session),
            cached_get_rdap_info(ip, session)
        )

        asn_number = cloudflare.get("asn_number")
        if asn_number:
            cached_asn = await asn_cache.get(asn_number)
            if cached_asn:
                rdap_cloudflare = cached_asn
            else:
                rdap_cloudflare = await get_rdap_cloudflare(asn_number, session)
                if "error" not in rdap_cloudflare:
                    await asn_cache.set(asn_number, rdap_cloudflare)
        else:
            rdap_cloudflare = {"error": "ASN not found"}

        ip_line, info_text = format_info(
            is_domain=is_domain,
            host=host,
            ip=ip,
            maxmind=maxmind,
            ipinfo=ipinfo,
            radp_cloudflare=rdap_cloudflare,
            radp=radp,
            cloudflare=cloudflare,
            ipregistry=ipregistry,
            ipqs=ipqs
        )

        result_tuple = (ip, info_text, ip_line)

        results.append(result_tuple)

    except Exception:
        pass

async def process_input(text: str, user_id: int | None = None) -> str | None:
    host, ip_list, is_domain, ech_status = await resolve_host(text)
    if not ip_list:
        return None, host

    valid_ips = [ip for ip in ip_list if is_ip(ip)]
    
    def sort_ip(ip: str):
        try:
            ip_obj = ipaddress.ip_address(ip.strip())
            return (ip_obj.version, ip_obj)
        except ValueError:
            return (9, ip)

    valid_ips.sort(key=sort_ip)

    results: list[tuple[str, str, str]] = []
    
    async with aiohttp.ClientSession() as session:
        await asyncio.gather(*(
            _process_ip(ip, session, is_domain, host, results, user_id=user_id)
            for ip in valid_ips
        ))

    results.sort(key=lambda x: (sort_ip(x[0])[0], x[1], sort_ip(x[0])[1]))

    ip_groups = OrderedDict()
    for ip, info_text, ip_line in results:
        ip_groups.setdefault(info_text, []).append(ip_line)

    texts = []
    if is_domain:
        ext = tldextract.extract(host)
        tld = ext.suffix.lower()       

        host_punycode = to_punycode(host)
        
        ext = tldextract.extract(host_punycode)
        root_domain = f"{ext.domain}.{ext.suffix}"
        
        match tld:
            case "ru" | "su" | "дети" | "tatar" | "рф":
                whois_link = f"https://whois.tcinet.ru/#{root_domain}"       
            case "ua":
                whois_link = f"https://www.hostmaster.ua/whois/?_domain={root_domain}"
            case _:
                whois_link = f"https://info.addr.tools/{root_domain}"

        texts.append(f"🔗 <b>Host:</b> {host} (<a href='{whois_link}'>Whois</a>?)")
        if ech_status:
            texts.append("🔒 Cloudflare ECH = ON")
        texts.append("------------------------")
        
    for info_text, ip_lines in ip_groups.items():
        texts.append("\n".join(ip_lines))
        texts.append(info_text)

    return "\n".join(texts), host

def to_punycode(host: str) -> str:
    try:
        result = host.encode("idna").decode("ascii")
        return result
    except Exception:
        return host

def is_valid_target(item: str) -> bool:
    if item.lower() == "localhost":
        return True

    domain_pattern = re.compile(
        r"^(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z0-9_-]{2,63}$"
    )

    parsed = urlparse(item)
    if parsed.scheme in ("http", "https") and parsed.hostname:
        host = to_punycode(parsed.hostname)
        try:
            ipaddress.ip_network(host, strict=False)
            return True
        except ValueError:
            pass

        if domain_pattern.match(host):
            return True
        return False

    item = to_punycode(item.strip())

    if item.startswith("[") and "]" in item:
        host = item[1:item.index("]")]
    elif ":" in item and item.count(":") == 1:
        host_part, port_part = item.rsplit(":", 1)
        host = host_part if port_part.isdigit() else item
    else:
        host = item

    try:
        ipaddress.ip_network(host, strict=False)
        return True
    except ValueError:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            pass

    if domain_pattern.match(host):
        return True

    return False

def extract_hosts(text: str):
    ipv4_pattern = r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?"
    ipv6_pattern = r"(?:[A-Fa-f0-9:]+:+)+[A-Fa-f0-9]*(?:/\d{1,3})?"
    domain_pattern = r"\b(?:[a-zA-Z0-9_\u00a1-\uffff-]{1,63}\.)+[a-zA-Z\u00a1-\uffff]{2,63}\b"

    ips = re.findall(ipv4_pattern, text)
    ips += re.findall(ipv6_pattern, text)
    domains = re.findall(domain_pattern, text, flags=re.UNICODE)

    all_hosts = ips + domains
    seen = set()
    ordered_hosts = []
    for h in all_hosts:
        if h not in seen:
            seen.add(h)
            ordered_hosts.append(h)

    return ordered_hosts

@dp.message()
async def dpmessage(message: types.Message):
    text = None

    if message.text:
        text = message.text

    elif message.document:
        doc = message.document
        if (doc.mime_type and doc.mime_type.startswith("text/")) or doc.file_name.endswith(TEXT_FILE_EXTENSIONS):
            file_info = await bot.get_file(doc.file_id)
            file_path = file_info.file_path
            downloaded = await bot.download_file(file_path)
            text = downloaded.read().decode("utf-8", errors="ignore")
        else:
            await answer_with_rate_limit(message, "❌ This file is not in text format.")
            return

    if not text:
        return

    text = re.sub(r"[,'\"!?]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    
    raw_hosts = extract_hosts(text)
    hosts_map = {to_punycode(h): h for h in raw_hosts}
    inputs = list(hosts_map.keys())

    if not inputs:
        await answer_with_rate_limit(message, "❌ No IPs or domains found.")
        return

    found = False
    seen = set()
    for punycode_host in inputs:
        if not is_valid_target(punycode_host):
            continue

        original_host = hosts_map[punycode_host]

        try:
            result, host = await process_input(original_host, user_id=message.from_user.id)
        except Exception:
            continue

        if result and result not in seen:
            found = True
            seen.add(result)
            await answer_with_rate_limit(message, result, parse_mode="HTML", disable_web_page_preview=True)

    if not found:
        await answer_with_rate_limit(message, "❌ Failed to resolve any IPs/domains.", parse_mode="HTML")

@dp.inline_query()
async def inline_ip_lookup(query: InlineQuery):
    text = query.query.strip()
    if not text:
        return

    result_text, host = await process_input(text, user_id=query.from_user.id)
    if not result_text:
        content = InputTextMessageContent(message_text=f"❌ Failed to resolve IP for: {text}")
    else:
        content = InputTextMessageContent(
            message_text=result_text,
            parse_mode="HTML",
            disable_web_page_preview=True
        )

    result = InlineQueryResultArticle(
        id=str(uuid.uuid4()),
        title=f"Send geo info about: {host}",
        input_message_content=content
    )

    await query.answer(
        results=[result],
        cache_time=10,
        is_personal=True
    )

async def check_and_update(session, file_path, url):
    try:
        if not os.path.exists(file_path):
            logger.info(f"{file_path} not found. Downloading new file.")
        else:
            mtime = os.path.getmtime(file_path)
            age = time.time() - mtime
            if age <= UPDATE_THRESHOLD:
                logger.info(f"{file_path} is fresh ({int(age)} seconds). No update needed.")
                return
            logger.info(f"{file_path} is older than threshold ({int(age)} seconds). Updating.")

        logger.info(f"Downloading {url} to {file_path}")
        async with session.get(url) as response:
            response.raise_for_status()
            with open(file_path, "wb") as f:
                while True:
                    chunk = await response.content.read(1024 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)
        logger.info(f"Geofile {file_path} updated successfully.")
    except Exception as e:
        logger.info(f"Error while updating geofile {file_path}: {e}")

async def polling_task():
    await dp.start_polling(bot)

async def updater_task():
    async with aiohttp.ClientSession() as session:
        while True:
            await check_and_update(session, MAXMIND_DB_CITY, MAXMIND_DB_CITY_URL)
            await check_and_update(session, MAXMIND_DB_ASN, MAXMIND_DB_ASN_URL)
            await asyncio.sleep(CHECK_INTERVAL)

async def main():
    logging.getLogger("aiogram").setLevel(logging.WARNING)
    await asyncio.gather(
        polling_task(),
        updater_task()
    )

if __name__ == "__main__":
    asyncio.run(main())
