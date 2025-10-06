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
import html
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
from config.variables import ENABLE_SUBSCRIPTION_CHECK
from config.variables import OUTBOUND_PROXY

from services.cloudflare import get_cloudflare_info
from services.maxmind import get_maxmind_info
from services.ipinfo import get_ipinfo_info
from services.rdap import get_rdap_info
from services.ipregistry import get_ipregistry_info
from services.proxy import extract_proxy_uris, parse_proxy_uri
from services.subscriptions import fetch_subscription_proxies


CHECK_INTERVAL = 60 * 60
UPDATE_THRESHOLD = 24 * 60 * 60

bot = Bot(token=BOT_API_TOKEN)
dp = Dispatcher()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

@dp.startup()
async def on_startup(bot: Bot):
    global bot_id, conn
    me = await bot.get_me()
    bot_id = me.id
    
@dp.message(Command("start"))
async def start(message: Message, command: Command):
    await message.answer(
        "Hi! Send me an IPv4, IPv6, or domain name, and I’ll show you its geo information."
    )


logger = logging.getLogger(__name__)


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

    ratio = difflib.SequenceMatcher(None, a_norm, b_norm).ratio()
    return ratio >= threshold
    


SUBSCRIPTION_URL_PATTERN = re.compile(r"https?://[^\s]+")
TRAILING_PROXY_CHARS = ')]\n\r\t,.;:\'"'


def escape_html(value: str) -> str:
    return html.escape(value or "", quote=True)

def format_info(
    is_domain: bool,
    host: str,
    ip: str,
    maxmind: dict,
    ipinfo: dict,
    radp: dict,
    cloudflare: dict,
    ipregistry: dict
) -> tuple[str, str]:
    bgp_link = f"https://bgp.tools/prefix-selector?ip={ip}"
    censys_link = f"https://search.censys.io/hosts/{ip}"
    ipnfo_link = f"https://ipinfo.io/{ip}"
    
    separator = ""
  
    ip_line = f"{separator}<b>IP:</b> <code>{ip}</code>\n<a href='{bgp_link}'>BGP</a> / <a href='{censys_link}'>Censys</a> / <a href='{ipnfo_link}'>Ipinfo.io</a>"
    lines = []
    bogon_desc = get_bogon_description(ip)
    if bogon_desc:
        ip_line = f"{separator}<b>IP:</b> <code>{ip}</code>"
        lines.append(f"⚠️ <b>Private Network IP:</b> {bogon_desc}")
        if is_domain: 
            lines.append(f"----------------")
        return ip_line, "\n".join(lines) 
    
    # MaxMind
    mm_country = maxmind.get("country")
    mm_region = maxmind.get("region")
    mm_city = maxmind.get("city")
    mm_asn_number = str(maxmind.get("asn_number"))
    if mm_asn_number:
        mm_asn_number = f"AS{mm_asn_number}"
    mm_asn_org = maxmind.get("asn_org")
    mm_error = maxmind.get("error")

    # IPinfo
    ipi_country = ipinfo.get("country")
    ipi_region = ipinfo.get("region")
    ipi_city = ipinfo.get("city")
    ipi_asn_number = str(ipinfo.get("asn_number"))
    ipi_asn_org = ipinfo.get("asn_org")
    ipi_error = ipinfo.get("error")

    # Cloudflare
    cf_country = cloudflare.get("country")
    cf_asn_number = cloudflare.get("asn_number")
    if cf_asn_number and cf_asn_number != "0":
        cf_asn_number = f"AS{cf_asn_number}"
    if cf_asn_number and str(cf_asn_number) == "0":
        cf_asn_number = None
    cf_asn_org = cloudflare.get("asn_org")
    cf_error = cloudflare.get("error")
    cf_request_error = cloudflare.get("request_error")
    

    # RADP
    radp_source = radp.get("source")
    radp_country = radp.get("country")
    radp_name = radp.get("name")
    radp_aka = radp.get("aka")
    radp_org = radp.get("org")
    radp_website = radp.get("website")
    radp_error = radp.get("error")
    
    
    maxmind_available = not mm_error
    ipinfo_available = not ipi_error
    cloudflare_available = not cf_error and not cf_request_error
    
    merged_all = False
    try:
        merged_all = all([
            maxmind_available,
            ipinfo_available,
            cloudflare_available,
            mm_country and ipi_country and cf_country and
            mm_country.strip().lower() == ipi_country.strip().lower() == cf_country.strip().lower(),
            mm_asn_number and ipi_asn_number and cf_asn_number and
            mm_asn_number.strip().lower() == ipi_asn_number.strip().lower() == cf_asn_number.strip().lower(),
            mm_asn_org and ipi_asn_org and cf_asn_org and
            similar_enough(mm_asn_org, ipi_asn_org) and
            similar_enough(ipi_asn_org, cf_asn_org),
            (mm_region or mm_city) and (ipi_region or ipi_city) and (
                (mm_region and ipi_region and (mm_region.strip().lower() in ipi_region.strip().lower() or ipi_region.strip().lower() in mm_region.strip().lower())) or
                (mm_city and ipi_city and (mm_city.strip().lower() in ipi_city.strip().lower() or ipi_city.strip().lower() in mm_city.strip().lower())) or
                (mm_region and ipi_city and (mm_region.strip().lower() in ipi_city.strip().lower() or ipi_city.strip().lower() in mm_region.strip().lower())) or
                (mm_city and ipi_region and (mm_city.strip().lower() in ipi_region.strip().lower() or ipi_region.strip().lower() in mm_city.strip().lower()))
            )
        ])
    except Exception:
        merged_all = False
    
    cloudflare_proceed = False
    
    if merged_all:
        # --- MaxMind & IPinfo & Cloudflare ---
        lines.append("○  <b>MaxMind</b> & <b>IPinfo</b> & <b>Cloudflare:</b>")
        country_flag = get_country_flag(mm_country.strip())
        country_name = get_country_name(mm_country)
        line = f"{country_flag}{mm_country} {country_name}"
        if mm_region:
            line += f", {mm_region}"
        if mm_city and mm_city != mm_region:
            line += f", {mm_city}"
        lines.append(line)

        asn_line = f"{mm_asn_number}"
        if mm_asn_org:
            asn_line += f" / {mm_asn_org}"
        lines.append(asn_line)

        cloudflare_proceed = True
    else:
        # --- MaxMind ---
        if maxmind_available:
            lines.append(f"○  <b>MaxMind:</b>")
            if mm_country:
                country_flag = get_country_flag(mm_country.strip())
                country_name = get_country_name(mm_country)
                line = f"{country_flag}{mm_country} {country_name}"
                if mm_region:
                    line += f", {mm_region}"
                if mm_city and mm_city != mm_region:
                    line += f", {mm_city}"
                lines.append(line)
            else:
                country_flag = "🏳"
                line = f"{country_flag} Region not specified"
                lines.append(line)
            if mm_asn_number:
                asn_line = f"{mm_asn_number}"
                if mm_asn_org:
                    asn_line += f" / {mm_asn_org}"
                lines.append(asn_line)
        else:
            lines.append("")
            lines.append(f"⚠️ MaxMind error")  
        
        merged = (
            ipinfo_available and cloudflare_available and
            ipi_country.strip().lower() == cf_country.strip().lower() and
            ipi_asn_number.strip().lower() == cf_asn_number.strip().lower() and
            similar_enough(ipi_asn_org, cf_asn_org)
        )
        
        # --- IPinfo AND Cloudflare ---
        if merged:
            cloudflare_proceed = True
            lines.append("")
            lines.append("○  <b>IPinfo</b> & <b>Cloudflare:</b>")
            if ipi_country:
                country_flag = get_country_flag(ipi_country.strip())
                country_name = get_country_name(ipi_country)
                line = f"{country_flag}{ipi_country} {country_name}"
                if ipi_region:
                    line += f", {ipi_region}"
                if ipi_city and (not similar_enough(ipi_city, ipi_region)):
                    line += f", {ipi_city}"
                lines.append(line)
            if ipi_asn_number:
                asn_line = f"{ipi_asn_number}"
                if ipi_asn_org:
                    asn_line += f" / {ipi_asn_org}"
                lines.append(asn_line)
        else:
        # --- IPinfo ---
            if not ipi_error:
                lines.append("")
                lines.append(f"○  <b>IPinfo:</b>")
                if ipi_country:
                    country_flag = get_country_flag(ipi_country.strip())
                    country_name = get_country_name(ipi_country)
                    line = f"{country_flag}{ipi_country}"
                    if ipi_country.strip().upper() != country_name.strip().upper():
                        line += f" {country_name}"
                    if ipi_region:
                        line += f", {ipi_region}"
                    if ipi_city and (not similar_enough(ipi_city, ipi_region)):
                        line += f", {ipi_city}"
                    lines.append(line)
                if ipi_asn_number:
                    asn_line = f"{ipi_asn_number}"
                    if ipi_asn_org:
                        asn_line += f" / {ipi_asn_org}"
                    lines.append(asn_line)
            else:
                if str(ipi_error) == "HTTP 429":
                    lines.append("")
                    lines.append(f"○  <b>Ipinfo:</b>")
                    lines.append(f"⚠️ Ipinfo error (429)")
                else:
                    lines.append("")
                    lines.append(f"⚠️ Ipinfo error")
            
            # --- Cloudflare ---
            if not cf_error and not cf_request_error:
                cloudflare_proceed = True
                lines.append("")
                lines.append(f"○  <b>Cloudflare:</b>")
                if cf_country:
                    country_flag = get_country_flag(cf_country.strip())
                    country_name = get_country_name(cf_country)
                    line = f"{country_flag}{cf_country}"
                    if cf_country.strip().upper() != country_name.strip().upper():
                        line += f" {country_name}"
                    lines.append(line)
                if cf_asn_number:
                    asn_line = f"{cf_asn_number}"
                    if cf_asn_org:
                        asn_line += f" / {cf_asn_org}"
                    lines.append(asn_line)
            else:
                if str(cf_request_error or cf_error) == "HTTP 429":
                    lines.append("")
                    lines.append(f"○  <b>Cloudflare:</b>")
                    lines.append(f"⚠️ Cloudflare error (429)")
                else:
                    lines.append("")
                    lines.append(f"⚠️ Cloudflare error")

    # --- RADP ---
    if not radp_error and cloudflare_proceed:
        if radp_source:
            lines.append("")
            lines.append(f"○  <b>Registration ({radp_source}):</b>")
            if radp_country:
                country_flag = get_country_flag(radp_country.strip())
                country_name = get_country_name(radp_country)
                line = f"{country_flag}{radp_country.upper()} {country_name}"
                lines.append(line)
            else:
                country_flag = "🏳"
                line = f"{country_flag} Region not specified"
                lines.append(line)
            if radp_name:
                if radp_website and radp_website.lower() != 'none':
                    name_line = f"<a href='{radp_website.strip()}'>{radp_name.strip()}</a>"
                else:
                    name_line = f"{radp_name.strip()}"
                if radp_aka:
                    name_line += f" / {radp_aka}"
                lines.append(name_line)

    # --- ipregistry (VPN info) ---
    if "security" in ipregistry:
        lines.append("")
        lines.append("○  <b>VPN Info (ipregistry․co):</b>")

        security = ipregistry["security"]

        checks = {
            "Abuser": security.get("is_abuser") or security.get("is_attacker") or security.get("is_threat"),
            "Server": security.get("is_cloud_provider"),
            "Proxy": security.get("is_proxy") or security.get("is_tor") or security.get("is_tor_exit") or security.get("is_anonymous") or security.get("is_relay") or security.get("is_vpn")    
        }

        items = list(checks.items())
        line = ""

        for i, (name, value) in enumerate(items):
            mark = "✅" if value else "❌"
            if i == len(items) - 1:
                line += f"{name}: {mark}"
            else:
                line += f"{name}: {mark}\n"

        lines.append(line)

    if is_domain:
        lines.append(f"----------------")
    
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

    async def doh_query(session: aiohttp.ClientSession, domain: str, doh_url: str, record_type: str) -> list[str]:
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

                tasks = [doh_query(session, domain, doh_url, rt) for rt in record_types]
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

async def process_input(text: str) -> str | None:
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
    
    async def process_ip(ip: str):
        try:
            bogon_desc = get_bogon_description(ip)
            if bogon_desc:
                ip_line, info_text = format_info(is_domain, host, ip, None, None, None, None, None)
                results.append((ip, info_text, ip_line))
                return

            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                maxmind, ipinfo, cloudflare, ipregistry = await asyncio.gather(
                    get_maxmind_info(ip),
                    get_ipinfo_info(ip, session),
                    get_cloudflare_info(ip, session),
                    get_ipregistry_info(ip, session)
                )

                if cloudflare.get("asn_number"):
                    rdap = await get_rdap_info(cloudflare["asn_number"], session)
                else:
                    rdap = {"error": "ASN not found"}

            ip_line, info_text = format_info(
                is_domain, host, ip, maxmind, ipinfo, rdap, cloudflare, ipregistry
            )
            results.append((ip, info_text, ip_line))

        except Exception as e:
            pass

    await asyncio.gather(*(process_ip(ip) for ip in valid_ips))

    results.sort(key=lambda x: (sort_ip(x[0])[0], x[1], sort_ip(x[0])[1]))

    ip_groups = OrderedDict()
    for ip, info_text, ip_line in results:
        ip_groups.setdefault(info_text, []).append(ip_line)

    texts = []
    if is_domain:
        host_lines = build_host_section_text(host, ech_status)
        if host_lines:
            texts.extend(host_lines)
        texts.append("----------------")
        
    for info_text, ip_lines in ip_groups.items():
        texts.append("\n".join(ip_lines))
        texts.append("")
        texts.append(info_text)

    return "\n".join(texts), host

def to_punycode(host: str) -> str:
    try:
        result = host.encode("idna").decode("ascii")
        return result
    except Exception:
        return host


def build_host_section_text(host: str, ech_status: bool = False) -> list[str]:
    lines: list[str] = []
    if not host:
        return lines

    host = host.strip()
    if not host:
        return lines

    if is_ip(host):
        lines.append(f"🔗 <b>Server IP:</b> <code>{host}</code>")
        return lines

    display_host = escape_html(host)
    host_punycode = to_punycode(host)
    ext = tldextract.extract(host_punycode)
    root_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else host_punycode
    tld = ext.suffix.lower()

    match tld:
        case "ru" | "su" | "дети" | "tatar" | "рф":
            whois_link = f"https://whois.tcinet.ru#{root_domain}"
        case "ua":
            whois_link = f"https://www.hostmaster.ua/whois/?_domain={root_domain}"
        case _:
            whois_link = f"https://info.addr.tools/{root_domain}"

    lines.append(f"🔗 <b>Host:</b> {display_host} (<a href='{whois_link}'>Whois</a>?)")
    if ech_status:
        lines.append("🔒 Cloudflare ECH = ON")
    return lines


def build_proxy_section(proxy_info: dict | None, host: str) -> list[str]:
    _ = host  # Host info rendered separately via handler
    if not proxy_info:
        return []

    lines: list[str] = []
    comment_raw = proxy_info.get("comment")
    truncated = bool(proxy_info.get("comment_truncated"))
    comment = (comment_raw or "").strip()
    if truncated or comment:
        if truncated:
            lines.append(
                "⚠️ Proxy comment was truncated due to the inline query limit in Telegram"
            )
        if comment:
            display_comment = comment
            if truncated and not display_comment.endswith("…"):
                display_comment = f"{display_comment}…"
            lines.append(escape_html(display_comment))
        if lines and lines[-1] != "":
            lines.append("")

    protocol = proxy_info.get("protocol") or "proxy"
    details: list[str] = [f"protocol={escape_html(str(protocol))}"]
    for key in ("server", "port", "method", "type", "security", "sni", "host"):
        val = proxy_info.get(key)
        if val is None or val == "":
            continue
        details.append(f"{key}={escape_html(str(val))}")

    lines.append("🔗 Proxy:")
    for detail in details:
        lines.append(f"<code>{detail}</code>")
    return lines


def extract_subscription_links(text: str) -> list[str]:
    if not text:
        return []

    seen: set[str] = set()
    links: list[str] = []
    for match in SUBSCRIPTION_URL_PATTERN.finditer(text):
        candidate = match.group(0).rstrip(TRAILING_PROXY_CHARS)

        if not candidate or candidate in seen:
            continue
        try:
            parsed = urlparse(candidate)
        except Exception:
            continue
        if parsed.scheme not in {"http", "https"}:
            continue
        if not parsed.netloc:
            continue
        if not parsed.path or parsed.path == "/":
            continue
        seen.add(candidate)
        links.append(candidate)
    return links


async def collect_proxy_messages(text: str) -> tuple[list[tuple[str | None, str]], list[tuple[str | None, list[tuple[str | None, str]]]]]:
    direct_entries: list[tuple[str | None, str]] = []
    subscription_entries: list[tuple[str | None, list[tuple[str | None, str]]]] = []
    if not text:
        return direct_entries, subscription_entries

    def render_lines(lines: list[str]) -> str:
        cleaned = [line for line in lines if line is not None]
        return "\n".join(cleaned)

    seen_uris: set[str] = set()
    for uri in extract_proxy_uris(text):
        if uri in seen_uris:
            continue
        seen_uris.add(uri)
        info = parse_proxy_uri(uri)
        host_candidate = ""
        if isinstance(info, dict):
            host_candidate = (info.get("server") or "")
        if not host_candidate:
            host_candidate = urlparse(uri).hostname or ""
        host_candidate = host_candidate.strip()
        lines = build_proxy_section(info, host_candidate)
        if lines:
            direct_entries.append((host_candidate or None, render_lines(lines)))

    if not ENABLE_SUBSCRIPTION_CHECK:
        return direct_entries, subscription_entries

    seen_subscription_urls: set[str] = set()
    for url in extract_subscription_links(text):
        if url in seen_subscription_urls:
            continue
        seen_subscription_urls.add(url)

        parsed_url = urlparse(url)
        subscription_host = (parsed_url.hostname or "").strip() or None
        entry_messages: list[tuple[str | None, str]] = []

        try:
            proxies = await fetch_subscription_proxies(url, OUTBOUND_PROXY)
        except Exception as exc:
            error = escape_html(str(exc))
            entry_messages.append(
                (None, f"⚠️ Failed to fetch subscription {escape_html(url)}: {error}")
            )
            subscription_entries.append((subscription_host, entry_messages))
            continue

        for uri in proxies:
            if uri in seen_uris:
                continue
            seen_uris.add(uri)
            info = parse_proxy_uri(uri)
            host_candidate = ""
            if isinstance(info, dict):
                host_candidate = (info.get("server") or "")
            if not host_candidate:
                host_candidate = urlparse(uri).hostname or ""
            host_candidate = host_candidate.strip()
            section_lines = build_proxy_section(info, host_candidate)
            if section_lines:
                entry_messages.append((host_candidate or None, render_lines(section_lines)))

        subscription_entries.append((subscription_host, entry_messages))

    return direct_entries, subscription_entries



def is_valid_target(item: str) -> bool:
    if item.lower() == "localhost":
        return True

    domain_pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9-]{2,63}$"
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
    domain_pattern = r"\b(?:[a-zA-Z0-9\u00a1-\uffff-]{1,63}\.)+[a-zA-Z\u00a1-\uffff]{2,63}\b"

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
            await message.answer("❌ This file is not in text format.")
            return

    if not text:
        return

    direct_proxy_entries, subscription_entries = await collect_proxy_messages(text)

    text = re.sub("[,'\"!?]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()

    raw_hosts = extract_hosts(text)
    hosts_map = {to_punycode(h): h for h in raw_hosts}
    inputs = list(hosts_map.keys())

    host_results: dict[str, str | None] = {}
    host_sent: set[str] = set()
    sent_any = False

    async def cache_host_result(host_value: str | None) -> str | None:
        if not host_value:
            return None
        value = host_value.strip()
        if not value:
            return None
        puny = to_punycode(value)
        if puny not in host_results:
            if not is_valid_target(puny):
                host_results[puny] = None
            else:
                try:
                    result, _ = await process_input(value)
                except Exception:
                    result = None
                host_results[puny] = result
        return puny

    proxy_host_punys: set[str] = set()
    for proxy_host, _ in direct_proxy_entries:
        if proxy_host:
            puny = to_punycode(proxy_host.strip())
            if puny:
                proxy_host_punys.add(puny)
    for subscription_host, proxy_list in subscription_entries:
        for proxy_host, _ in proxy_list:
            if proxy_host:
                puny = to_punycode(proxy_host.strip())
                if puny:
                    proxy_host_punys.add(puny)

    for puny in inputs:
        await cache_host_result(hosts_map[puny])

    for puny in inputs:
        if puny in proxy_host_punys:
            continue
        result = host_results.get(puny)
        if result and puny not in host_sent:
            await message.answer(result, parse_mode="HTML", disable_web_page_preview=True)
            host_sent.add(puny)
            sent_any = True

    for subscription_host, proxy_list in subscription_entries:
        sub_puny = await cache_host_result(subscription_host)
        sub_result = host_results.get(sub_puny) if sub_puny else None
        if sub_result and sub_puny not in host_sent:
            await message.answer(sub_result, parse_mode="HTML", disable_web_page_preview=True)
            host_sent.add(sub_puny)
            sent_any = True
        for proxy_host, proxy_text in proxy_list:
            proxy_puny = await cache_host_result(proxy_host)
            host_text = host_results.get(proxy_puny) if proxy_puny else None
            if host_text:
                combined = host_text
                if proxy_text:
                    combined = f"{proxy_text}\n\n{host_text}"
                await message.answer(combined, parse_mode="HTML", disable_web_page_preview=True)
                host_sent.add(proxy_puny)
                sent_any = True
            elif proxy_text:
                await message.answer(proxy_text, parse_mode="HTML", disable_web_page_preview=True)
                sent_any = True

    for proxy_host, proxy_text in direct_proxy_entries:
        proxy_puny = await cache_host_result(proxy_host)
        host_text = host_results.get(proxy_puny) if proxy_puny else None
        if host_text:
            combined = host_text
            if proxy_text:
                combined = f"{proxy_text}\n\n{host_text}"
            await message.answer(combined, parse_mode="HTML", disable_web_page_preview=True)
            host_sent.add(proxy_puny)
            sent_any = True
        elif proxy_text:
            await message.answer(proxy_text, parse_mode="HTML", disable_web_page_preview=True)
            sent_any = True

    for puny, result in host_results.items():
        if result and puny not in host_sent:
            await message.answer(result, parse_mode="HTML", disable_web_page_preview=True)
            host_sent.add(puny)
            sent_any = True

    if not sent_any:
        if inputs or subscription_entries or direct_proxy_entries:
            await message.answer("❌ Failed to resolve any IPs/domains.", parse_mode="HTML")
        else:
            await message.answer("❌ No IPs or domains found.")




@dp.inline_query()
async def inline_ip_lookup(query: InlineQuery):
    text = query.query.strip()
    if not text:
        return

    result_text, host = await process_input(text)
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
        logger.error(f"Error while updating geofile {file_path}: {e}")

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
