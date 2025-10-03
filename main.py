import ipaddress
import socket
import aiohttp
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

from services.cloudflare import get_cloudflare_info
from services.maxmind import get_maxmind_info
from services.ipinfo import get_ipinfo_info
from services.rdap import get_rdap_info
from services.ipregistry import get_ipregistry_info


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
    
def format_info(is_domain: bool, host: str, ip: str, maxmind: dict, ipinfo: dict, radp: dict, cloudflare: dict, ipregistry: dict) -> tuple[str, str]:
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
    
    if "error" not in maxmind:
        lines.append(f"○  <b>MaxMind:</b>")
        if maxmind.get("country"):
            country_flag = get_country_flag(maxmind.get("country").strip())
            country_name = get_country_name(maxmind['country'])
            line = f"{country_flag}{maxmind['country']} {country_name}"
            if maxmind.get("region"):
                line += f", {maxmind['region']}"
            if maxmind.get("city") and maxmind.get("city") != maxmind.get("region"):
                line += f", {maxmind['city']}"
            lines.append(line)
        else:
            country_flag = "🏳"
            line = f"{country_flag} Region not specified"
            lines.append(line)
        if maxmind.get("asn_number"):
            asn_line = f"AS{maxmind['asn_number']}"
            if maxmind.get("asn_org"):
                asn_line += f" / {maxmind['asn_org']}"
            lines.append(asn_line)
    else:
        lines.append("")
        lines.append(f"⚠️ MaxMind error")

    if "error" not in ipinfo:
        lines.append("")
        lines.append(f"○  <b>IPinfo:</b>")
        if ipinfo.get("country"):
            country_flag = get_country_flag(ipinfo.get("country").strip())
            country_name = get_country_name(ipinfo['country'])
            line = f"{country_flag}{ipinfo['country']}"
            if ipinfo['country'].strip().upper() != country_name.strip().upper():
                line += f" {country_name}"
            if ipinfo.get("region"):
                line += f", {ipinfo['region']}"
            if ipinfo.get("city") and ipinfo.get("city") != ipinfo.get("region"):
                line += f", {ipinfo['city']}"
            lines.append(line)
        if ipinfo.get("asn_number"):
            asn_line = f"{ipinfo['asn_number']}"
            if ipinfo.get("asn_org"):
                asn_line += f" / {ipinfo['asn_org']}"
            lines.append(asn_line)
    else:
        if str(ipinfo['error']) == "HTTP 429":
            lines.append("")
            lines.append(f"○  <b>Ipinfo:</b>")
            lines.append(f"Too Many Requests, please wait")
        else:
            lines.append("")
            lines.append(f"⚠️ Ipinfo error")
    
    cloudflare_poreceed = False
    
    if "request_error" not in cloudflare and "error" not in cloudflare:
        cloudflare_poreceed = True
        lines.append("")
        lines.append(f"○  <b>Cloudflare:</b>")
        if cloudflare.get("country"):
            country_flag = get_country_flag(cloudflare.get("country").strip())
            country_name = get_country_name(cloudflare['country'])
            line = f"{country_flag}{cloudflare['country']}"
            if cloudflare['country'].strip().upper() != country_name.strip().upper():
                line += f" {country_name}"
            lines.append(line)
        if cloudflare.get("asn_number"):
            if cloudflare['asn_number'] != "0":
                asn_line = f"AS{cloudflare['asn_number']}"
                if cloudflare.get("asn_org"):
                    asn_line += f" / {cloudflare['asn_org']}"
                lines.append(asn_line)
    else:
        if str(cloudflare.get("request_error", cloudflare.get("error"))) == "HTTP 429":
            lines.append("")
            lines.append(f"○  <b>Cloudflare:</b>")
            lines.append(f"Too Many Requests, please wait")
        else:
            lines.append("")
            lines.append(f"⚠️ Cloudflare error")

    
    if "error" not in radp and cloudflare_poreceed:
        lines.append("")
        if radp.get("source"):
            lines.append(f"○  <b>Registration ({radp['source']}):</b>")
            if radp.get("country"):
                country_flag = get_country_flag(radp.get("country").strip())
                country_name = get_country_name(radp['country'])
                line = f"{country_flag}{radp['country'].upper()} {country_name}"
                lines.append(line)
            else:
                country_flag = "🏳"
                line = f"{country_flag} Region not specified"
                lines.append(line)
            if radp.get("name"):
                website = radp.get('website')
                if website and website.lower() != 'none':
                    name = radp['name'].strip()
                    link = radp['website'].strip()
                    name_line = f"<a href='{link}'>{name}</a>"
                else:
                    name_line = f"{radp['name'].strip()}"
                if radp.get("aka"):
                    name_line += f" / {radp['aka']}"
                #if radp.get("org"):
                #    name_line += f" / {radp['org']}"
                lines.append(name_line)
    

    if "security" in ipregistry:
        lines.append("")
        lines.append("○  <b>VPN Info (ipregistry․co):</b>")

        security = ipregistry["security"]

        checks = {
            "Malicious": security.get("is_abuser") or security.get("is_attacker") or security.get("is_threat"),
            "Server": security.get("is_cloud_provider") or security.get("is_relay"),
            "Proxy": security.get("is_proxy") or security.get("is_tor") or security.get("is_tor_exit") or security.get("is_anonymous"),
            "VPN": security.get("is_vpn")
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
    ipv4_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    ipv6_pattern = r"\b(?:[A-Fa-f0-9:]+:+)+[A-Fa-f0-9]+\b"
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

    text = re.sub(r"[,'\"!?]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    
    raw_hosts = extract_hosts(text)
    hosts_map = {to_punycode(h): h for h in raw_hosts}
    inputs = list(hosts_map.keys())

    if not inputs:
        await message.answer("❌ No IPs or domains found.")
        return

    found = False
    seen = set()
    for punycode_host in inputs:
        if not is_valid_target(punycode_host):
            continue

        original_host = hosts_map[punycode_host]

        try:
            result, host = await process_input(original_host)
        except Exception:
            continue

        if result and result not in seen:
            found = True
            seen.add(result)
            await message.answer(result, parse_mode="HTML", disable_web_page_preview=True)

    if not found:
        await message.answer("❌ Failed to resolve any IPs/domains.", parse_mode="HTML")

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