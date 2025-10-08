import geoip2.database
import asyncio
import os
from functools import partial
from config.variables import MAXMIND_DB_CITY, MAXMIND_DB_ASN


async def get_maxmind_info(ip: str) -> dict:
    info = {}
    loop = asyncio.get_running_loop()

    def read_city(ip):
        if not os.path.exists(MAXMIND_DB_CITY):
            raise FileNotFoundError(f"City DB not found: {MAXMIND_DB_CITY}")
            
        with geoip2.database.Reader(MAXMIND_DB_CITY) as reader:
            city = reader.city(ip)
            return {
                "country": city.country.iso_code,
                "country_name": city.country.name,
                "region": city.subdivisions.most_specific.name,
                "city": city.city.name,
            }

    def read_asn(ip):
        if not os.path.exists(MAXMIND_DB_ASN):
            raise FileNotFoundError(f"ASN DB not found: {MAXMIND_DB_ASN}")
            
        with geoip2.database.Reader(MAXMIND_DB_ASN) as reader:
            asn = reader.asn(ip)
            return {
                "asn_number": asn.autonomous_system_number,
                "asn_org": asn.autonomous_system_organization,
            }

    city_task = loop.run_in_executor(None, partial(read_city, ip))
    asn_task = loop.run_in_executor(None, partial(read_asn, ip))

    results = await asyncio.gather(city_task, asn_task, return_exceptions=True)

    errors = []

    if isinstance(results[0], Exception):
        errors.append(f"City DB error: {results[0]}")
    else:
        info.update(results[0])

    if isinstance(results[1], Exception):
        errors.append(f"ASN DB error: {results[1]}")
    else:
        info.update(results[1])

    if errors:
        info["error"] = "; ".join(errors)

    return info
