import geoip2.database
import asyncio

from config.variables import MAXMIND_DB_CITY, MAXMIND_DB_ASN
from functools import partial

async def get_maxmind_info(ip: str) -> dict:
    info = {}
    loop = asyncio.get_running_loop()

    def read_city(ip):
        with geoip2.database.Reader(MAXMIND_DB_CITY) as reader:
            city = reader.city(ip)
            return {
                "country": city.country.iso_code,
                "country_name": city.country.name,
                "region": city.subdivisions.most_specific.name,
                "city": city.city.name,
            }

    def read_asn(ip):
        with geoip2.database.Reader(MAXMIND_DB_ASN) as reader:
            asn = reader.asn(ip)
            return {
                "asn_number": asn.autonomous_system_number,
                "asn_org": asn.autonomous_system_organization,
            }

    city_task = loop.run_in_executor(None, partial(read_city, ip))
    asn_task = loop.run_in_executor(None, partial(read_asn, ip))

    results = await asyncio.gather(city_task, asn_task, return_exceptions=True)

    if isinstance(results[0], Exception):
        info["city_error"] = str(results[0])
    else:
        info.update(results[0])

    if isinstance(results[1], Exception):
        info["asn_error"] = str(results[1])
    else:
        info.update(results[1])

    return info