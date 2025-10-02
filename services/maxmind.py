import geoip2.database
import asyncio

from config.variables import MAXMIND_DB_CITY
from config.variables import MAXMIND_DB_ASN

async def get_maxmind_info(ip: str) -> dict:
    info = {}
    try:
        with geoip2.database.Reader(MAXMIND_DB_CITY) as city_reader:
            city = city_reader.city(ip)
            info.update({
                "country": city.country.iso_code,
                "country_name": city.country.name,
                "region": city.subdivisions.most_specific.name,
                "city": city.city.name,
            })
    except Exception as e:
        info["city_error"] = str(e)

    try:
        with geoip2.database.Reader(MAXMIND_DB_ASN) as asn_reader:
            asn = asn_reader.asn(ip)
            info.update({
                "asn_number": asn.autonomous_system_number,
                "asn_org": asn.autonomous_system_organization,
            })
    except Exception as e:
        info["asn_error"] = str(e)
    
    return info