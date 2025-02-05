import requests
#24.10.2022

import time
#31.10.2022
import json
import logging
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')

def setup_logger(name, log_file, level=logging.INFO):
    """To setup as many loggers as you want"""

    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger

def get_cve_info_one(cve_name):
    dict_cve = {"name": None, "baseScore": 0.0, "vectorString_v3": None, "link": None, "publicated": False,
                "datePublished": None, "dateUpdated": None}

    # url = "https://www.cve.org/api/?action=getCveById&cveId="
    link = f"https://cveawg.mitre.org/api/cve/{cve_name}"
    answer = requests.get(link)
    result = answer.json()
    print(f"result: {result}")
    dict_cve['name'] = cve_name
    dict_cve['link'] = f'https://www.cve.org/CVERecord?id={cve_name}'

    if result is None or 'error' in result:
        print('no json')
        return dict_cve
    if 'REJECTED' in result['cveMetadata']['state']:
        print('rejected detected-->', result['cveMetadata']['dateRejected'])
        return dict_cve
    try:
        dict_cve['baseScore'] = float(result['containers']['cna']['metrics'][0]['cvssV3_0']['baseScore'])
        no_cvss_str = result['containers']['cna']['metrics'][0]['cvssV3_0']['vectorString']
        dict_cve['vectorString_v3'] = no_cvss_str
    except:
        try:
            dict_cve['baseScore'] = float(
                result['containers']['cna']['metrics'][0]['cvssV3_1']['baseScore'])
            no_cvss_str = result['containers']['cna']['metrics'][0]['cvssV3_1']['vectorString']
            dict_cve['vectorString_v3'] = no_cvss_str
        except:
            try:
                dict_cve['baseScore'] = float(result['containers']['adp'][0]['metrics'][0]['cvssV3_1']['baseScore'])
                dict_cve['vectorString_v3'] = result['containers']['adp'][0]['metrics'][0]['cvssV3_1']['vectorString']
            except:
                print('error score in cna and adp')
    dict_cve['publicated'] = True
    try:
        date_public = result['cveMetadata']['datePublished']
        date_public_list = date_public.split('T')
        date_public = date_public_list[0]
        dict_cve['datePublished'] = date_public
    except:
        dict_cve['datePublished'] = result['cveMetadata']['dateUpdated']
    try:
        date_upd = result['cveMetadata']['dateUpdated']
        date_upd_list = date_upd.split('T')
        date_upd = date_upd_list[0]
        dict_cve['dateUpdated'] = date_upd
    except:
        date_public = result['cveMetadata']['datePublished']
        date_public_list = date_public.split('T')
        date_public = date_public_list[0]
        dict_cve['dateUpdated'] = date_public

    dict_cve_t = {
        "name": "CVE-2025-0435",
        "baseScore": 6.5,
        "vectorString_v3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        "link": "https://www.cve.org/CVERecord?id=CVE-2025-0435",
        "publicated": True,
        "datePublished": "2025-01-15",
        "dateUpdated": "2025-01-15"
    }
    return dict_cve_t
