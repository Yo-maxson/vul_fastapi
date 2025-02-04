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
            print('error find score')
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


def get_cve_info(cve_names):
    
    # logger_upd_cve = setup_logger('upd_cve_py', '/home/yo_maxson/Projects/tests/fastapi_test/logging/upd_cve_py.log')
    all_cve = []
    print(cve_names)
    for cve_name in cve_names:
        print(cve_name)
        # url = "https://www.cve.org/api/?action=getCveById&cveId="
        link = f"https://cveawg.mitre.org/api/cve/{cve_name}"
        answer = requests.get(link)
        print(link)
        result = answer.json()
        print(f"result: {result}")
        if result is None or 'error' in result:
            print('no result')
            continue

        try:
            result['cveMetadata']
            print(result)
        except:
            print(result)
            print('no response')
            continue
        time.sleep(1)
        # dict_cve = {'Идентификатор': '', 'Описание': 'Отсутствует', 'Описание рус': 'Отсутствует',
        #             'Оценка (CVSS v3)': 0,
        #             'Ссылка': 'Отсутствует', 'Ссылка на БДУ': 'Отсутствует', 'наличие ссылки БДУ': 'Отсутствует',
        #             'CWE': {'n/a': 'n/a'},'Описание CWE': {'n/a': 'n/a'}, 'вектор': 'Отсутствует', 'Дата резервирования': None, 'Дата публикации': None,
        #             'Дата обновления': None, 'Вендор': 'Отсутствует', 'Продукт': 'Отсутствует', 'Версия': 'Отсутствует',
        #             'Возможные меры по устранению': 'Отсутствует', 'REJECTED': None}
        dict_cve = {'Идентификатор': '', 'Описание': 'Отсутствует', 'Описание рус': 'Отсутствует',
                    'Оценка (CVSS v3)': 0,
                    'Ссылка': 'Отсутствует', 'Ссылка на БДУ': 'Отсутствует', 'наличие ссылки БДУ': 'Отсутствует',
                    'CWE': 'n/a', 'вектор': 'Отсутствует', 'Дата резервирования': None, 'Дата публикации': None,
                    'Дата обновления': None, 'Вендор': 'Отсутствует', 'Продукт': 'Отсутствует', 'Версия': 'Отсутствует',
                    'Возможные меры по устранению': 'Отсутствует', 'Описание CWE': 'Отсутствует', 'REJECTED': False}
        resp = 0
        try:
            link_cve = f'https://www.cve.org/CVERecord?id={cve_name}' #main link
            dict_cve['Идентификатор'] = cve_name
            dict_cve['Ссылка'] = link_cve
        except Exception as e:
            continue
        try:
            response = requests.get(link).json()
            prod_list = []
            vers_list = []
            st_code = 0
            resp_err = 0
            resp_glob = 0
            print('Find in second link')
            url_test = "hhttps://cveawg.mitre.org/api/cve/"
            url_test = url_test + cve_name
            print(f"{len(response)}--{response}")
            while resp < 6:
                try:
                    print(f'go link {resp}')
                    time.sleep(3)
                    MAX_RETRIES = 10
                    session = requests.Session()
                    adapter = requests.adapters.HTTPAdapter(max_retries=MAX_RETRIES)
                    session.mount('https://', adapter)
                    session.mount('http://', adapter)
                    answer = requests.get(link) #, headers=headers, timeout=120)
                    print(f"answer --> {answer}")
                    response = answer.json()

                    print('ready link')
                    break
                except Exception as e:
                    # tb.send_message(troubles, f'#131Add_reserved_CVE Something wrong with response reserved parsing ({rev}) --> {str(e)}')
                    print(f'#Add_reserved_CVE Something wrong with response reserved parsing ({cve_name}) -statuse_code {st_code}-> {str(e)}')
                    resp_err += 1
                    resp += 1
                    resp_glob += 1
                if resp > 6:
                    
                    print(
                        f'#Add_reserved_CVE Something wrong with response reserved parsing не удалось подключиться к {cve_name} --> {str(e)}')
                    continue
            print('go response')
            time.sleep(1)
            if response['cveMetadata']:
                print(response)
            else:
                print('no response')
                continue
            time.sleep(1)

            try:
                if 'REJECTED' in response['cveMetadata']['state']:
                    dict_cve['REJECTED'] = True
                    print('rejected detected-->', response['cveMetadata']['dateRejected'])
                    return dict_cve
            except:
                print('error')
                pass
            # try:
            #     if 'error' in response or 'error' in response_test:
            #         print(f"In {cve_name} --> {response['error']}")
            #         continue
            # except Exception as e:
            #     print(f'Error {cve_name} find error in json --> {e}')
            if 'error' in response:
                print('error find')
                return dict_cve
            else:
                try:
                    dict_cve['Вендор'] = response['containers']['cna']['affected'][0]['vendor']
                except:
                    pass
                #Продукт
                try:
                    for prod in response['containers']['cna']['affected']:
                        vers_str = ''
                        first = True
                        prod_list.append(prod['product'])
                        for vers in prod['versions']:
                            if first:
                                vers_str += f"{vers['version']}"
                                first = False
                            else:
                                vers_str += f", {vers['version']}"
                        # vers_str = f"для {vers_str}({prod['product'].strip()})"
                        vers_list.append(vers_str)
                    prod_str = '; '.join(prod_list)
                    vers_str = '; '.join(vers_list)
                    dict_cve['Продукт'] = prod_str
                    dict_cve['Версия'] = vers_str
                except:
                    pass
                # Дата публикации
                try:
                    date_public = response['cveMetadata']['datePublished']
                    date_public_list = date_public.split('T')
                    date_public = date_public_list[0]
                    dict_cve['Дата публикации'] = date_public
                except:
                    dict_cve['Дата публикации'] = response['cveMetadata']['dateUpdated']
                try:
                    date_upd = response['cveMetadata']['dateUpdated']
                    date_upd_list = date_upd.split('T')
                    date_upd = date_upd_list[0]
                    dict_cve['Дата обновления'] = date_upd
                except:
                    date_public = response['cveMetadata']['datePublished']
                    date_public_list = date_public.split('T')
                    date_public = date_public_list[0]
                    dict_cve['Дата обновления'] = date_public
                try:
                    date_reserv = response['cveMetadata']['dateReserved']
                    date_reserv_list = date_reserv.split('T')
                    date_reserv = date_reserv_list[0]
                    dict_cve['Дата резервирования'] = date_reserv
                except:
                    pass
                try:
                    dict_cve['Описание'] = response['containers']['cna']['descriptions'][0]['value']
                except:
                    try:
                        dict_cve['Описание'] = response['containers']['cna']['x_legacyV4Record']['description']['description_data'][0]['value']
                    except:
                        dict_cve['Описание'] = 'Отсутствует'
                cwe_dict = {}
                # Скор CVSS
                try:
                    dict_cve['Оценка (CVSS v3)'] = float(response['containers']['cna']['metrics'][0]['cvssV3_0']['baseScore'])
                    no_cvss_str = response['containers']['cna']['metrics'][0]['cvssV3_0']['vectorString']
                    dict_cve['вектор'] = no_cvss_str
                except:
                    try:
                        dict_cve['Оценка (CVSS v3)'] = float(
                            response['containers']['cna']['metrics'][0]['cvssV3_1']['baseScore'])
                        no_cvss_str = response['containers']['cna']['metrics'][0]['cvssV3_1']['vectorString']
                        dict_cve['вектор'] = no_cvss_str
                    except:
                        dict_cve['Оценка (CVSS v3)'] = float(0)
                #CWE
                try:
                    for cwe in range(len(response['containers']['cna']['problemTypes'])):
                        try:
                            cwe_dict[response['containers']['cna']['problemTypes'][cwe]['cweId']] = \
                                response['containers']['cna']['problemTypes'][cwe]['description']
                        except:
                            try:
                                cwe_dict[
                                    response['containers']['cna']['problemTypes'][cwe]['descriptions'][0]['cweId']] = \
                                    response['containers']['cna']['problemTypes'][cwe]['descriptions'][0]['description']
                            except:
                                cwe_dict['n/a'] = 'n/a'
                                break
                except:
                    cwe_dict['n/a'] = 'n/a'
                dict_cve['CWE'] = cwe_dict
                dict_cve['Описание CWE'] = cwe_dict
                #Рекомендации
                try:
                    dict_cve['Возможные меры по устранению'] = response['x_legacyV4Record']['references'][0][
                        'reference_data']
                except:
                    try:
                        url_rec = []
                        re = response['containers']['cna']['references']
                        for url in re:
                            url_rec.append(url['url'])
                        url_rec_str = ', '.join(url_rec)
                        dict_cve['Возможные меры по устранению'] = url_rec_str
                    except:
                        dict_cve['Возможные меры по устранению'] = 'n/a'
        except Exception as e:
            print('error', e)
            # logger_upd_cve.critical(f"Ошибка в обновлении CVE -- {cve_name}-->\n<--{e}")
            print(f"Ошибка в обновлении CVE -- {cve_name}-->\n<--{e}")
            continue
        print('<----------->')
        print('<------->')
        print(dict_cve)     
        print('<------->')
        print('<----------->')
        time.sleep(1)
        all_cve.append(dict_cve)
        json_string = json.dumps(all_cve)
    with open('data_cve.json', 'w', encoding='utf-8') as file:
        json.dump(all_cve, file, ensure_ascii=False)

    return all_cve



def test_request(cve_name):
    for cve_one in cve_name:
        try:
            print('start 1')
            url = "https://www.cve.org/api/?action=getCveById&cveId="  # https://cveawg.mitre.org/api/cve/CVE-2022-44576
            url = url + cve_one
            MAX_RETRIES = 10
            session = requests.Session()
            adapter = requests.adapters.HTTPAdapter(max_retries=MAX_RETRIES)
            session.mount('https://', adapter)
            session.mount('http://', adapter)
            answer = requests.get(url)#, timeout=60)
            print(1)
            if 'json' in answer.headers.get('Content-Type'):
                response = answer.json()
                print(response.status_code)
            else:
                print('Response content is not in JSON format.')
                print(answer.status_code)
            # if 'error' in response:
            #     print(response)
            #     print('end 1')
        except Exception as e: #except JSONDecodeError
            print(f"Error 1 -->{e}")
        try:
            print('start 2')
            url_test = "https://cveawg.mitre.org/api/cve/"
            url_test = url_test + cve_one
            MAX_RETRIES = 10
            session = requests.Session()
            adapter = requests.adapters.HTTPAdapter(max_retries=MAX_RETRIES)
            session.mount('https://', adapter)
            session.mount('http://', adapter)
            answer = requests.get(url_test)  # , timeout=60)
            response_test = answer.json()
            print('end 2')
            
            print()
            print(2)
            if 'error' in response_test:
                print(response_test)
        except Exception as e:
            print(f"Error 2-->{e}")

# CVE-2022-47549 CVE-2023-23397 CVE-2023-3089
# result = get_cve_info('CVE-2023-46294')
# result = get_cve_info(['CVE-2022-14262', 'CVE-2023-5730', 'CVE-2022-47549', 'CVE-2023-23397', 'CVE-2023-3089', 'CVE-2023-46294'])

# result = get_cve_info(['CVE-2022-47549', 'CVE-2022-14262', 'CVE-2023-5730', 'CVE-2022-47549', 'CVE-2023-23397',
#                           'CVE-2023-3089', 'CVE-2023-46294'])
# print()
# print(result)
# print(input())
# result = get_cve_info('CVE-2023-3089')



# get_cve_info(['CVE-2022-47549', 'CVE-2022-14262', 'CVE-2023-5730', 'CVE-2022-47549', 'CVE-2023-23397', 'CVE-2023-3089', 'CVE-2023-46294'])
# result = get_cve_info('CVE-2022-47549')
# result = get_cve_info('CVE-2022-47549')
# result = get_cve_info('CVE-2023-23397')
# print(result)
# for i in result:
#     print(f"{i}->{result[i]}")
# test_data = {'Идентификатор': 'CVE-2023-3089',
#            'Описание': 'A compliance problem was found in the Red Hat OpenShift Container Platform. Red Hat discovered that, when FIPS mode was enabled, not all of the cryptographic modules in use were FIPS-validated.',
#            'Описание рус': 'Отсутствует',
#            'Оценка (CVSS v3)': 0.0,
#            'Ссылка': 'https://www.cve.org/CVERecord?id=CVE-2023-3089',
#            'Ссылка на БДУ': 'Отсутствует',
#            'наличие ссылки БДУ': 'Отсутствует',
#            'CWE': {'CWE-693': 'Protection Mechanism Failure'},
#            'вектор': 'Отсутствует',
#            'Дата резервирования': '2023-06-03',
#            'Дата публикации': '2023-07-05',
#            'Дата обновления': '2023-07-05',
#            'Вендор': 'n/a',
#            'Продукт': 'Отсутствует',
#            'Версия': 'Отсутствует',
#            'Возможные меры по устранению': 'https://access.redhat.com/security/cve/CVE-2023-3089, https://bugzilla.redhat.com/show_bug.cgi?id=2212085',
#            'Описание CWE': {'CWE-693': 'Protection Mechanism Failure'},
#           'REJECTED': False}