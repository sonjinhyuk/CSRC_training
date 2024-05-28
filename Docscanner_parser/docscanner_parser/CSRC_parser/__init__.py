import json
import hashlib
import zlib
import regex as re
import ipinfo
import os
from pathlib import Path
decompile_size = 15000

BASE_DIR = Path(__file__).resolve().parent
SETTING_JSON = f"{os.path.join(BASE_DIR)}\\resource\\setting.json"

# def preprocessing(self, info_type = "pdfInfo"):
#     self.info['basicInfo']['b_id'], self.info['basicInfo']['f_id'] = get_bfid(self.file_type_id, self.file_type)
#     self.info[info_type]['f_id'] = self.info['basicInfo']['f_id']


def get_setting(key):
    """
        file save
        Args:
             :param key str: json resource key
        return:
            :return : get resource value
    """
    with open(SETTING_JSON, 'rt') as f:
        temp_set = json.load(f)
    return temp_set[key]

def get_hash(path: str) -> tuple:
    """
        get hash value
        Args:
            :param path: input file
        return:
            :return sha256: sha256 value
            :return md5: md5 value
    """
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except TypeError:
        data = path
    except ValueError:
        data = path
    except FileNotFoundError:
        data = path

    return hashlib.sha256(data).hexdigest().upper(), hashlib.md5(data).hexdigest().upper()


def valid_ip_addr(ip_addr: str) -> bool:
    if ip_addr.split('.')[0] == '192' and ip_addr.split('.')[1] == '168':
        return False
    elif ip_addr.split('.')[0] == '172' and (16 <= int(ip_addr.split('.')[1]) or int(ip_addr.split('.')[1]) <= 31):
        return False
    elif ip_addr.split('.')[0] == '10':
        return False
    else:
        return True


def get_ipinfo(ip_addr: str) -> str:
    ipinfo_token = "bf882c1cc85e28"
    handler = ipinfo.getHandler(ipinfo_token).getDetails(ip_addr)
    return f'{handler.country}.{ip_addr}.{handler.city}'


def ip_yara_detect(data: bin, rules=None) -> str:
    result = ''
    prev_offset = -1
    try:
        ip_matches = rules.match(data=data)

        if len(ip_matches) != 0:
            for idx, i in enumerate(ip_matches[0].strings):
                if idx == 0:
                    prev_offset = i[0] + len(i[2].decode())
                else:
                    if i[0] < prev_offset:
                        continue
                    prev_offset = i[0] + len(i[2].decode())
                ip_addr = '.'.join(
                    [''.join([chr(c) for c in data if chr(c) != '\x00']) for data in i[2].split(b'.')])

                if valid_ip_addr(ip_addr):
                    result += get_ipinfo(ip_addr)
    except Exception as e:
        pass

    return result



def url_yara_detect(data: bin, rules=None) -> str:
    result = ''
    prev_offset = -1
    try:
        url_matches = rules.match(data=data)

        if len(url_matches) != 0:
            for idx, i in enumerate(url_matches[0].strings):
                if idx == 0:
                    prev_offset = i[0] + len(i[2].decode())
                else:
                    if i[0] < prev_offset:
                        continue
                    prev_offset = i[0] + len(i[2].decode())

                if 'microsoft.com' not in i[2].decode():
                    result += (i[2].decode() + '|')
    except Exception as e:
        pass

    return result

import os
import yara
def full_yara_detect(dpath: str, fpath, rules) -> str:
    result = ''
    file_list = os.listdir(dpath)
    match_data = rules.match(fpath)
    if len(match_data):
        for i in range(len(match_data)):
            meta_description = match_data[i].meta
            if meta_description.get('description') is not None:
                message = meta_description.get('description')
            elif meta_description.get('Description') is not None:
                message = meta_description.get('Description')
            elif meta_description.get('desc') is not None:
                message = meta_description.get('desc')
            elif meta_description.get('Desc') is not None:
                message = meta_description.get('Desc')
            else:
                message = meta_description
            result += str(message) + '|'

    for file in file_list:
        try:
            if file.split('.')[1] == 'json':
                continue
        except IndexError:
            continue
        try:
            match_data = rules.match(f'{dpath}/{file}')
        except yara.Error:
            continue

        if len(match_data):
            for i in range(len(match_data)):
                meta_description = match_data[i].meta
                if meta_description.get('description') is not None:
                    message = meta_description.get('description')
                elif meta_description.get('Description') is not None:
                    message = meta_description.get('Description')
                elif meta_description.get('desc') is not None:
                    message = meta_description.get('desc')
                elif meta_description.get('Desc') is not None:
                    message = meta_description.get('Desc')
                else:
                    message = meta_description
                result += str(message) + '|'
    return result

def stream_read(ole, content, decomplie=True):
    # BinData 스토리지의 스트림 파일에 디컴프레스 할 데이터가 없을 경우
    stream_data = ole.openstream(content)
    data2 = stream_data.read()
    zobj = zlib.decompressobj(-1 * zlib.MAX_WBITS)
    r_data = data2
    try:
        if decomplie:
            r_data = zobj.decompress(data2)
    except zlib.error:
        pass
    return r_data

def get_regex(keyword, regex):
    if keyword == "domain":
        regex = ["([a-z0-9\w]+\.*)+[a-z0-9]{2,4}([\/a-z0-9-%#?&=\w])+(\.[a-z0-9]{2,4}(\?[\/a-z0-9-%#?&=\w]+)*)*"]
    elif keyword == "filepath":
        regex = ["^((?:\/[a-zA-Z0-9]+(?:_[a-zA-Z0-9]+)*(?:\-[a-zA-Z0-9]+)*(?:.+))+)",
                 # "^[a-zA-Z]:(\\([_a-zA-Z0-9가-힣]+))+\\"]
                 "^[a-zA-Z]:"]
    elif keyword == "ascii":
        regex = ["([`~!@#$%^&*()-_=+][0-9][0-9A-z]{0,1}){2,}"]

    return regex


def find_all(regex, stream, series, scdbg=False):
    def i_if(expr, truepart, falsepart):
        if expr:
            return truepart
        else:
            return falsepart

    keyword = None
    if regex == "domain" or regex == "http" or regex == "filepath" or regex == "ascii":
        stream_length = len(stream)
        keyword = regex
        regexs = get_regex(keyword, None)
        find_results = []
        threshold = 50000
        if stream_length < threshold or keyword != "domain":
            for regex in regexs:
                find_results.append(re.findall(regex, stream, i_if(False, 0, re.I)))
            find_result = []
            for result in find_results:
                find_result.append(result)
        else:
            find_result = []
    else:
        find_result = re.findall(regex, stream, i_if(False, 0, re.I))

    if len(find_result) == 0:
        return False
    if scdbg:
        multistream = re.compile('<(.*?)>', re.S)
        for i, s in enumerate(re.findall(multistream, stream)):
            if len(s) > decompile_size:
                try:
                    series["length".lower()] += 1
                except KeyError:
                    pass
                # shellcode_excute = sp.getstatusoutput(shellcode_excute)
    else:
        if "exec|" in regex:
            regex_split = regex.split("|")
            if regex_split[0] in find_result and regex_split[1] in find_result:
                series["|".join(regex_split)] += 1
        else:
            for find in find_result:
                try:
                    series[find.lower()] += 1
                except KeyError:
                    # print(find)
                    pass
                except AttributeError:
                    series[keyword] += 1

def search_all(data, return_series, regexs):
    find_all(regexs[0], data, return_series)
    find_all(regexs[1], data, return_series, True)
    for regex in regexs[2:]:
        find_all(regex, data, return_series)

    for number, data in enumerate(data):
        if ('==' in data) and ('1 get closefile quit' not in data):
            return_series["Base64".lower()] += 1

from datetime import datetime
def get_current_date() -> str:
    date_format = "%Y-%m-%d %H:%M:%S.%f"
    return datetime.now().strftime(date_format)
