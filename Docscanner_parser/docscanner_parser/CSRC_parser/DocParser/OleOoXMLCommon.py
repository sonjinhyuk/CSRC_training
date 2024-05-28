import yara
import os
import oletools.msodde
import oletools.olevba
import oletools.oleid
from .. import ip_yara_detect, url_yara_detect
import struct
def convert_string(string: bin) -> str:
    try:
        result = string.decode('utf-8')
    except AttributeError:
        result = string
    except UnicodeDecodeError:
        try:
            result = string.decode('cp949')
        except UnicodeDecodeError:
            result = string

    return str(result)

def full_yara_detect(dpath: str, fpath: str, rules, cve_rules):
    """
        OLE, OOXML file yara detect
        Args:
            :param dpath: directory path
            :param fpath: input file path
            :param rules: yara rules
            :param cve_rules: cve yara rules
        return:
            :return result: detected yara rule
            :return bianry_result: input binary file detected yara rule
            :return cve_result: cve detected yara rule
    """
    result = ''

    file_list = os.listdir(dpath)
    match_data = rules.match(fpath)
    binary_result = '|'.join(list(map(str, match_data)))
    match_data = cve_rules.match(fpath)
    cve_result = '|'.join(list(map(str, match_data)))

    for file in file_list:
        try:
            if file.split('.')[1] == 'json':
                continue
        except IndexError:
            pass

        try:
            match_data = rules.match(f'{dpath}/{file}')
            result += '|'.join(list(map(str, match_data)))
        except yara.Error as ye:
            if file != 'extract':
                print(f'    [\033[31mDebug\033[0m] full_yara_detect (rules.match) \033[91m{ye}\033[0m')
            continue


    return result, binary_result, cve_result

    # vba 가 존재 한다면 extract_macro 를 통해 풀고 각 코드에 대해 저장하고, ip, url, api 정보 파싱

def detect_macro(self) -> None:
    """
        detect macro in VBA
        Args:
        return:
    """
    try:
        vba = oletools.olevba.VBA_Parser(self.fpath)
    except oletools.olevba.FileOpenError:
        return None
    except AttributeError:
        return None

    macro_cnt = 0
    for (file_name, stream_path, vba_name, vba_code) in vba.extract_macros():
        stream_path = stream_path.replace('/', '_')
        if vba_code is None:
            vba_code = "None"
        try:
            with open(f'{self.output_path}/{stream_path}.txt', 'wt', encoding='utf-8') as f:
                f.write(vba_code)
                self.info["detailInfo"]["ipurluriinfo"] += ip_yara_detect(vba_code, self.ip_yara_detect)
                self.info["detailInfo"]["ipurluriinfo"] += url_yara_detect(vba_code, self.url_yara_detect)
            self.info["detailInfo"]["vbascript"] += (f'{self.output_path}/{stream_path}.txt' + '|')
        except TypeError:
            pass
        with open(f'{self.output_path}/{stream_path}.txt', 'rt', encoding='utf-8') as f:
            data = f.readlines()
        for i in data:
            for api in self.api_list:
                if api in i:
                    self.info["detailInfo"]["apilist"] += (api + '|')
        macro_cnt += 1

    self.info["detailInfo"]["numberofvba"] = macro_cnt

    # anaylze_macros 를 사용하면 macro 에 대해 악성인지 의심인지 정상인지 mraptor 알고리즘을 통해 구분해준다.
    try:
        for (type_e, keyword, description) in vba.analyze_macros():
            if 'malicious' in type_e.lower() or 'suspicious' in type_e.lower():
                self.malicious = 1
    except AssertionError:
        self.malicious = 0


def detect_dde(self) -> None:
    """
        check dde in ole file
        Args:
        return:
    """
    dde = ''
    try:
        if self.app == 'doc':
            dde = oletools.msodde.process_doc(self.ole)
        if self.app == 'xls':
            dde = oletools.msodde.process_xls(self.fpath)
    except ValueError:
        print(f'    [\033[31mDebug\033[0m] detect_dde (oletools.msodde.process_{self.app}) \033[91mValueError\033[0m')
    except KeyError:
        print(f'    [\033[31mDebug\033[0m] detect_dde (oletools.msodde.process_{self.app}) \033[91mKeyError\033[0m')
    except struct.error:
        print(f'    [\033[31mDebug\033[0m] detect_dde (oletools.msodde.process_{self.app}) \033[91mstruct.error\033[0m')

    self.info["detailInfo"]["dde"] += dde
