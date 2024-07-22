import os

from .. import get_setting, ip_yara_detect, url_yara_detect, get_current_date, search_all, stream_read
from CSRC_parser import get_setting, ip_yara_detect, url_yara_detect, get_current_date, search_all, stream_read
import olefile
import regex
import yara
import json
from CSRC_parser import get_setting
from .OleOoXMLCommon import full_yara_detect, convert_string, detect_macro, detect_dde
import oletools.msodde
import oletools.olevba
import oletools.oleid
import pandas as pd
import zlib
from .regex_def import *
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
YARA_DIR = f'{os.path.join(BASE_DIR)}\\resource\\csrc_YARA\\'

class OleParser:
    """
        MS-Office not extend version Parser Class
        MS-Office not extend version Parsing and get AI model input data
    """
    def __init__(self, file: str, app: str, source_file_name:str = None, output_dir:str = None,
                 file_type: str=None, sha256:str = None, md5: str=None) -> None:
        """
           Preprocessing based on file type and insert DB
           Args:
               :param file: input file
               :param app: file type
               :param source_file_name: input file source name
               :param output_dir: output directory
               :param file_type: file type
               :param dict: input file
               :param sha256: input file sha256 value
               :param md5: input file md5 value
           return:
       """
        self.sha256 = sha256
        self.md5 = md5
        self.fpath = str(file)
        self.file_type = file_type
        self.output_path = output_dir
        self.source_file_name = source_file_name
        self.api_list = get_setting('api_list')
        self.app = app
        self.info = get_setting('form')
        self.ole_keylist = get_setting('ole_keylist')
        self.ole = olefile.OleFileIO(self.fpath)
        self.vbaExists = False
        self.malicious = False
        self.yara_rule = yara.compile(YARA_DIR + get_setting('mz_yara'))
        self.cve_rule = yara.compile(YARA_DIR + get_setting('cve_yara'))
        self.ole_yara = yara.compile(YARA_DIR + get_setting('ole_yara'))
        self.ip_yara_detect = yara.compile(YARA_DIR + get_setting('ip_yara_detect'))
        self.url_yara_detect = yara.compile(YARA_DIR + get_setting('url_yara_detect'))
        self.current = get_current_date()
        self.regexs = set_regex(self.ole_keylist, "OLE")
        self.compress_count = 0
        df_columns = ['file_name']
        for okey in self.ole_keylist:
            df_columns.append(okey.lower())
        _data = [self.source_file_name]
        _data += [0 for _ in self.ole_keylist]
        _data = pd.Series(_data, index=df_columns)
        self.model_input = _data
        self.info = pd.DataFrame(self.info)
        self.run()

    def run(self) -> None:
        """
            OLE file parsing and get AI model input data
            Args:
            return:
        """
        start_time = int(time.time() * 1000)
        model_input = self.model_input
        self.info["detailInfo"]["isencrypt"] = 0
        self.info["basicInfo"]["sourcefilename"] = self.source_file_name
        self.info["basicInfo"]["sha256"] = self.sha256
        self.info["basicInfo"]["md5"] = self.md5
        self.info["detailInfo"]["detail_type"] = self.file_type
        self.basic_info()
        self.detect_script()

        if self.vbaExists:
            detect_macro(self)
            model_input['vba'] = 1

        stream_list = self.ole.listdir()
        self.info["detailInfo"]["findmzstreampath"] = self.mz_yara_detect(stream_list)
        if self.app != 'ppt':
            detect_dde(self)
            search_all(self.info["detailInfo"]["dde"], self.model_input, self.regexs)


        ## reulst yara detect
        result, binary_result, cve_result = full_yara_detect(f'{self.output_path}', self.fpath, self.ole_yara, self.cve_rule)
        self.info["detailInfo"]["yaradetect"] = result
        self.info["detailInfo"]["binaryyaradetect"] = binary_result
        self.info["detailInfo"]["cvedetect"] = cve_result
        self.model_input['yara'] = result.count("|") + binary_result.count("|")
        self.model_input['cve'] = cve_result.count("|")
        if self.model_input['yara'] != 0 or self.model_input['cve'] != 0:
            self.malicious = 1
        if len(self.info["detailInfo"]["findmzstreampath"]) != 0:
            self.model_input['mz'] = 1


        if self.malicious:
            self.info["basicInfo"]["ismalware"] = 1
        else:
            self.info["basicInfo"]["ismalware"] = 0
        self.ole.close()
        # self.model_input['compress_count'] = self.compress_count
        if len(self.info["detailInfo"]["ipurluriinfo"]) != 0:
            self.model_input['domain'] = 1

        self.model_input['autoopen'] += self.model_input['auto_open']
        self.model_input = self.model_input.iloc[:-1]
        ## setting database for insert data
        end_time = int(time.time() * 1000)
        self.info['basicInfo']['analysistime'] = end_time - start_time


    def basic_info(self) -> None:
        """
            setting basic information
            Args:
            return:
        """
        self.info["basicInfo"]["filesize"] = os.path.getsize(self.fpath)
        # self.model_input["filesize"] = self.info["basicInfo"]["filesize"]
        self.info["basicInfo"]["analysisdate"] = self.current
        self.get_meta()

    def get_meta(self) -> None:
        """
            setting meta information
            Args:
            return:
        """
        meta = self.ole.get_metadata()

        for prop in meta.SUMMARY_ATTRIBS:
            value = getattr(meta, prop)

            if value is None:
                continue

            if prop == 'num_pages':
                self.info["basicInfo"]["numofpage"] = value

            elif prop == 'create_time':
                self.info["basicInfo"]["creationdate"] = value.strftime('%Y-%m-%d %H:%M:%S')

            elif prop == 'last_saved_time':
                self.info["basicInfo"]["modificationdate"] = value.strftime('%Y-%m-%d %H:%M:%S')
                self.info["detailInfo"]["lastsavedtime"] = value.strftime('%Y-%m-%d %H:%M:%S')

            elif prop == 'title':
                self.info["detailInfo"]["title"] = convert_string(value)

            elif prop == 'author':
                self.info["detailInfo"]["author"] = convert_string(value)

            elif prop == 'last_saved_by':
                self.info["detailInfo"]["lastsavedby"] = convert_string(value)

        for prop in meta.DOCSUM_ATTRIBS:
            value = getattr(meta, prop)

            if prop == 'version':
                if value is not None:
                    self.info["basicInfo"]["docversion"] = str(value)

    # vba 여부를 확인하는 함수
    def detect_script(self) -> None:
        """
            exist vba or not
            Args:
            return:
        """
        oid = oletools.oleid.OleID(self.fpath)
        for i in oid.check():
            if i.id == 'vba' and 'yes' in i.value.lower():
                self.vbaExists = True
                break

    def stream_parser(self, stream_path: str) -> bin:
        try:
            stream_data = self.ole.openstream(stream_path)
            data = stream_data.read()
            zobj = zlib.decompressobj(-zlib.MAX_WBITS)
            decom_data = zobj.decompress(data)

            with open(f'{self.output_path}/{stream_path.replace("/", "_")}_decom.txt', 'wb') as f:
                f.write(decom_data)
            self.compress_count += 1
            return decom_data

        except zlib.error or OSError:
            pass


    def mz_yara_detect(self, stream_list: list) -> str:
        rules = self.yara_rule
        result = ''
        for stream in stream_list:
            stream_path = '/'.join(stream)
            data = self.stream_parser(stream_path)
            if data is None:
                data = self.ole.openstream(stream_path)

            if "OLE" in stream_path:
                try:
                    data = data.decode('ISO-8859-1')
                except AttributeError:
                    data = data.read().decode('ISO-8859-1')
                for api in self.api_list:
                    if api in data:
                        self.model_input[api.lower()] += 1
            elif "Scripts" in stream_path or "scripts" in stream_path \
                    or "Script" in stream_path or "script" in stream_path:
                self.model_input['Script'] += 1
                jscode = stream_read(self.ole, stream_path, decomplie=True)
                try:
                    jscode = jscode.decode("UTF-16").replace("\r\n", '')
                except UnicodeError:
                    jscode = jscode.decode("ISO-8859-1").replace("\r\n", '')
                self.model_input["js_size"] += len(jscode)
                if "Section" in stream_path:
                    self.model_input["sectionscript".lower()] += 1
                # .js파일이 있을 경우
                if ".js" in stream_path:
                    self.model_input["js".lower()] += 1
                search_all(jscode, return_series=self.model_input, regexs=self.regexs)
                ipyara = ip_yara_detect(jscode, self.ip_yara_detect)
                urlyara = url_yara_detect(jscode, self.url_yara_detect)
                self.info["detailInfo"]["ipurluriinfo"] += ipyara
                self.info["detailInfo"]["ipurluriinfo"] += urlyara
            data_parser = self.stream_parser(stream_path)
            if data_parser is None:
                if type(data) == type(""):
                    data = data
                else:
                    data = data.read().decode('ISO-8859-1')
            else:
                data = data_parser.decode('ISO-8859-1')
            search_all(data, return_series=self.model_input, regexs=self.regexs)
            ipyara = ip_yara_detect(data, self.ip_yara_detect)
            urlyara = url_yara_detect(data, self.url_yara_detect)
            self.info["detailInfo"]["ipurluriinfo"] += ipyara
            self.info["detailInfo"]["ipurluriinfo"] += urlyara
            try:
                stream_data = self.ole.openstream(stream_path).read()
                try:
                    mz_matches = rules.match(data=stream_data)
                    if len(mz_matches) != 0:
                        result += (stream_path + '|')
                    self.model_input['mz'] += len(mz_matches)
                except Exception as e:
                    print(f'    [\033[31mDebug\033[0m] mz_yara_detect (yara.compile) \033[91m{e}\033[0m')
            except Exception as e:
                print(f'    [\033[31mDebug\033[0m] mz_yara_detect (ole.openstream) \033[91m{e}\033[0m')

        return result

