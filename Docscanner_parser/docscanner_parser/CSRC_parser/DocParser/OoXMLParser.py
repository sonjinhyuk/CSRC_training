import os
from .. import get_setting, get_current_date, ip_yara_detect, url_yara_detect, search_all
import zipfile
import yara
import json
from .regex_def import *
from .OleOoXMLCommon import full_yara_detect, convert_string, detect_macro, detect_dde, struct
import pandas as pd
import xml.etree.ElementTree as ET
import shutil
import regex
import base64
import oletools.msodde
import oletools.olevba
import oletools.oleid
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
YARA_DIR = f'{os.path.join(BASE_DIR)}\\resource\\csrc_YARA\\'

class OoXMLParser:
    def __init__(self, file: str, app, source_file_name:str = None, output_dir:str = None,
                 file_type: str=None, extract_path:str = None, sha256:str = None, md5: str=None) -> None:
        """
            Ooxml is two types of file, hwpx and ms-office extended file
            Args:
                :param file: input file
                :param source_file_name: input file name
                :param output_dir: output directory
                :param file_type: hwpx or ms-office extended file
                :param extract_path: ooxml is zip file, so extract path
                :param sha256: hash value(sha256)
                :param md5: hash value(md5)
            return:
        """

        ## set basic information
        self.sha256 = sha256
        self.md5 = md5
        self.fpath = str(file)
        self.file_type = file_type
        self.output = output_dir
        self.output_path = output_dir
        self.source_file_name = source_file_name
        self.app = app
        self.ole_keylist = get_setting('ole_keylist')
        self.info = get_setting('form')
        self.vbaExists = False
        # self.xlmExists = False
        self.malicious = False
        ## set yara rules
        self.yara_rule = yara.compile(YARA_DIR + get_setting('mz_yara'))
        self.cve_rule = yara.compile(YARA_DIR + get_setting('cve_yara'))
        self.ole_yara = yara.compile(YARA_DIR + get_setting('ole_yara'))
        self.ip_yara_detect = yara.compile(YARA_DIR + get_setting('ip_yara_detect'))
        self.url_yara_detect = yara.compile(YARA_DIR + get_setting('url_yara_detect'))
        self.current = get_current_date()
        self.api_list = get_setting('api_list')
        self.extract_path = extract_path
        self.result_text = "success"
        self.start_time = int(time.time() * 1000)
        if self.app == 'hwpx':
            ## set hwp information
            self.hwp_keylist = get_setting('hwp_keylist')
            self.info = get_setting('hwp_form')
            self.xairesult = get_setting('xairesult')

            self.hwp_yara = yara.compile(YARA_DIR + get_setting('hwp_yara'))
            self.regexs = set_regex(self.hwp_keylist)

            self.objids = []
            df_columns = ['file_name']
            for okey in self.hwp_keylist:
                df_columns.append(okey.lower())
            _data = [self.source_file_name]
            _data += [0 for _ in self.hwp_keylist]
            _data = pd.Series(_data, index=df_columns)
            self.model_input = _data
            for col in list(self.model_input.index):
                if "tag_id" in col:
                    tagid = col.split("tag_id_")[-1]
                    try:
                        self.objids.append(int(tagid))
                    except ValueError:
                        self.objids.append(tagid)
            self.hwpx_run()
        else:
            df_columns = ['file_name']
            self.regexs = set_regex(self.ole_keylist, "OLE")
            for okey in self.ole_keylist:
                df_columns.append(okey.lower())
            _data = [self.source_file_name]
            _data += [0 for _ in self.ole_keylist]
            _data = pd.Series(_data, index=df_columns)
            self.model_input = _data
            self.ooxml_yara = yara.compile(YARA_DIR + get_setting('ole_yara'))
            self.run()

        self.info = pd.DataFrame(self.info)

    @staticmethod
    def debug_msg(level: str, msg: str) -> None:
        if level == 'Debug':
            print(f'    [\033[31m{level}\033[0m] {msg}')
        else:
            print(f'    [\033[32mDebug\033[0m] {msg}')

    def mz_yara_detect(self, data: bin, stream_path: str) -> None:
        try:
            mz_matches = self.yara_rule.match(data=data)
            if len(mz_matches) != 0:
                self.info["hwpInfo"]["findmzstreampath"] += (stream_path + '|')
        except Exception as e:
            pass

    def hwpx_run(self):
        """
            hwpx file type parsing
            Args:
            return:
        """
        try:
            ## ooxml is tree format, so parse xml
            tree = ET.parse(f'{self.extract_path}/META-INF/manifest.xml')
            root = tree.getroot()
        except FileNotFoundError:
            self.result_text = "Empty File"
            return ""
        ns = {'odf': 'urn:oasis:names:tc:opendocument:xmlns:manifest:1.0'}
        enc_data_elem = root.findall(".//odf:file-entry/odf:encryption-data", ns)
        if len(enc_data_elem) != 0:
            ## is encrypted
            self.info["hwpInfo"]["isencrypt"] = 1
        else:
            self.info["hwpInfo"]["isencrypt"] = 0
            tree = ET.parse(f'{self.extract_path}/Contents/header.xml')
            root = tree.getroot()
            header_ns = {'hh': 'http://www.hancom.co.kr/hwpml/2011/head'}
            self.info["basicInfo"]["numofpage"] = root.find('.//hh:beginNum', header_ns).attrib['page']

            tree = ET.parse(f'{self.extract_path}/version.xml')
            root = tree.getroot()

            for child in root.iter():
                self.info["basicInfo"]["docversion"] = child.attrib['appVersion']

            self.info["basicInfo"]["filetype"] = 11
            self.info["basicInfo"]["sourcefilename"] = self.source_file_name
            self.info["basicInfo"]["sha256"] = self.sha256
            self.info["basicInfo"]["md5"] = self.md5
            self.info["basicInfo"]["filesize"] = os.path.getsize(self.fpath)
            self.info["basicInfo"]["analysisdate"] = get_current_date()

            tree = ET.parse(f'{self.extract_path}/Contents/content.hpf')
            root = tree.getroot()

            # metadata 파싱
            content_ns = {'opf': 'http://www.idpf.org/2007/opf/'}
            title = root.findall('.//opf:title', content_ns)[0]
            self.info["hwpInfo"]["title"] = title.text
            metadata = root.findall('.//opf:meta', content_ns)
            for child in metadata:
                name = child.attrib['name']

                if name == 'creator':
                    self.info["hwpInfo"]["author"] = child.text
                elif name == 'CreatedDate':
                    self.info["basicInfo"]["creationdate"] = child.text.replace('T', ' ').replace('Z', ' ').strip()
                elif name == 'ModifiedDate':
                    self.info["basicInfo"]["modificationdate"] = child.text.replace('T', ' ').replace('Z', ' ').strip()
                    self.info["hwpInfo"]["lastsavedtime"] = child.text.replace('T', ' ').replace('Z', ' ').strip()
                elif name == 'lastsaveby':
                    self.info["hwpInfo"]["lastsavedby"] = child.text

            manifest = root.findall('.//opf:item', content_ns)
            for child in manifest:
                item_id = child.attrib['id']

                if item_id == 'header':
                    header = os.path.basename(child.attrib['href'])
                    src = f'{self.extract_path}/Contents/{header}'
                    dst = f'{self.output}/{header}'
                    self.info["hwpInfo"]["fileheader"] = dst
                    shutil.move(src, dst)

                if 'section' in item_id:
                    section = os.path.basename(child.attrib['href'])
                    src = f'{self.extract_path}/Contents/{section}'
                    dst = f'{self.output}/{section}'
                    self.model_input["sectionscript".lower()] += 1
                    shutil.move(src, dst)

                self.info["hwpInfo"]["streamlist"] += (child.attrib['href'] + '|')

            if os.path.isfile(f'{self.extract_path}/Preview/PrvText.txt'):
                self.info["hwpInfo"]["pretext"] = f'{self.output}/PrvText.txt'
                src = f'{self.extract_path}/Preview/PrvText.txt'
                dst = f'{self.output}/PrvText.txt'
                shutil.move(src, dst)

            ## similar to stream analisys in HWP file
            ## parsing bianry data
            if os.path.isdir(f'{self.extract_path}/BinData'):
                bin_files = os.listdir(f'{self.extract_path}/BinData')

                for bf in bin_files:
                    with open(f'{self.extract_path}/BinData/{bf}', 'rb') as f:
                        data = f.read()
                        mz_matches = self.yara_rule.match(data=data)
                    self.mz_yara_detect(data, f'BinData/{bf}')
                    ipyara = ip_yara_detect(data, self.ip_yara_detect)
                    url_yara = ip_yara_detect(data, self.url_yara_detect)
                    self.info["hwpInfo"]["ipurluriinfo"] += ipyara
                    self.info["hwpInfo"]["ipurluriinfo"] += url_yara
                    if len(mz_matches) != 0:
                        self.info["hwpInfo"]["findmzstreampath"] += f'BinData/{bf}|'
                    if 'eps' in bf or 'ps' in bf or 'pct' in bf:
                        # BinData 스토리지의 스트림 파일에 디컴프레스 할 데이터가 없을 경우
                        if ('string dup' in data) and ('putinterval' in data) and ('repeat' in data):
                            multi_stream = regex.compile('<(.*?)>', regex.S)
                            for i, s in enumerate(regex.findall(multi_stream, data)):
                                if 15000 < len(s):
                                    shell_path = f'{self.output}/BinData_shellcode{i}_ext.txt'
                                    shell_r_path = f'{self.output}/BinData_shellcode{i}_res.txt'
                                    with open(shell_path, 'w') as f:
                                        f.write(s)

                                    ipyara = ip_yara_detect(s, self.ip_yara_detect)
                                    url_yara = ip_yara_detect(s, self.url_yara_detect)
                                    self.info["hwpInfo"]["ipurluriinfo"] += ipyara
                                    self.info["hwpInfo"]["ipurluriinfo"] += url_yara
                                    # scdbg 처리
                                    # scdbg = self.setting["pycharm_path"] + "\\bin\\scdbg\\scdbg.exe"
                                    # shellcode_execute = [scdbg, '-f', shell_path]
                                    # shellcode_execute = sp.getstatusoutput(shellcode_execute)
                                    # self.info["hwpInfo"]["decomshell"] += (shell_r_path + '|')
                                    # with open(shell_r_path, 'w') as f:
                                    #     f.write(str(shellcode_execute))
                        # 압축 해제된 데이터에 아래 스트링이 존재할 경우 exec를 print quit로 변경 후 고스트스크립트 파일 실행하여 디코딩된 코드 추출 후 저장
                        elif ('exec' in data) and ('xor' in data) or ('exec' in data) and ('cvx' in data):
                            data = data.replace('exec', 'print quit')
                            decom_path = f'{self.output}/BinData_{bf}_decom.txt'
                            with open(decom_path, 'w', encoding='utf-8') as f:
                                f.write(data)
                            with open(decom_path, 'r', encoding='utf-8') as f:
                                data_read = f.readlines()

                            DATA = ''
                            name = ''
                            for d in data_read:
                                if '{ token pop exch pop }' in d:
                                    name = d.split()[0][1:]
                            for d in data_read:
                                if '{ token pop exch pop }' in d:
                                    pass
                                elif name in d:
                                    d = d.replace(name, '')
                                    DATA += d
                                else:
                                    DATA += d

                            with open(decom_path, 'w', encoding='utf-8') as f:
                                f.write(DATA)
                            ipyara = ip_yara_detect(data, self.ip_yara_detect)
                            url_yara = ip_yara_detect(data, self.url_yara_detect)
                            self.info["hwpInfo"]["ipurluriinfo"] += ipyara
                            self.info["hwpInfo"]["ipurluriinfo"] += url_yara
                            # todo
                            # ghost = self.setting["pycharm_path"] + "\\bin\\ghostscript\\gswin32c.exe"
                            # ghost_cmd = [ghost, decom_path]
                            # ghost_r_path = f'{self.output}/{"_".join(stream)}_ghost_result.txt'
                            # self.info["hwpInfo"]["decomghost"] += (ghost_r_path + '|')
                            # with open(ghost_r_path, 'w', encoding='utf-8') as f:
                            #     try:
                            #         ghost_execute = sp.check_output(ghost_cmd)
                            #         f.write(str(ghost_execute))
                            #     except sp.CalledProcessError:
                            #         f.write('GPL Ghostscript 8.71: Unrecoverable error, exit code 1\n')
                        else:
                            for number, d in enumerate(data):
                                if '==' in d:
                                    if '1 get closefile quit' not in d:
                                        data = data.split('def')
                                        stream_data = d.split('(')[1].split('==')[0] + '=='
                                        stream_decode = base64.b64decode(stream_data).decode('utf-8').replace('\0',
                                                                                                              '')

                                        base_path = f'{self.output}/BinData_{bf}_BASE64_Decom.txt'
                                        self.info["hwpInfo"]["decombase64"] += (base_path + '|')
                                        with open(base_path, 'w') as f:
                                            f.write(stream_decode)

                                        ipyara = ip_yara_detect(stream_decode, self.ip_yara_detect)
                                        url_yara = ip_yara_detect(stream_decode, self.url_yara_detect)
                                        self.info["hwpInfo"]["ipurluriinfo"] += ipyara
                                        self.info["hwpInfo"]["ipurluriinfo"] += url_yara
                                    else:
                                        pass
                        search_all(data, return_series=self.model_input, regexs=self.regexs)
                    elif 'OLE' in bf:
                        for api in self.ole_keylist:
                            if api in data:
                                self.info["hwpInfo"]["apilist"] += (api + '|')
                                self.model_input[api.lower()] += 1

                        ipyara = ip_yara_detect(data, self.ip_yara_detect)
                        url_yara = ip_yara_detect(data, self.url_yara_detect)
                        self.info["hwpInfo"]["ipurluriinfo"] += ipyara
                        self.info["hwpInfo"]["ipurluriinfo"] += url_yara
                    else:
                        pass
            ## parsing script data
            if os.path.isdir(f'{self.extract_path}/Scripts'):
                self.model_input['script'] += 1
                js_files = os.listdir(f'{self.extract_path}/Scripts')
                for jf in js_files:
                    if 'Version' in jf:
                        continue
                    src = f'{self.extract_path}/Scripts/{jf}'
                    self.info["hwpInfo"]["decomjscript"] += f'{self.output}/{jf}|'
                    shutil.move(src, f'{self.output}/{jf}')

                    with open(f'{self.output}/{jf}', 'rb') as f:
                        data = f.read()

                    ipyara = ip_yara_detect(data, self.ip_yara_detect)
                    url_yara = ip_yara_detect(data, self.url_yara_detect)
                    self.info["hwpInfo"]["ipurluriinfo"] += ipyara
                    self.info["hwpInfo"]["ipurluriinfo"] += url_yara

                    with open(f'{self.output}/{jf}', 'rt', encoding='utf-8') as f:
                        jscode = f.readlines()
                        self.model_input["js_size"] += len(jscode)
                        for api in self.api_list:
                            if api in jscode:
                                self.info["hwpInfo"]["apilist"] += f'{api}|'
                                self.model_input[api.lower()] += 1
                        for js in jscode:
                            search_all(js, return_series=self.model_input, regexs=self.regexs)
                self.model_input["js".lower()] += len(js_files)

            ## get yara detect result
            result, binary_result, cve_result = full_yara_detect(f'{self.output_path}', self.fpath, self.hwp_yara, self.cve_rule)
            self.info["hwpInfo"]["yaradetect"] = result
            self.info["hwpInfo"]["binaryyaradetect"] = binary_result
            self.info["hwpInfo"]["cvedetect"] = cve_result
            self.model_input['yara'] = result.count("|") + binary_result.count("|")
            self.model_input['cve'] = cve_result.count("|")
            if self.model_input['yara'] != 0 or self.model_input['cve'] != 0:
                self.info["basicInfo"]["ismalware"] = 1

            ## remove extract file
            shutil.rmtree(self.extract_path)

    def run(self) -> None:
        """
           ms-office extended file type parsing
           Args:
           return:
       """

        ## basic information setting
        self.info["detailInfo"]["isencrypt"] = 0
        self.info["basicInfo"]["sourcefilename"] = self.source_file_name
        self.info["basicInfo"]["sha256"] = self.sha256
        self.info["basicInfo"]["md5"] = self.md5
        self.info["detailInfo"]["detail_type"] = self.file_type

        self.xml_parser()
        self.detect_script()

        if self.vbaExists:
            detect_macro(self)
            self.model_input['vba'] = 1

        if os.path.isdir(f'{self.extract_path}/xl/macrosheets'):
            self.info["detailInfo"]["xmlscript"] = self.detect_xlm_macro()
            search_all(self.info["detailInfo"]["xmlscript"], self.model_input, self.regexs)
            if len(self.info["detailInfo"]["xmlscript"]) != 0 :
                self.model_input['xmlscript'] = 1
        if self.app != 'pptx':
            detect_dde(self)
            search_all(self.info["detailInfo"]["dde"], self.model_input, self.regexs)

        self.file_yara_detect(self.yara_rule)
        result, binary_result, cve_result = full_yara_detect(f'{self.output_path}', self.fpath, self.ooxml_yara,
                                                             self.cve_rule)
        self.info["detailInfo"]["yaradetect"] = result
        self.info["detailInfo"]["binaryyaradetect"] = binary_result
        self.info["detailInfo"]["cvedetect"] = cve_result
        self.model_input['yara'] = result.count("|") + binary_result.count("|")
        self.model_input['cve'] = cve_result.count("|")
        if len(self.info["detailInfo"]["yaradetect"]) != 0:
            self.malicious = 1
        if len(self.info["detailInfo"]["findmzstreampath"]) != 0:
            self.model_input['mz'] = 1
        if self.malicious:
            self.info["basicInfo"]["ismalware"] = 1
        else:
            self.info["basicInfo"]["ismalware"] = 0

        # self.model_input['compress_count'] = self.compress_count
        if len(self.info["detailInfo"]["ipurluriinfo"]) != 0:
            self.model_input['domain'] = 1

        self.model_input['autoopen'] += self.model_input['auto_open']
        self.model_input = self.model_input.iloc[:-1]

        end_time = int(time.time() * 1000)
        self.info['basicInfo']['analysistime'] = end_time - self.start_time

    def xml_parser(self) -> None:
        """
            xml analysis
            Args:
            return:
        """
        self.info["basicInfo"]["filesize"] = os.path.getsize(self.fpath)
        # self.model_input["filesize"] = self.info["basicInfo"]["filesize"]
        self.info["basicInfo"]["analysisdate"] = self.current

        try:
            tree = ET.parse(f'{self.extract_path}/docProps/app.xml')
            root = tree.getroot()

            for child in root:
                tag = child.tag.split('}')[1].lower()
                if tag == 'slides':
                    self.info["basicInfo"]["numofpage"] = int(child.text)
                elif tag == 'pages':
                    self.info["basicInfo"]["numofpage"] = int(child.text)
                elif tag == 'appversion':
                    self.info["basicInfo"]["docversion"] = child.text
        except FileNotFoundError:
            msg = f'xml_parser \033[91mapp.xml not found\033[0m'
            self.debug_msg('Debug', msg)

        try:
            tree = ET.parse(f'{self.extract_path}/docProps/core.xml')
            root = tree.getroot()

            for child in root:
                tag = child.tag.split('}')[1].lower()

                if tag == 'title':
                    title = child.text
                    if title is None:
                        title = ""
                    self.info["detailInfo"]["title"] = title
                elif tag == 'creator':
                    author = child.text
                    if author is None:
                        author = ""
                    self.info["detailInfo"]["author"] = author
                elif tag == 'created':
                    self.info["basicInfo"]["creationdate"] = child.text.replace('T', ' ').replace('Z', '')
                    if "+" in self.info["basicInfo"]["creationdate"]:
                        self.info["basicInfo"]["creationdate"] = self.info["basicInfo"]["creationdate"][:19]
                elif tag == 'lastmodifiedby':
                    self.info["detailInfo"]["lastsavedby"] = child.text
                elif tag == 'modified':
                    self.info["basicInfo"]["modificationdate"] = child.text.replace('T', ' ').replace('Z', '')
                    self.info["detailInfo"]["lastsavedtime"] = child.text.replace('T', ' ').replace('Z', '')
                    if "+" in self.info["basicInfo"]["modificationdate"]:
                        self.info["basicInfo"]["modificationdate"] = self.info["basicInfo"]["modificationdate"][:19]
                        self.info["detailInfo"]["lastsavedtime"] = self.info["detailInfo"]["lastsavedtime"][:19]
        except FileNotFoundError:
            msg = f'xml_parser \033[91mcore.xml not found\033[0m'
            self.debug_msg('Debug', msg)

    def detect_script(self) -> None:
        """
            use third party library(oletools) to detect script
            Args:
            return:
        """
        oid = oletools.oleid.OleID(self.fpath)
        try:
            for i in oid.check():
                if i.id == 'vba' and 'yes' in i.value.lower():
                    self.vbaExists = True
        except Exception as e:
            self.debug_msg('Debug', str(e))

    def detect_vba_macro(self) -> None:
        """
            use third party library(oletools) to detect vba macro
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
            if vba_code is None:
                continue
            stream_path = stream_path.replace('/', '_')
            with open(f'{self.output}\\{stream_path}.txt', 'wt', encoding='utf-8') as f:
                f.write(vba_code)
                self.info["detailInfo"]["ipurluriinfo"] += ip_yara_detect(vba_code)
                self.info["detailInfo"]["ipurluriinfo"] += url_yara_detect(vba_code)
            self.info["detailInfo"]["VBAScript"] += (f'{self.output}\\{stream_path}.txt' + '|')
            with open(f'{self.output}\\{stream_path}.txt', 'rt', encoding='utf-8') as f:
                data = f.readlines()
            for i in data:
                for api in self.api_list:
                    if api in i:
                        self.info["detailInfo"]["apiList"] += (api + '|')
            macro_cnt += 1

        self.info["detailInfo"]["numberOfVBA"] = macro_cnt

        for (type_e, keyword, description) in vba.analyze_macros():
            if 'malicious' in type_e.lower() or 'suspicious' in type_e.lower():
                self.malicious = 1

    def detect_xlm_macro(self) -> str:
        """
            use third party library(oletools) to detect xlm macro
            Args:
            return:
        """
        return_result = ''
        macro_path = f'{self.extract_path}/xl/macrosheets'
        macro_sheets = os.listdir(f'{macro_path}')

        for fi in macro_sheets:
            if '.xml' not in fi:
                continue

            tree = ET.parse(f'{macro_path}/{fi}')
            root = tree.getroot()

            store_result = ''
            for child in root.iter():
                tag = child.tag.split('}')[1].lower()

                if tag == 'f':
                    store_result += (child.text + '\n')

            store_path = f'{self.output}/xlm_' + fi.split('.')[0] + '.txt'
            with open(f'{store_path}', 'wt', encoding='utf-8') as f:
                f.write(store_result)
            return_result += (store_result + '|')

        return return_result

    def detect_dde(self):
        """
            use third party library(oletools) to detect dde
            Args:
            return:
        """
        dde = ''
        try:
            if self.app == 'docx':
                dde = oletools.msodde.process_docx(self.fpath)
            if self.app == 'xlsx':
                dde = oletools.msodde.process_xlsx(self.fpath)
        except ValueError:
            msg = f'detect_dde (oletools.msodde.process_{self.app}) \033[91mValueError\033[0m'
            self.debug_msg('Debug', msg)
        except KeyError:
            msg = f'detect_dde (oletools.msodde.process_{self.app}) \033[91mKeyError\033[0m'
            self.debug_msg('Debug', msg)
        except struct.error:
            msg = f'detect_dde (oletools.msodde.process_{self.app}) \033[91mstruct.error\033[0m'
            self.debug_msg('Debug', msg)
        except AssertionError:
            msg = f'detect_dde (oletools.msodde.process_{self.app}) \033[91mAssertion.error\033[0m'
            self.debug_msg('Debug', msg)

        self.info["detailInfo"]["DDE"] += dde

    def file_yara_detect(self, mz_rules) -> None:

        result = ''
        ipurluriinfo = []
        for (root_dir, sub_dir, files) in os.walk(f'{self.extract_path}'):
            for fi in files:
                path = os.path.join(root_dir, fi)
                with open(path, 'rb') as f:
                    data = f.read()
                match_data = mz_rules.match(data=data)

                ipyara = ip_yara_detect(data, self.ip_yara_detect)
                urlyara = url_yara_detect(data, self.url_yara_detect)
                if ipyara != '':
                    for ipyara_result in ipyara.split("|")[:-1]:
                        ipurluriinfo.append(ipyara_result)
                if urlyara != '':
                    for urlyara_result in urlyara.split("|")[:-1]:
                        ipurluriinfo.append(urlyara_result)

                if len(match_data) != 0:
                    result += (path + '|')
        ipurluriinfo = list(set(ipurluriinfo))
        self.model_input['domain'] += len(ipurluriinfo)
        self.info["detailInfo"]["ipurluriinfo"] += "|".join(ipurluriinfo)

        self.info["detailInfo"]["findmzstreampath"] += result
