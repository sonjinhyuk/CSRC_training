import subprocess

from .. import get_setting, ip_yara_detect, url_yara_detect, stream_read, search_all, get_current_date
import os
import olefile
import yara
from collections import namedtuple
import struct
from binascii import hexlify
from datetime import datetime
import pandas as pd
import zlib
import subprocess as sp
from .regex_def import *
import regex
import base64
from struct import unpack
from pathlib import Path
import time

BASE_DIR = Path(__file__).resolve().parent.parent
YARA_DIR = f'{os.path.join(BASE_DIR)}\\resource\\csrc_YARA\\'

def hwpBitMap(val, names, offsets, sizes):
    def getbitvalue(val, offset, size):
        val = val >> offset
        tmp = 1
        size -= 1
        while size > 0:
            tmp = tmp | (1 << size)
            size -= 1
        return val & tmp

    Flag = namedtuple("Flag", names)
    return Flag(*[getbitvalue(val, offsets[i], sizes[i]) for i in range(len(names))])

def GetTag(val):
    RECORD_MEMBER_NAME = ["TagID", "Level", "Size"]
    RECORD_MEMBER_OFFSET = [0, 10, 20]
    RECORD_MEMBER_SIZE = [10, 10, 12]
    return hwpBitMap(val, RECORD_MEMBER_NAME, RECORD_MEMBER_OFFSET, RECORD_MEMBER_SIZE)

class HwpParser:
    """
        HWP Parser Class
        HWP Parsing and get AI model input data
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

        self.output = output_dir
        self.python3_path = get_setting('python3_path')
        self.ViewText_Dec = get_setting('ViewText_Dec')
        self.compress_count = 0
        self.fpath = file
        self.source_file_name = source_file_name
        self.sha256 = sha256
        self.md5 = md5
        ## get hwp key list for AI model
        self.hwp_keylist = get_setting('hwp_keylist')
        ## DB form setting
        self.info = get_setting('hwp_form')
        ## xai form setting
        self.xairesult = get_setting('xairesult')
        self.ole = olefile.OleFileIO(file)
        self.file_type = file_type

        self.yara_rule = yara.compile(YARA_DIR + get_setting('mz_yara'))
        self.cve_yara = yara.compile(YARA_DIR + get_setting('cve_yara'))
        self.hwp_yara = yara.compile(YARA_DIR + get_setting('hwp_yara'))
        self.ip_yara_detect = yara.compile(YARA_DIR + get_setting('ip_yara_detect'))
        self.url_yara_detect = yara.compile(YARA_DIR + get_setting('url_yara_detect'))

        ## get regex for AI model data
        self.regexs = set_regex(self.hwp_keylist)
        ## get hwp api list
        self.api_list = get_setting('api_list')
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

        self.info = pd.DataFrame(self.info)
        self.run()


    def mz_yara_detect(self, data: bin, stream_path: str) -> None:
        """
            Excutible file check
            Args:
                :param data(binary): stream data
                :param stream_path(str): mz file path
            return:
        """
        try:
            mz_matches = self.yara_rule.match(data=data)
            if len(mz_matches) != 0:
                self.info["hwpInfo"]["findmzstreampath"] += (stream_path + '|')

        except Exception as e:
            print(e)
            pass

    def run(self):
        """
            parsing hwp file
            preprocessing and insert DB hwp file
            Args:
            return:
        """
        start_time = int(time.time() * 1000)
        version = self.file_header()

        self.info["basicInfo"]["sourcefilename"] = self.source_file_name
        self.info["basicInfo"]["sha256"] = self.sha256
        self.info["basicInfo"]["md5"] = self.md5
        self.info["basicInfo"]["filesize"] = os.path.getsize(self.fpath)
        self.info["basicInfo"]["docversion"] = version

        self.hwp_summary()
        ## get stream list
        stream_list = self.stream_list()
        ## interpreter stream data and get AI model input data
        self.stream_data(stream_list)
        if len(self.info["hwpInfo"]["ipurluriinfo"]) != 0:
            self.model_input['domain'] = 1

        self.ole.close()
        self.info["hwpInfo"]["numofcompsection"] = self.compress_count
        self.detect_yara()
        ## get yara rule detect count
        self.model_input['yara'] += self.info["hwpInfo"]["binaryyaradetect"].count("|")
        self.model_input['yara'] += self.info["hwpInfo"]["yaradetect"].count("|")
        self.model_input['cve'] += self.info["hwpInfo"]["cvedetect"].count("|")
        if self.info["hwpInfo"]["binaryyaradetect"].count("|") != 0:
            self.info["basicInfo"]["isMalware"] = 1

    def get_bit_value(self, val: bool, offset: int, size: int) -> int:
        val = val >> offset
        tmp = 1
        size -= 1
        while size > 0:
            tmp = tmp | (1 << size)
            size -= 1
        return val & tmp

    def bit_map(self, val: bool, names: list, offsets: list, sizes: list) -> namedtuple:
        Flag = namedtuple("Flag", names)
        return Flag(*[self.get_bit_value(val, offsets[i], sizes[i]) for i in range(len(names))])

    def get_tag_object(self, data: bin, offset: int) -> namedtuple:
        try:
            val = struct.unpack("<L", data[offset:offset + 4])[0]
            offset += 4
            tag = self.get_tag(val)
            if tag.Size >= 4095:
                new_size = struct.unpack("<L", data[offset:offset + 4])[0]
                offset += 4
                tag = tag._replace(**{"Size": new_size})
            tmp = data[offset:offset + tag.Size]
            offset += tag.Size
            data = namedtuple("TagData", "data")(tmp)

            return namedtuple("Record", tag._fields + data._fields)(*(tag + data)), offset
        except struct.error:
            pass

    def get_tag(self, val: bin) -> namedtuple:
        record_member_name = ["TagID", "Level", "Size"]
        record_member_offset = [0, 10, 20]
        record_member_size = [10, 10, 12]
        return self.bit_map(val, record_member_name, record_member_offset, record_member_size)

    def file_header(self) -> str:
        version = ''
        try:
            data = self.ole.openstream('FileHeader').read()
            version = '.'.join(hexlify(data[32:36]).decode()[::-1][::2])
        except OSError:
            try:
                data = self.ole.openstream('\x05HwpSummaryInformation').read()
                version = '.'.join(hexlify(data[32:36]).decode()[::-1][::2])
            except OSError:
                pass

        return version

    def hwp_summary(self):
        """
            get hwp file summary information
            Args:
            return:
        """
        summary = self.ole.getproperties('\x05HwpSummaryInformation', convert_time=True)

        self.info["basicInfo"]["creationdate"] = str(summary[12])
        self.info["basicInfo"]["modificationdate"] = str(summary[13])
        self.info["basicInfo"]["analysisdate"] = get_current_date()
        self.info["hwpInfo"]["lastsavedtime"] = str(summary[13])

        try:
            self.info["basicInfo"]["numofpage"] = summary[14]
        except KeyError:
            self.info["basicInfo"]["numofpage"] = 0


        self.info["hwpInfo"]["title"] = summary[2]
        try:
            self.info["hwpInfo"]["author"] = summary[4]
        except KeyError:
            self.info["hwpInfo"]["author"] = ""

        self.info["hwpInfo"]["lastsavedby"] = summary[8]

    @staticmethod
    def ole_category(stream_list: list) -> dict:
        """
           get ole basic information
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
        flag = {'FileHeader': None, '\x05HwpSummaryInformation': None}
        for stream in stream_list:
            if 'FileHeader' in stream:
                flag['FileHeader'] = stream
            if '\x05HwpSummaryInformation' in stream:
                flag['\x05HwpSummaryInformation'] = stream
        return flag

    def stream_list(self) -> list:
        """
            Get a list of all streams in a HWP file
        """
        listdir = self.ole.listdir()

        for content in listdir:
            self.info["hwpInfo"]["streamlist"] += ('/'.join(content) + '|')
        return listdir

    def file_header_check(self, header_data: bin) -> bool:
        """
            Whether the file is encrypted
            Args:
                :param header_data(binary): header data
            return:
                :return isEncrypt(bool): is encrypted
        """
        try:
            header_member_name = 'Signature Version Flag Reserved'
            header_member_size = '=32s2l216s'

            file_header_tuple = namedtuple('FileHeader', header_member_name)._make(
                struct.unpack(header_member_size, header_data))

            flag_member_name = ["IsPack", "IsEncrypt", "IsDistribution", "IsSavingScript", "IsDRM", "IsSavingXML",
                                "IsDocHistoryOp", "IsExistDigSign", "IsEncryptCert", "IsBackDigSign", "IsDRMCert",
                                "IsCCL", "Reserved"]
            flag_member_offset = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
            flag_member_size = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 30]

            flags = self.bit_map(file_header_tuple.Flag, flag_member_name, flag_member_offset, flag_member_size)
            file_header_tuple = file_header_tuple._replace(**{"Flag": flags})

            self.info["hwpInfo"]["ispack"] = file_header_tuple.Flag.IsPack
            self.info["hwpInfo"]["isencrypt"] = file_header_tuple.Flag.IsEncrypt
            return file_header_tuple.Flag.IsEncrypt
        except struct.error:
            pass

    def stream_parser(self, stream_path: str) -> bin:
        """
            decompress stream data
            Args:
                :param stream_path: stream file path
            return:
                :return decom_data(binary): decompress data
        """
        try:
            stream_data = self.ole.openstream(stream_path)
            data = stream_data.read()
            zobj = zlib.decompressobj(-zlib.MAX_WBITS)
            decom_data = zobj.decompress(data)

            with open(f'{self.output}/{stream_path.replace("/", "_")}_decom.txt', 'wb') as f:
                f.write(decom_data)
            self.compress_count += 1
            return decom_data

        except zlib.error or OSError:
            pass

    def file_header_stream_parser(self, content: str) -> None:
        """
           get header information and save file header
           Args:
               :param content(str): stream name
           return:
       """
        try:
            stream_data = self.ole.openstream(content)
            data = stream_data.read()
            self.info["hwpInfo"]["fileheader"] = f'{self.output}/fileheader.txt'
            with open(f'{self.output}/fileHeader.txt', 'wb') as f:
                f.write(data)
        except zlib.error:
            pass

    def stream_parser_content(self, data3, series, objids):
        def GetTagObject(data, offset):
            try:
                val = unpack("<L", data[offset:offset + 4])[0]
                offset += 4
                tag = GetTag(val)
                if tag.Size >= 4095:
                    new_size = unpack("<L", data[offset:offset + 4])[0]
                    offset += 4
                    tag = tag._replace(**{"Size": new_size})
                tmp = data[offset:offset + tag.Size]
                offset += tag.Size
                data = namedtuple("TagData", "data")(tmp)

                return namedtuple("Record", tag._fields + data._fields)(*(tag + data)), offset

            except struct.error:
                pass

        if data3 != None:
            offset = 0
            try:
                ## tag_info size가 12000, 15000만 넘으면 shell code가 있는건가?
                while offset < len(data3):
                    # section_offset_info = "[0x%08X]" % offset,
                    taginfo, offset = GetTagObject(data3, offset)
                    # section_info = (section_offset_info, taginfo.TagID, taginfo.Level, hex(taginfo.Size), taginfo.Size)
                    # 문단 텍스트 쉘코드 탐지
                    # print(taginfo.TagID)
                    tagid = taginfo.TagID
                    if tagid in objids:
                        series["tag_id_{}".format(tagid)] += 1
                    else:
                        series["tag_id_oth"] += 1

                    if (taginfo.TagID == int(67) and (taginfo.Size > int(12000))):
                        series["Generic43".lower()] += 1
                    # 문단 헤더 쉘코드 탐지
                    elif (taginfo.TagID == int(66) and (taginfo.Size > int(15000))):
                        series["Generic44".lower()] += 1
            except TypeError:
                pass
            # print()

    def bodyTextStreamParser(self, ole, content, series, objids):
        data3 = None
        try:
            data3 = stream_read(ole, content, decomplie=True)
            self.stream_parser_content(data3, series, objids)
        except zlib.error:
            pass

        if data3 == None:
            # 현재 하나도 없음...
            data3 = stream_read(ole, content, decomplie=False).read()

    def body_text_stream_parser(self, stream_path: str) -> None:
        """
            decompress body text stream data
            Args:
                :param stream_path: stream file path
        """
        content = stream_path.split('/')[1]
        try:
            data = self.stream_parser(stream_path)
            if data is None:
                stream_data = self.ole.openstream(stream_path).read()
                with open(f'{self.output}/{content}.txt', 'wb') as f:
                    f.write(stream_data)
            else:
                section_info1 = ''
                offset = 0
                try:
                    while offset < len(data):
                        section_offset_info = '[0x%08X]' % offset,
                        taginfo, offset = self.get_tag_object(data, offset)
                        section_info = (
                        section_offset_info, taginfo.TagID, taginfo.Level, hex(taginfo.Size), taginfo.Size)
                        section_info = str(list(section_info))
                        section_info1 = section_info + '\n' + section_info1
                    try:
                        with open(f'{self.output}/Section_info.txt', 'a') as f:
                            f.write(stream_path.replace('/', '_') + '\n')
                            f.write(section_info1 + '\n')
                    except NameError:
                        pass
                except TypeError:
                    pass
        except zlib.error:
            stream_data = self.ole.openstream(stream_path).read()
            with open(f'{self.output}/{content}.txt', 'wb') as f:
                f.write(stream_data)

    # def preprocessing(self):
    #     self.info['basicInfo']['b_id'], self.info['basicInfo']['f_id'] = get_bfid(self.file_type_id, self.file_type)
    #     self.info["hwpInfo"]['f_id'] = self.info['basicInfo']['f_id']

    def stream_data(self, stream_list: list) -> dict:
        """
           read stream data
           Args:
               :param stream_list(list): stream list
           return:
       """
        model_input = self.model_input
        category = self.ole_category(stream_list)
        if category['FileHeader'] is not None:
            content_path = ''.join(category['FileHeader'])
            self.file_header_stream_parser(content_path)

            ## check encrypted file
            with open(f'{self.output}/fileHeader.txt', 'rb') as f:
                header_data = f.read(256)
                header_result = self.file_header_check(header_data)

            if header_result:
                return {"error": "Encrypted HWP file"}

            for stream in stream_list:
                ## ViewText with third party python module
                if stream[0] == 'ViewText':
                    stream_path = '/'.join(stream)
                    try:
                        view_text_exec = sp.Popen([self.python3_path,
                                                   self.ViewText_Dec + "ViewText_Dec.py",
                                                   self.fpath, stream_path], stdout=sp.PIPE)
                        view_text_exec = view_text_exec.stdout.read().decode('utf-8').\
                            replace('(', '').replace(')', '').replace('\'', '').replace(',', '')
                        with open(f'{self.output}/{"_".join(stream)}.txt', 'wt', encoding='utf-8') as f:
                            f.write(view_text_exec)

                        with open(f'{self.output}/{"_".join(stream)}.txt', 'rb') as f:
                            view_text_exec = f.read()

                        ipyara = ip_yara_detect(view_text_exec, self.ip_yara_detect)
                        url_yara = ip_yara_detect(view_text_exec, self.url_yara_detect)
                        self.info["hwpInfo"]["ipurluriinfo"] += ipyara
                        self.info["hwpInfo"]["ipurluriinfo"] += url_yara
                    except Exception as e:
                        print(f'    [\033[31mDebug\033[0m] ViewText \033[91m{e}\033[0m')
                        pass
                ## Binary Data read
                if stream[0] == 'BinData':
                    data = self.stream_parser('/'.join(stream))
                    if data is None:
                        data = self.ole.openstream('/'.join(stream))


                    ## yara dectect
                    self.mz_yara_detect(data, '/'.join(stream))
                    self.info["hwpInfo"]["ipurluriinfo"] += ip_yara_detect(data, self.ip_yara_detect)
                    self.info["hwpInfo"]["ipurluriinfo"] += url_yara_detect(data, self.url_yara_detect)

                    if 'eps' in stream[1].lower() or 'ps' in stream[1].lower() or 'pct' in stream[1].lower():
                        # BinData 스토리지의 스트림 파일에 디컴프레스 할 데이터가 없을 경우
                        if data is None:
                            data = self.ole.openstream('/'.join(stream))
                            with open(f'{self.output}/{"_".join(stream)}.txt', 'wb') as f:
                                f.write(data)
                            self.mz_yara_detect(data, '/'.join(stream))
                        else:
                            try:
                                data = data.decode('ISO-8859-1')
                            except AttributeError:
                                data = stream_read(self.ole, "/".join(stream), decomplie=True)
                                if data != None:
                                    data = data.decode('ISO-8859-1')
                                else:  #
                                    data = stream_read(self.ole, "/".join(stream), decomplie=False)
                            self.mz_yara_detect(data, '/'.join(stream))
                            # 압축 해제된 데이터에 아래 스트링이 존재할 경우 쉘코드만 추출 후 scdbg로 쉘코드 실행 후 쉘코드가 호출하고자 하는 API에 대한 정보 파일 생성
                            if ('string dup' in data) and ('putinterval' in data) and ('repeat' in data):
                                multi_stream = regex.compile('<(.*?)>', regex.S)
                                for i, s in enumerate(regex.findall(multi_stream, data)):
                                    if 15000 < len(s):
                                        shell_path = f'{self.output}/{"_".join(stream)}_shellcode{i}_ext.txt'
                                        shell_r_path = f'{self.output}/{"_".join(stream)}_shellcode{i}_res.txt'
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
                                decom_path = f'{self.output}/{"_".join(stream)}_decom.txt'
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
                                #todo
                                # gswin 처리
                                # ghost = "/usr/bin/ghostscript"
                                # ghost_cmd = [ghost, "-q", decom_path]
                                # ghost_r_path = f'{self.output}/{"_".join(stream)}_ghost_result.txt'
                                # self.info["hwpInfo"]["decomghost"] += (ghost_r_path + '|')
                                # with open(ghost_r_path, 'w', encoding='utf-8') as f:
                                #     try:
                                #         # ghost_execute = sp.check_output(ghost_cmd)
                                #         p = sp.Popen(ghost_cmd, stdout=sp.PIPE, stderr=sp.STDOUT, universal_newlines=True)
                                #         # try:
                                #         #     out, errs = p.communicate(timeout=10)
                                #         # except subprocess.TimeoutExpired:
                                #         #     p.kill()
                                #         # while p.poll() == None:
                                #         #     out = p.stdout.readline()
                                #         #     print(out, end='')
                                #         ghost_execute = p.stdout.read()
                                #         f.write(str(ghost_execute))
                                #     except sp.CalledProcessError:
                                #         f.write('GPL Ghostscript 8.71: Unrecoverable error, exit code 1\n')
                            else:
                                for number, d in enumerate(data):
                                    if '==' in d:
                                        if '1 get closefile quit' not in d:
                                            data = data.split('def')
                                            stream_data = d.split('(')[1].split('==')[0] + '=='
                                            stream_decode = base64.b64decode(stream_data).decode('utf-8').replace('\0', '')

                                            base_path = f'{self.output}/{"_".join(stream)}_BASE64_Decom.txt'
                                            self.info["hwpInfo"]["decombase64"] += (base_path + '|')
                                            with open(base_path, 'w') as f:
                                                f.write(stream_decode)

                                            ipyara = ip_yara_detect(stream_decode, self.ip_yara_detect)
                                            url_yara = ip_yara_detect(stream_decode, self.url_yara_detect)
                                            self.info["hwpInfo"]["ipurluriinfo"] += ipyara
                                            self.info["hwpInfo"]["ipurluriinfo"] += url_yara

                                        else:
                                            pass
                        search_all(data, return_series=model_input, regexs=self.regexs)
                    elif 'OLE' in stream[1]:
                        data = self.stream_parser('/'.join(stream))
                        if data is not None:
                            data = data.decode('ISO-8859-1')
                            ## api count
                            for api in self.api_list:
                                if api in data:
                                    self.info["hwpInfo"]["apilist"] += (api + '|')
                                    model_input[api.lower()] += 1

                            ## yara detect
                            self.mz_yara_detect(data, '/'.join(stream))
                            ipyara = ip_yara_detect(data, self.ip_yara_detect)
                            url_yara = ip_yara_detect(data, self.url_yara_detect)
                            self.info["hwpInfo"]["ipurluriinfo"] += ipyara
                            self.info["hwpInfo"]["ipurluriinfo"] += url_yara
                        else:
                            pass
                    else:
                        pass
                elif stream[0] == 'BodyText':
                    self.body_text_stream_parser('/'.join(stream))
                    #for model input
                    self.bodyTextStreamParser(self.ole, '/'.join(stream), model_input, self.objids)
                elif stream[0] == 'Scripts':
                    ## action or javascript counting
                    model_input['Script'.lower()] += 1
                    if 'Version' in stream[1]:
                        continue

                    data = self.stream_parser('/'.join(stream))

                    if os.path.isfile(f'{self.output}/{"_".join(stream)}_decom.txt'):
                        with open(f'{self.output}/{"_".join(stream)}_decom.txt', 'r',
                                  encoding='utf-16le') as f:
                            try:
                                f_read = f.read().replace('\0', '').replace(' ', '')
                                with open(f'{self.output}/{"_".join(stream)}_decom.txt', 'w',
                                          encoding='utf-16le') as f:
                                    f.write(f_read)
                            except UnicodeDecodeError:
                                pass

                        ## save decompress js code data
                        self.info["hwpInfo"]["decomjscript"] += f'{self.output}/{"_".join(stream)}_decom.txt|'
                    try:
                        data = data.decode('ISO-8859-1')
                        for idx, api in enumerate(self.setting['script_api_list']):
                            if api in data:
                                self.info["hwpInfo"]["apilist"] += (api + '|')
                                self.model_input[api.lower()] += 1
                    except Exception as e:
                        pass

                    jscode = stream_read(self.ole, "/".join(stream), decomplie=True)
                    try:
                        jscode = jscode.decode("UTF-16").replace("\r\n", '')
                    except UnicodeError:
                        jscode = jscode.decode("ISO-8859-1").replace("\r\n", '')
                    model_input["js_size"] += len(jscode)
                    # section에 있는 script
                    if "Section" in stream[-1]:
                        model_input["sectionscript".lower()] += 1
                    # .js파일이 있을 경우
                    if ".js" in stream[-1]:
                        model_input["js".lower()] += 1

                    search_all(jscode, return_series=model_input, regexs=self.regexs)
                elif stream[0] == 'PrvText':
                    data = self.ole.openstream(stream[0]).read()
                    with open(f'{self.output}/PrvText.txt', 'wb') as f:
                        f.write(data)
                    self.info['hwpInfo']['pretext'] = f'{self.output}/PrvText.txt'
                elif "SummaryInformation" not in stream[0]:
                    data3 = stream_read(self.ole, "/".join(stream), decomplie=True)
                    if data3 != None:
                        data3 = data3.decode('ISO-8859-1')
                    else:  #
                        data3 = stream_read(self.ole, "/".join(stream), decomplie=False)
                    search_all(data3, return_series=self.model_input, regexs=self.regexs)
        elif category['\x05HwpSummaryInformation']:
            for stream in stream_list:
                if stream[0] == 'BodyText':
                    self.body_text_stream_parser('/'.join(stream))
        else:
            pass

    def detect_yara(self) -> None:
        """
            binary file and each stream output file yara detect
            Args:
            return:
        """
        rules = self.hwp_yara
        cve_yara = self.cve_yara

        for file in Path(self.output).rglob('*'):
            if file.suffix == 'json':
                continue
            try:
                if file.suffix == "" and file.stem == self.sha256:
                    result = rules.match(str(file))
                    self.info["hwpInfo"]["binaryyaradetect"] += '|'.join(list(map(str, result)))
                    result = cve_yara.match(str(file))
                    self.info["hwpInfo"]["cvedetect"] += '|'.join(list(map(str, result)))
                else:
                    with open(f'{file}', 'rb') as f:
                        data = f.read()
                    result = rules.match(data=data)
                    self.info["hwpInfo"]['yaradetect'] += '|'.join(list(map(str, result)))
            except Exception as e:
                print(f'    [\033[31mDebug\033[0m] full_yara_detect (rules.match) \033[91myara.Error\033[0m')

