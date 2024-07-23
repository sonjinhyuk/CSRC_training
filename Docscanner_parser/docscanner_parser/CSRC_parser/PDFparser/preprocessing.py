import sys

import pandas as pd
from CSRC_parser import ip_yara_detect, url_yara_detect
from .cPDFs.cPDFUtil import PDF_ELEMENT_COMMENT, PDF_ELEMENT_XREF, PDF_ELEMENT_TRAILER, PDF_ELEMENT_STARTXREF, \
    PDF_ELEMENT_INDIRECT_OBJECT
from .cPDFs.cPDFUtil import LoadDecoders, ParseINIFile
from .cPDFs.cPDFParser import cPDFParser
from .cPDFs.cPDFUtil import getFileSize
import fitz
from .EnDecode.EnDecoder import *
from .EnDecode.jsDecoder import *
import regex as re
from datetime import datetime
from CSRC_parser import get_setting, get_current_date
import js2py
import os
import time
import yara
from pathlib import Path
from types import SimpleNamespace
import hashlib

BASE_DIR = Path(__file__).resolve().parent.parent
YARA_DIR = f'{os.path.join(BASE_DIR)}/resource/csrc_YARA/'

class Result:
    def __init__(self, bft_dict, input_data):
        self.info = pd.DataFrame(bft_dict)

        df_col = []
        for k in input_data.keys():
            df_col.append(k)
        self.model_input = pd.Series(input_data, index=df_col)

def get_model_input(file_path):
    """
        pdf preprocessing
        Args:
            :param file_path: pdf file path
        return:
            :return model input(dict): for model input
    """
    # oPDFParser = cPDFParser(file_path, False, None)

    # import pypdftk
    #
    # # pypdftk.uncompress(file_path, out_file=file_path+"decom")
    # # file_path = file_path+"decom"
    oPDFParser = cPDFParser(file_path, False, None)


    cntComment = 0
    cntXref = 0
    xref_size = 0
    cntTrailer = 0
    trailer_size = 0
    cntStartXref = 0
    cntIndirectObject = 0
    dicObjectTypes = {}

    ## malware key resource
    keywords = ['/JS', '/JavaScript', '/AA', '/OpenAction', '/AcroForm', '/RichMedia', '/Launch',
                '/EmbeddedFile', '/XFA', '/URI', "/F", "/GoToE", "/Extends", "/Annot", "/Length",
                "/Filter", "/FlateDecode", "/XObject", "/Encrypt", "/RichMedia", "/CreationDate",
                "/Author", "/Creator", "/Subject", "/ModDate",
                "html", "htm", "Script", "powershell.exe", 'cmd.exe',
                "#[0-9]([0-9|A-z])",
                "sys", "root", "reg", "execute",
                "http", 'domain', 'filepath', 'exe', "ascii"
                ]

    inStreamKeywords = ['xml', 'dll', 'exe', "execute", 'unescape', '%u9090%u9090', 'getIcon', 'temp',
                        'tmp', 'eval', 'unescape', '%appdata%', 'http', 'htm', 'chunk', 'base64',
                        'mkdir', 'replace', 'fromCharCode', "subject", "html", "htm", "Script",
                        "sys", 'root', "getAnnots",
                        'filepath', 'ip', 'domain', "ascii"]
    nof_regex = 4
    length_thredhold = 20000
    inStream_dict = {iskeyword: 0 for iskeyword in inStreamKeywords}
    for extrakeyword in ParseINIFile():
        if extrakeyword not in keywords:
            keywords.append(extrakeyword())
    edcodedXerf = 0
    dKeywords = {}
    for keyword in keywords:
        dKeywords[keyword] = []
    for streamkey in inStreamKeywords:
        dKeywords[streamkey] = []

    oPDFParserOBJSTM = None
    stats = True
    unfiltered = False
    casesensitive = False
    overridingfilters = ''
    ## while loop until object is none
    while True:
        if oPDFParserOBJSTM == None:
            object = oPDFParser.GetObject()
        else:
            object = oPDFParserOBJSTM.GetObject()
            if object == None:
                oPDFParserOBJSTM = None
                object = oPDFParser.GetObject()
        if object != None:
            if stats:
                if object.type == PDF_ELEMENT_COMMENT:
                    cntComment += 1
                elif object.type == PDF_ELEMENT_XREF:
                    g_xref_size = object.getXrefSize()
                    if type(g_xref_size) == type(0):
                        xref_size += g_xref_size
                    else:
                        edcodedXerf += 1
                    cntXref += 1
                elif object.type == PDF_ELEMENT_TRAILER:
                    cntTrailer += 1
                    trailer_size += object.getContainsValue()
                elif object.type == PDF_ELEMENT_STARTXREF:
                    cntStartXref += 1
                elif object.type == PDF_ELEMENT_INDIRECT_OBJECT:
                    cntIndirectObject += 1
                    type1 = object.GetType()
                    if not type1 in dicObjectTypes:
                        dicObjectTypes[type1] = [object.id]
                    else:
                        dicObjectTypes[type1].append(object.id)

                    get_js_list = []
                    for keyword in dKeywords.keys():
                        regex = None
                        if keyword == "http":
                            regex = "http"
                        elif keyword == "filepath":
                            regex = ["^((?:\/[a-zA-Z0-9]+(?:_[a-zA-Z0-9]+)*(?:\-[a-zA-Z0-9]+)*(?:.+))+)",
                                     "^[a-zA-Z]:(\\([_a-zA-Z0-9가-힣]+))+\\"]
                        elif keyword == "exe":
                            regex = "exe"
                        elif keyword == "ascii":
                            regex = "([`~!@#$%^&*()-_=+][0-9][0-9A-z]{0,1}){2,}"
                        elif keyword == "ip":
                            regex = "([0-9]{1,3}\.){3}[0-9]{1,3}"

                        if object.ContainsName(keyword, regex):
                            if keyword == "/Length":
                                try:
                                    _length = int(object.getContainsValue(keyword))
                                except ValueError:
                                    _length = "encodingData"
                                if _length == "encodingData" or _length > length_thredhold:
                                    dKeywords[keyword].append("{}_{}".format(_length, object.id))
                            elif keyword == "/JS":
                                dKeywords[keyword].append(object.id)
                                js_value = object.getContainsValue(keyword)
                                get_js_list.append(js_value)
                            else:
                                dKeywords[keyword].append(object.id)
                        #########################

                    regex = "|".join(inStreamKeywords[:-nof_regex])
                    match_values = object.StreamContains(streamkey, not unfiltered,
                                                         casesensitive, regex,
                                                         overridingfilters)
                    #
                    if not match_values:
                        match_values = []

                    for js in get_js_list:
                        temp = object.rfindall(regex, js)
                        for t in temp:
                            match_values.append(t)

                    if len(match_values) != 0:
                        for value in match_values:
                            try:
                                vd = value.decode()
                            except AttributeError:
                                vd = value
                            if "script" == vd.lower():
                                vd = "Script"
                            elif "geticon" == vd.lower():
                                vd = "getIcon"
                            try:
                                temp_list = dKeywords[vd]
                            except KeyError:
                                vd = vd.lower()
                                temp_list = dKeywords[vd]
                            if object.id not in temp_list:
                                temp_list.append(object.id)
                                inStream_dict[vd] += 1

                    for streamkey in inStreamKeywords[-nof_regex:]:

                        regex = None
                        if streamkey == "ascii":
                            regex = "([`~!@#$%^&*()-_=+A-z][0-9][0-9A-z]{0,1}){2,}"
                        elif streamkey == "filepath":
                            regex = ["^((?:\/[a-zA-Z0-9]+(?:_[a-zA-Z0-9]+)*(?:\-[a-zA-Z0-9]+)*(?:.+))+)",
                                     "^[a-zA-Z]:"]

                        value = object.StreamContains(streamkey, not unfiltered, casesensitive,
                                                      regex, overridingfilters)
                        if value:
                            dKeywords[streamkey].append(object.id)
                            inStream_dict[streamkey] += 1
        else:
            break

    nof_stream = 0
    if stats and sum(inStream_dict.values()) > 0:
        for keyword in inStreamKeywords:
            if inStream_dict[keyword] > 0:
                nof_stream += inStream_dict[keyword]

    file_size = getFileSize(file_path) / 1000
    ## 존재여부로 데이터 추출
    bool_type_keys = ["xml", "eval", "chunk", "ip", "domain", "ascii", "base64", "filepath", "exe", "execute",
                      "dll", "powershell", "mkdir", "root", "reg", "http", "Script", "/CreationDate",
                      "/Author", "/Creator", "html", "htm", "%appdata%", "getIcon", "/RichMedia",
                      "subject", "/Subject", "replace", "formcharCode", "sys"]
    df_dict = {"file_name": file_path}

    for key, value in dKeywords.items():
        kl = key.lower()
        if "js" in kl or "javascript" in kl:
            key = "/JS"
        elif "temp" in kl or "tmp" in kl:
            key = "temp,tmp"
        elif key in bool_type_keys:
            if key == "exe" or key == "execute":
                key = "exe"
            elif key == "/Creator" or key == "/Author":
                key = "/Author"
            elif key == "html" or key == "htm":
                key = "html"
            elif key == "subject" or key == "/Subject":
                key = "subject"

            if key in df_dict:
                if df_dict[key] > 0:
                    continue
                else:
                    df_dict[key] = 1
            else:
                if len(value) > 0:
                    df_dict[key] = 1

        if key in df_dict:
            df_dict[key] += len(value)
        else:
            df_dict[key] = len(value)
    df_dict["xref_size"] = xref_size
    df_dict["trailer_size"] = trailer_size
    df_dict["file_size"] = file_size
    df_dict["nof_stream"] = nof_stream

    return df_dict

def get_pdf_detail_info(file_path: str = None,
                        out_dir: str = None,
                        bft_dict:dict = None,
                        pdf_obj:object = None,
                        ip_yara:object = None,
                        url_yara:object = None,
                        input_data:dict = None,
                        p_count:int = 0,
                        sha256: str = None,
                        md5: str = None) -> None:

    bft_dict['pdfInfo']['f_id'] = bft_dict['basicInfo']['f_id']
    if pdf_obj.metadata is None:
        bft_dict['pdfInfo']['author'] = ""
        bft_dict['pdfInfo']['producer'] = ""
        bft_dict['pdfInfo']['creator'] = ""
    else:
        bft_dict['pdfInfo']['author'] = pdf_obj.metadata['author'][:150]
        bft_dict['pdfInfo']['producer'] = pdf_obj.metadata['producer'][:150]
        bft_dict['pdfInfo']['creator'] = pdf_obj.metadata['creator'][:150]

    bft_dict['pdfInfo']['sha256'] = sha256
    bft_dict['pdfInfo']['md5'] = md5
    bft_dict['pdfInfo']['threatobj'] = ""
    bft_dict['pdfInfo']['ipurluriinfo'] = ""
    bft_dict['pdfInfo']['yaradetect'] = ""
    bft_dict['pdfInfo']['embeddingfile'] = 0
    bft_dict['pdfInfo']['jsobfusioncount'] = 0
    bft_dict['pdfInfo']['jscodelist'] = ''
    bft_dict['pdfInfo']['pdfcontent'] = f'{out_dir}/content.txt'
    define_filter_list = ['FlateDecode', 'Fl', 'ASCIIHexDecode', 'AHx', 'ASCII85Decode', 'A85', 'LZWDecode', 'LZW',
                          'RunLengthDecode']
    pdfcontent = ""
    for pages_c in range(0, p_count):
        try:
            page = pdf_obj.load_page(pages_c)
            page = page.get_text()
        except RuntimeError:
            page = ""
        except ValueError:
            page = ""
        pdfcontent += page
    try:
        with open(bft_dict['pdfInfo']['pdfcontent'], 'w') as content:
            content.write(pdfcontent)
    except UnicodeEncodeError:
        with open(bft_dict['pdfInfo']['pdfcontent'], 'w', encoding='utf-8') as content:
            content.write(pdfcontent)
    stream = re.compile(b'/Filter(.*?)stream(.*?)endstream', re.S)  # Normal
    Get_Length = re.compile(b'/Length \d+', re.S)
    pdf_read = open(file_path, 'rb').read()

    length_list = []
    ipyara = ip_yara_detect(pdf_read, ip_yara)
    urlyara = url_yara_detect(pdf_read, url_yara)
    bft_dict['pdfInfo']['ipurluriinfo'] += ipyara
    bft_dict['pdfInfo']['ipurluriinfo'] += urlyara
    input_data['ip'] += ipyara.count("|")
    input_data['domain'] += urlyara.count("|")
    for Length_value in re.findall(Get_Length, pdf_read):
        length_list.append(int(str(Length_value).split(" ")[-1].replace("'", "")))

    with open(file_path, 'rb') as pdf:
        with open(f'{out_dir}/{sha256}.txt', 'w+') as log:
            for i in pdf.readlines():
                log.writelines(str(i))

    decodeList = list()
    for si, s in enumerate(re.findall(stream, pdf_read)):
        temp_filters = list()
        i = si + 1
        find_filters = re.split(r" |/|\]|\[|\\n|\>>|\\r", str(s[0]))
        for filter in find_filters:
            if filter in define_filter_list:
                temp_filters.append(filter)
                decodeList.append(filter)

        try:
            filtered_data = ""

            if not os.path.exists(f'{out_dir}/js/'):
                os.makedirs(f'{out_dir}/js/')
            if not os.path.exists(f'{out_dir}/data/'):
                os.makedirs(f'{out_dir}/data/')

            for index, filter in enumerate(temp_filters):

                data = UnFilters(filter, s)

                if len(temp_filters) != 0:
                    js_file = f'{out_dir}/js/{i}_{index}'
                    data_file = f'{out_dir}/data/{i}_{index}_data.txt'
                else:
                    js_file = f'{out_dir}/js/{i}_'
                    data_file = f'{out_dir}/data/{i}_data.txt'

                try:
                    data = data.decode('utf-8')
                except AttributeError:
                    data = str(data)
                except UnicodeDecodeError:
                    data = str(data)

                if "eval(" in data:
                    try:
                        with open(f'{js_file}_1.js', 'w') as writer:
                            writer.write(data)
                    except UnicodeDecodeError:
                        with open(f'{js_file}_1.js', 'w', encoding='utf-8') as writer:
                            writer.write(data)
                    except UnicodeEncodeError:
                        with open(f'{js_file}_1.js', 'w', encoding='utf-8') as writer:
                            writer.write(data)

                    recuv_js(f'{js_file}_1.js')
                else:
                    try:
                        with open(data_file, 'w') as writer:
                            writer.write(data)
                    except UnicodeDecodeError:
                        with open(data_file, 'w', encoding='utf-8') as writer:
                            writer.write(data)
                    except UnicodeEncodeError:
                        with open(data_file, 'w', encoding='utf-8') as writer:
                            writer.write(data)
                filtered_data += data

            with open(f'{out_dir}/data/{i}_filtered_data.txt', 'w') as wfr:
                wfr.write(filtered_data)
        except UnicodeDecodeError:
            strip_data = s[1].strip(b'\r\n')
            data2 = zlib.decompress(strip_data).decode('UTF-8', errors='ignore')
            data_file = f'{out_dir}/data/{i}_data.txt'
            try:
                with open(data_file, 'w', encoding='utf-8') as writer_4:
                    writer_4.write(data2)
            except UnicodeDecodeError:
                with open(data_file, 'w', encoding='cp949') as writer_4:
                    writer_4.write(data2)

    result_list = list(set(decodeList))
    decode_cnt = len(result_list)  # 압축영역 갯수
    with open(f'{out_dir}/filters.txt', 'w+') as wr:
        wr.write(str(result_list))
    bft_dict['pdfInfo']['decomlist'] = ",".join(result_list)
    bft_dict['pdfInfo']['decomcount'] = decode_cnt
    bft_dict['pdfInfo']['jsobfusioncount'] = get_max_filter_js(out_dir)

    pdf_Analyzer(indir=f'{out_dir}', __dict=bft_dict['pdfInfo'], sha256=sha256)
    input_data["cve"] = bft_dict['pdfInfo']['cvedecte'].count("|")
    input_data["yara"] = bft_dict['pdfInfo']['yaradetect'].count("|") + bft_dict['pdfInfo']['binaryyaradetect'].count("|")

def pdfparser(file_path: str = None) -> pd.DataFrame:

    ##
    sha256 = hashlib.sha256(open(file_path, 'rb').read()).hexdigest()
    md5 = hashlib.md5(open(file_path, 'rb').read()).hexdigest()
    out_dir = "output/pdf/" + sha256
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    ##

    start_time = int(time.time() * 1000)
    date_format = "%Y-%m-%d %H:%M:%S.%f"
    LoadDecoders('', True)

    bft_dict = get_setting("pdf_form")
    ## Yara Detect, ip and url
    ip_yara = yara.compile(YARA_DIR + get_setting('ip_yara_detect'))
    url_yara = yara.compile(YARA_DIR + get_setting('url_yara_detect'))

    try:
        pdf_obj = fitz.open(file_path)
    except fitz.fitz.FileDataError:
        return get_model_input(file_path)

    p_count = pdf_obj.page_count

    ## pdf metadata resource
    Fsize = os.path.getsize(file_path)
    bft_dict['basicInfo']['sha256'] = sha256
    bft_dict['basicInfo']['md5'] = md5
    bft_dict['basicInfo']['filetype'] = 0
    bft_dict['basicInfo']['filesize'] = Fsize
    bft_dict['basicInfo']['numofpage'] = p_count
    bft_dict['basicInfo']['analysisdate'] = get_current_date()
    cdate = pdf_obj.metadata['creationDate']
    mdate = pdf_obj.metadata['modDate']

    ## date format resource
    if len(cdate) < 16:
        ctime = cdate
    else:
        ctime = pdf_obj.metadata['creationDate'][2:16]
    if len(mdate) < 16:
        mtime = cdate
    else:
        mtime = pdf_obj.metadata['modDate'][2:16]
    bft_dict['basicInfo']['docversion'] = pdf_obj.metadata['format']
    try:
        bft_dict['basicInfo']['creationdate'] = datetime.strptime(ctime, "%Y%m%d%H%M%S").strftime(date_format)
    except ValueError:
        pass
    try:
        bft_dict['basicInfo']['modificationdate'] = datetime.strptime(mtime, "%Y%m%d%H%M%S").strftime(date_format)
    except ValueError:
        pass

    ## AI model input form generate
    input_data = get_model_input(file_path)
    get_pdf_detail_info(file_path, out_dir, bft_dict, pdf_obj, ip_yara, url_yara, input_data, p_count, sha256, md5)
    end_time = int(time.time() * 1000)
    bft_dict['basicInfo']['analysistime'] = end_time - start_time

    result = Result(bft_dict, input_data)
    return result

    # return SimpleNamespace(bft_dict=bft_dict, input_data=input_data)



def pdf_Analyzer(indir, __dict, sha256):
    rule_match_result = ""
    ipyara_result = []
    urlyara_result = []
    metadata = ""

    rules = yara.compile(YARA_DIR + get_setting('pdf_yara'))
    cve_rules = yara.compile(YARA_DIR + get_setting('cve_yara'))
    ip_rules = yara.compile(YARA_DIR + get_setting('ip_yara_detect'))
    url_rules = yara.compile(YARA_DIR + get_setting('url_yara_detect'))

    # # 0. Log file Analyzer

    # ## 1. JS EndState Count File Check
    # # folder Check
    js_list = {}
    try:
        lenfiles = os.listdir(f'{indir}/js')
        for _f in lenfiles:
            try:
                js_list[_f.split("_")[0]] += 1
            except KeyError:
                js_list[_f.split("_")[0]] = 1
    except FileNotFoundError:
        lenfiles = 0
    objfile = js2py.get_file_contents(f'{indir}/{indir.split("/")[-1]}.txt')
    if lenfiles == 0:  # 필터(압축) 가 없으면 txt파일 분석 (data)
        rule_match_result = rules.match(data=objfile)
        metadata += '|'.join(list(map(str, rule_match_result)))

    else:
        ## TEST 추가
        if not js_list.items():
            path = Path(f'{indir}/data')
            for p in path.glob("*_data.txt"):
                with open(p, 'r', encoding='utf-8') as data_reader:
                    read_data = data_reader.read()
                    rule_match_result = rules.match(data=read_data)
                    metadata += '|'.join(list(map(str, rule_match_result)))

                    ipyara = ip_rules.match(data=read_data)
                    urlyara = url_rules.match(data=read_data)

                    if len(ipyara):
                        for val in ipyara[0].strings[0].instances:
                            ipyara_result.append(str(val))

                    if len(urlyara):
                        for val in urlyara[0].strings[0].instances:
                            urlyara_result.append(str(val))

        try:
            for js_index, index in js_list.items():
                js_file = f'{indir}/js/{js_index}_0_{index}.js'
                with open(js_file, 'r') as JS_reader:
                    JS_data = JS_reader.read()
                    rule_match_result = rules.match(data=JS_data)
                    metadata += '|'.join(list(map(str, rule_match_result)))
                __dict['jscodelist'] += f'{js_file},'
        except FileNotFoundError:
            path = Path(f'{indir}/data')
            for p in path.glob("*_data.txt"):
                if "filtered" in p.stem:
                    continue

                with open(p, 'r') as data_reader:
                    rule_match_result = rules.match(data=data_reader.read())
                    metadata += '|'.join(list(map(str, rule_match_result)))

    # Js file Analyzer
    # Keywords
    ksshinkeywords = ['binary_Object', 'JS', 'JavaScript', 'AA', 'OpenAction', 'AcroForm', 'RichMedia',
                      'Launch',
                      'EmbeddedFile', 'EmbeddedFiles', 'XFA', 'FlateDecode', 'Objstm', 'ObjStm']
    setlog2 = list()

    split_objfile = re.split(r"/| |\.", objfile)
    for keyword in ksshinkeywords:
        for log in split_objfile:
            if keyword == log:
                setlog2.append(log)
    threat_obj = [i for i, j in zip(setlog2, ksshinkeywords) if i == j]
    __dict['threatobj'] = ",".join(threat_obj)
    __dict['yaradetect'] = metadata
    binary_detect = rules.match(f"{indir}/{sha256}.txt")
    cve_detect = cve_rules.match(f"{indir}/{sha256}.txt")
    binaryyara_metadata = '|'.join(list(map(str, binary_detect)))
    cveyara_metadata = '|'.join(list(map(str, cve_detect)))


    __dict['binaryyaradetect'] = binaryyara_metadata
    __dict['cvedecte'] = cveyara_metadata

    ## 추가
    __dict['ipurluriinfo'] += '|'.join(map(str, set(ipyara_result)))
    __dict['ipurluriinfo'] += '|'.join(map(str, set(urlyara_result)))