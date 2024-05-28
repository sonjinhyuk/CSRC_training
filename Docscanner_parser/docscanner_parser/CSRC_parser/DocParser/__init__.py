from datetime import datetime
import olefile
import pandas as pd

from .hwp_preprocess import HwpParser
from .OleParser import OleParser
from .OoXMLParser import OoXMLParser
from CSRC_parser import get_hash
from ..utils import create_directory
import shutil
import zipfile, os
import xml.etree.ElementTree as ET
import hashlib

# 파일이 암호화 되어 있다면 True 반환
def is_encrypt(fpath: str) -> bool:
    import oletools.oleid
    oid = oletools.oleid.OleID(fpath)
    for i in oid.check():
        if i.id == 'encrypted' and i.value:
            return True
    return False

decompile_size = 15000

#error code 정의 필요
def ole_main(file: str) -> pd.DataFrame or tuple:

    sha256, md5 = get_hash(file)
    source_file_name = os.path.basename(file).split('.')[0]

    """
        OLE file type parser
        Args:
            :param file: input file
            :param source_file_name: input file name
            :param out_dir: output directory
            :param sha256: hash value(sha256)
            :param md5: hash value(md5)
        return:
            :return parsing result(object): parsing result
            :return app: file type
            :return out_dir: output directory
    """

    ##
    out_dir = "output/ole/" + sha256
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    ##

    is_enc = is_encrypt(file)
    create_directory(out_dir)

    if is_enc:
        create_directory(f"{out_dir}/Encrypted_file")
        with open(f"{out_dir}/Encrypted_file/{sha256}.encry", "w") as f:
            f.write("encrypted")
        ## file copy to Encrypted_file
        shutil.copy(file, f"{out_dir}/Encrypted_file/{sha256}")
        return {"error": "Encrypted File"}, None, None

    try:
        ole = olefile.OleFileIO(file)
    except OSError:
        create_directory(f"{out_dir}/not_ole_file")
        with open(f"{out_dir}/not_ole_file/{sha256}.encry", "w") as f:
            f.write("encrypted")
        # file copy to not OLE File
        shutil.copy(file, f"{out_dir}/not_ole_file/{sha256}")
        return {"error": "Not OLE File"}, None, None

    stream_list = ole.listdir()
    ole.close()

    app = None
    for stream in stream_list:
        if '\x05HwpSummaryInformation' in '/'.join(stream):
            app = 'hwp'
        elif 'worddocument' in '/'.join(stream).lower():
            app = 'doc'
        elif 'powerpoint document' in '/'.join(stream).lower():
            app = 'ppt'
        elif 'workbook' in '/'.join(stream).lower():
            app = 'xls'
        else:
            app = None

        if app is not None:
            break

    if app is None:
        create_directory(f"{out_dir}/not_supported_file")
        with open(f"{out_dir}/not_supported_file/{sha256}.nsf", "w") as f:
            f.write("not_supported_file")
        ## file copy to not supported file
        shutil.copy(file, f"{out_dir}/not_supported_file/{sha256}")
        return {"error": "This file is not supported"}, None, None
    else:
        ## file path, directory setting
        # traget_file, out_dir, file_type = set_directory(file, out_dir, app, sha256)
        traget_file, out_dir, file_type = file, out_dir, app

        ## The OLE format has a non-extensible version of HWP and ms-office.
        ## Therefore, the OLE format is divided into two types: HWP and ms-office.
        ## Different function calls for two different types

        if app == 'hwp':
            hp = HwpParser(traget_file, app, source_file_name, out_dir, file_type, sha256, md5)
            return hp, app
        else:
            ms = OleParser(traget_file, app, source_file_name, out_dir, file_type, sha256, md5)
            return ms, app

def ooxml_main(file: str) -> pd.DataFrame or tuple:

    sha256, md5 = get_hash(file)
    source_file_name = os.path.basename(file).split('.')[0]

    """
        Ooxml file type parser
        Args:
            :param file: input file
            :param source_file_name: input file name
            :param out_dir: output directory
            :param sha256: hash value(sha256)
            :param md5: hash value(md5)
        return:
            :return parsing result(object): parsing result
            :return app: file type
            :return out_dir: output directory
    """

    ##
    out_dir = "output/ooxml/" + sha256
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    ##


    app = ""
    create_directory(out_dir)
    if sha256 is None or md5 is None:
        sha256, md5 = get_hash(file)
    try:
        ## ooxml file unzip
        with zipfile.ZipFile(file) as ez:
            extract_path = f'{out_dir}/extract/{sha256}'
            create_directory(extract_path)
            ez.extractall(extract_path)
            with open(f'{extract_path}/mimetype', 'rt', encoding='utf-8') as f:
                mime_str = f.readline()
                if 'hwp+zip' in mime_str:
                    app = 'hwpx'
    except FileNotFoundError:
        files = os.listdir(f'{extract_path}')
        app = ""
        for fi in files:
            if 'word' == fi:
                app = 'docx'
            elif 'ppt' == fi:
                app = 'pptx'
            elif 'xl' == fi:
                app = 'xlsx'

        if app == "":
            try:
                tree = ET.parse(f'{extract_path}/docProps/app.xml')
            except FileNotFoundError:
                try:
                    tree = ET.parse(f'{extract_path}/docProps\\app.xml')
                except FileNotFoundError as ffe:
                    print(f'    [\033[31mDebug\033[0m] OoxmlParser \033[91m{ffe}\033[0m')
                    return {"error": "not_supported_file"}, None

            root = tree.getroot()

            for child in root:
                tag = child.tag.split('}')[1].lower()
                if tag == 'application':
                    if 'powerpoint' in child.text.lower():
                        app = 'pptx'
                    elif 'excel' in child.text.lower():
                        app = 'xlsx'
                    elif 'word' in child.text.lower():
                        app = 'docx'
    except Exception as e:
        pass

    if app == "":
        create_directory(f"{out_dir}/not_supported_file")
        with open(f"{out_dir}/not_supported_file/{sha256}.nsf", "w") as f:
            f.write("not_supported_file")
        return {"error": "This file is not supported"}, None
    else:
        traget_file, out_dir, file_type = file, out_dir, app
        ooxml = OoXMLParser(traget_file, app, source_file_name, out_dir, file_type, extract_path, sha256, md5)
    return ooxml, app

def get_current_date() -> str:
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def get_file_type(app: str) -> dict:
    key = app
    if app == 'hwp':
        value = 1
    elif app == 'hwpx':
        value = 11
    elif app == 'doc':
        value = 2
    elif app == 'docx':
        value = 22
    elif app == 'ppt':
        value = 3
    elif app == 'pptx':
        value = 33
    elif app == 'xls':
        value = 4
    elif app == 'xlsx':
        value = 44
    else:
        value = -1

    return {"type": key, "type_id": value}
