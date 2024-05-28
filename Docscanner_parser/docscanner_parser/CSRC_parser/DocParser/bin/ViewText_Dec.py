# -*- coding: utf-8 -*-
from olefile import OleFileIO
from struct import unpack
import zlib
from collections import namedtuple
from Cryptodome.Cipher import AES
import sys
import os


def getbitvalue(val, offset, size):
    val = val >> offset
    tmp = 1
    size -= 1
    while size > 0:
        tmp = tmp | (1 << size)
        size -= 1
    return val & tmp
# endfunction


def bitMap(val, names, offsets, sizes):
    Flag = namedtuple("Flag", names)
    return Flag(*[getbitvalue(val, offsets[i], sizes[i]) for i in range(len(names))])
# endfunction


def GetTag(val):
    RECORD_MEMBER_NAME = ["TagID", "Level", "Size"]
    RECORD_MEMBER_OFFSET = [0, 10, 20]
    RECORD_MEMBER_SIZE = [10, 10, 12]
    return bitMap(val, RECORD_MEMBER_NAME, RECORD_MEMBER_OFFSET, RECORD_MEMBER_SIZE)
# endfunction


def GetTagObject(data, offset):
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
# endfunction


# file1 = 분석 대상 파일 이름
file1 = sys.argv[1]
f_name = os.path.basename(file1)


# file2 = 분석 대상 뷰 섹션 이름
file2 = str(sys.argv[2])
file_path = file1

viewfile_name = file2
viewsection_name = file2.encode('utf8')
viewsection_name = viewsection_name.decode('utf8')
viewsection_name = viewsection_name.replace("'", '')
ole = OleFileIO(file_path, write_mode=True)
content = ole.openstream(viewsection_name).read()[4:]
seed = unpack('<L', content[:4])[0]


def rand():
    global seed
    seed = (214013 * seed + 2531011) & 0x7fffffff
    return seed >> 16

content = list(content)

random = [0 for i in range(0, 256)]
b = 0
for i in range(256):
    if b == 0:
        a = rand() & 0xff
        b = (rand() & 15) + 1
    random[i] = a
    b -= 1

for i in range(256):
    content[i] = chr(content[i] ^ random[i])

offset = 4 + (seed & 0x0f)
Hash = [0 for i in range(0, 80)]

for i in range(80):
    Hash[i] = content[offset + i]

content = ''.join(map(str, content))
key = ''.join(map(str, Hash[:offset + 6]))
print(key)

content = content[256:]
padding = 16 - (len(content) % 16)
padding = (chr(padding) * padding)

cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
cipher_decrypt = cipher.decrypt((content + padding).encode('utf-8'))
try:
    zobj = zlib.decompressobj(-zlib.MAX_WBITS)
    result = zobj.decompress(cipher_decrypt)
except Exception as e:
    print(e)


dec_path = 'C:/HWP_output/' + f_name
view_name = file2.replace('/', '_')

viewsection_dec = open(dec_path + '/' + view_name + '_Dec.txt', 'wb')
viewsection_dec.write(result)
viewsection_dec.close()

Section_data = open(dec_path + '/' + view_name + '_Dec.txt', "rb").read()
file_offset = 0
global Section_info1
Section_info1 = ''
while offset < len(Section_data):
    Section_offset_info = "[0x%08X]" % offset,
    taginfo, offset = GetTagObject(Section_data, offset)
    Section_info = (Section_offset_info, taginfo.TagID, taginfo.Level, hex(taginfo.Size), taginfo.Size)
    Section_info = str(list(Section_info))
    Section_info1 = Section_info + '\n' + Section_info1
    if (taginfo.TagID == int(67) and (taginfo.Size > int(15000))):
        print("(((((((((((((((((((((((((((((((((((((((((((((((((((((")
        print('TagID : ' + str(taginfo.TagID), 'TagSize : ' + str(taginfo.Size), "Exploit.HWP.Generic.43" + "(" + "HWPTAG_PARA_TEXT" + ")", viewfile_name + '.txt')

ViewSection_info_write = open(dec_path + '/' + 'ViewSection_info.txt', 'a')
ViewSection_info_write.write(view_name)
ViewSection_info_write.write('\n')
ViewSection_info_write.write(Section_info1)
ViewSection_info_write.write('\n')
ViewSection_info_write.close()

ole.close()
