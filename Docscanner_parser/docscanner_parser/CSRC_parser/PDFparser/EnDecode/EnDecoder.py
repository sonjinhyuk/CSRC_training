import zlib
import binascii
import sys

def C2BIP3(string):
    if sys.version_info[0] > 2:
        if type(string) == bytes:
            return string
        else:
            return bytes([ord(x) for x in string])
    else:
        return string

def pattern_ASCII_rex(match):
    match = match.group()
    trans_str2 = match.replace("#", "")
    trans_str3 = bytes.fromhex(trans_str2).decode("ASCII")
    return trans_str3

if sys.version_info[0] >= 3:
    from io import StringIO
    import urllib.request
    urllib23 = urllib.request
else:
    #python2
    from cStringIO import StringIO
    import urllib2
    urllib23 = urllib2

def C2BIP3(string):
    if sys.version_info[0] > 2:
        if type(string) == bytes:
            return string
        else:
            return bytes([ord(x) for x in string])
    else:
        return string

dic = list()

def ASCIIHexDecode(data):
    ascii_data = binascii.unhexlify(''.join([c for c in data.decode('utf-8') if c not in ' \t\n\r']).rstrip('>')).decode('utf-8')
    return ascii_data

def ASCII85Decode(data):
  import struct
  n = b = 0
  out = ''
  for c in data:
    if '!' <= c and c <= 'u':
      n += 1
      b = b*85+(ord(c)-33)
      if n == 5:
        out += struct.pack('>L',b)
        n = b = 0
    elif c == 'z':
      assert n == 0
      out += '\0\0\0\0'
    elif c == '~':
      if n:
        for _ in range(5-n):
          b = b*85+84
        out += struct.pack('>L',b)[:n-1]
      break
  return out

class LZWDecoder(object):
    def __init__(self, fp):
        self.fp = fp
        self.buff = 0
        self.bpos = 8
        self.nbits = 9
        self.table = None
        self.prevbuf = None
        return

    def readbits(self, bits):
        v = 0
        while 1:
            # the number of remaining bits we can get from the current buffer.
            r = 8-self.bpos
            if bits <= r:
                # |-----8-bits-----|
                # |-bpos-|-bits-|  |
                # |      |----r----|
                v = (v<<bits) | ((self.buff>>(r-bits)) & ((1<<bits)-1))
                self.bpos += bits
                break
            else:
                # |-----8-bits-----|
                # |-bpos-|---bits----...
                # |      |----r----|
                v = (v<<r) | (self.buff & ((1<<r)-1))
                bits -= r
                x = self.fp.read(1)
                if not x: raise EOFError
                self.buff = ord(x)
                self.bpos = 0
        return v

    def feed(self, code):
        x = ''
        if code == 256:
            self.table = [ chr(c) for c in range(256) ] # 0-255
            self.table.append(None) # 256
            self.table.append(None) # 257
            self.prevbuf = ''
            self.nbits = 9
        elif code == 257:
            pass
        elif not self.prevbuf:

            x = self.prevbuf = self.table[code]
        else:
            if code < len(self.table):
                x = self.table[code]
                self.table.append(self.prevbuf+x[0])
            else:
                self.table.append(self.prevbuf+self.prevbuf[0])
                x = self.table[code]
            l = len(self.table)
            if l == 511:
                self.nbits = 10
            elif l == 1023:
                self.nbits = 11
            elif l == 2047:
                self.nbits = 12
            self.prevbuf = x
        return x

    def run(self):
        while 1:
            try:
                code = self.readbits(self.nbits)
            except EOFError:
                break
            x = self.feed(code)
            yield x
        return

####

def LZWDecode(data):
    # print(data)
    try :
        data2 = ''.join(LZWDecoder(StringIO(data)).run())
    except TypeError:
        data2 = str(data)
        data2 = ''.join(LZWDecoder(StringIO(data2)).run())
    return data2


def RunLengthDecode(data):
    f = StringIO(data)
    decompressed = ''
    runLength = ord(f.read(1))
    while runLength:
        if runLength < 128:
            decompressed += f.read(runLength + 1)
        if runLength > 128:
            decompressed += f.read(1) * (257 - runLength)
        if runLength == 128:
            break
        runLength = ord(f.read(1))
    return decompressed

def Uncompress(data):
    zobj = zlib.decompressobj()
    decom_data = zobj.decompress(data)
    return decom_data

def Wbit_Uncompress(data):
    stringData = C2BIP3(data)
    zobj = zlib.decompressobj(-zlib.MAX_WBITS)
    return zobj.decompress(stringData)

def UnFilters(filter, s):

    data1 = ""
    if "FlateDecode" in filter:
        strip_data = s[1].strip(b'\r\n')
        try:
            data1 = Uncompress(strip_data)
        except:
            try:
                data1 = zlib.decompress(strip_data).decode('UTF-8', errors='ignore')
            except:
                data1 = s[1]
            pass
    elif "ASCIIHexDecode" in filter:
        try:
            data1 = ASCIIHexDecode(s[1])
        except:
            data1 = s[1]
            pass

    elif "ASCII85Decode" in filter:
        # decodeList.append("ASCII85Decode")

        try:
            data1 = ASCII85Decode(s[1].rstrip('>'))
        except:
            data1 = s[1]
            pass

    elif "LZWDecode" in filter:
        # decodeList.append("LZWDecode")

        try:
            data1 = LZWDecode(s[1])
        except:
            data1 = s[1]
            pass

    elif "RunLengthDecode" in filter:
        # decodeList.append("RunLengthDecode")

        try:
            data1 = RunLengthDecode(s[1])
        except:
            data1 = s[1]
            pass
    else:
        data1 = s[1]


    return data1
