import binascii
import hashlib
import sys
import time
import regex as re
import zlib
import os
from io import StringIO
import configparser as ConfigParser
import textwrap

from .cDumpStream import cDumpStream
from .LZWDecoder import LZWDecoder
from .cPDFParseDictionary import cPDFParseDictionary
from .cPDFDefine import __maximum_python_version__, __minimum_python_version__, __author__, __version__, __date__, __minimum_python_version__, __description__
from .cPDFDefine import CHAR_WHITESPACE, CHAR_REGULAR, CHAR_DELIMITER, CONTEXT_OBJ, CONTEXT_NONE, CONTEXT_XREF, CONTEXT_TRAILER
from .cPDFDefine import PDF_ELEMENT_TRAILER, PDF_ELEMENT_XREF, PDF_ELEMENT_COMMENT, PDF_ELEMENT_MALFORMED, PDF_ELEMENT_STARTXREF, PDF_ELEMENT_INDIRECT_OBJECT
from .cPDFDefine import dumplinelength
from pathlib import Path




# Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        if type(string) == bytes:
            return string
        else:
            return bytes([ord(x) for x in string])
    else:
        return string


# Convert 2 String If Python 3
def C2SIP3(bytes):
    if sys.version_info[0] > 2:
        return ''.join([chr(byte) for byte in bytes])
    else:
        return bytes


# CIC: Call If Callable
def CIC(expression):
    if callable(expression):
        return expression()
    else:
        return expression


# IFF: IF Function
def IFF(expression, valueTrue, valueFalse):
    if expression:
        return CIC(valueTrue)
    else:
        return CIC(valueFalse)


def Timestamp(epoch=None):
    if epoch == None:
        localTime = time.localtime()
    else:
        localTime = time.localtime(epoch)
    return '%04d%02d%02d-%02d%02d%02d' % localTime[0:6]


def CopyWithoutWhiteSpace(content):
    result = []
    for token in content:
        if token[0] != CHAR_WHITESPACE:
            result.append(token)
    return result


def Obj2Str(content):
    return ''.join(map(lambda x: repr(x[1])[1:-1], CopyWithoutWhiteSpace(content)))


def Canonicalize(sIn):
    if sIn == '':
        return sIn
    elif sIn[0] != '/':
        return sIn
    elif sIn.find('#') == -1:
        return sIn
    else:
        i = 0
        iLen = len(sIn)
        sCanonical = ''
        while i < iLen:
            if sIn[i] == '#' and i < iLen - 2:
                try:
                    sCanonical += chr(int(sIn[i + 1:i + 3], 16))
                    i += 2
                except:
                    sCanonical += sIn[i]
            else:
                sCanonical += sIn[i]
            i += 1
        return sCanonical


def EqualCanonical(s1, s2):
    return Canonicalize(s1) == s2


def ConditionalCanonicalize(sIn, nocanonicalizedoutput):
    if nocanonicalizedoutput:
        return sIn
    else:
        return Canonicalize(sIn)


def EqualCanonical(s1, s2):
    return Canonicalize(s1) == s2


def IsNumeric(str):
    return re.match('^[0-9]+', str)


def IIf(expr, truepart, falsepart):
    if expr:
        return truepart
    else:
        return falsepart


def FlateDecode(data):
    try:
        a = zlib.decompress(C2BIP3(data))
        return a
    except zlib.error as e:
        # if len(data) <= 10:
        #     raise
        oDecompress = zlib.decompressobj()
        oStringIO = StringIO()
        count = 0
        for byte in C2BIP3(data):
            try:
                oStringIO.write(oDecompress.decompress(byte))
                count += 1
            except:
                break
        if len(data) - count <= 2:
            return oStringIO.getvalue()
        else:
            return data

def ASCIIHexDecode(data):
    return binascii.unhexlify(''.join([c for c in data if c not in ' \t\n\r']).rstrip('>'))


def ASCII85Decode(data):
    import struct
    n = b = 0
    out = b''
    for c in data:
        if '!' <= c and c <= 'u':
            n += 1
            b = b * 85 + (ord(c) - 33)
            if n == 5:
                out += struct.pack('>L', b)
                n = b = 0
        elif c == 'z':
            assert n == 0
            out += b'\0\0\0\0'
        elif c == '~':
            if n:
                for _ in range(5 - n):
                    b = b * 85 + 84
                out += struct.pack('>L', b)[:n - 1]
            break
    return out


def LZWDecode(data):
    return ''.join(LZWDecoder(StringIO(data)).run())


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
    #    return sub(r'(\d+)(\D)', lambda m: m.group(2) * int(m.group(1)), data)
    return decompressed


def TestPythonVersion(enforceMaximumVersion=False, enforceMinimumVersion=False):
    if sys.version_info[0:3] > __maximum_python_version__:
        if enforceMaximumVersion:
            print('This program does not work with this version of Python (%d.%d.%d)' % sys.version_info[0:3])
            print('Please use Python version %d.%d.%d' % __maximum_python_version__)
            sys.exit()
        else:
            print('This program has not been tested with this version of Python (%d.%d.%d)' % sys.version_info[0:3])
            print('Should you encounter problems, please use Python version %d.%d.%d' % __maximum_python_version__)
    if sys.version_info[0:3] < __minimum_python_version__:
        if enforceMinimumVersion:
            print('This program does not work with this version of Python (%d.%d.%d)' % sys.version_info[0:3])
            print('Please use Python version %d.%d.%d' % __maximum_python_version__)
            sys.exit()
        else:
            print('This program has not been tested with this version of Python (%d.%d.%d)' % sys.version_info[0:3])
            print('Should you encounter problems, please use Python version %d.%d.%d' % __maximum_python_version__)


def GetArguments():
    arguments = sys.argv[1:]
    envvar = os.getenv('PDFPARSER_OPTIONS')
    if envvar == None:
        return arguments
    return envvar.split(' ') + arguments


def PrintManual():
    manual = '''
Manual:

This manual is a work in progress.

There is a free PDF analysis book:
https://blog.didierstevens.com/2010/09/26/free-malicious-pdf-analysis-e-book/

Option -o is used to select objects by id. Provide a single id or multiple ids separated by a comma (,).

When environment variable PDFPARSER_OPTIONS is defined, the options it defines are added implicitely to the command line arguments.
Use this to define options you want included with each use of PDFparser.py.
Like option -O, to parse stream objects (/ObjStm).
By defining PDFPARSER_OPTIONS=-O, PDFparser will always parse stream objects (when found).
PS: this feature is experimental.

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))


def GetScriptPath():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(sys.argv[0])


def File2Strings(filename):
    try:
        f = open(filename, 'r')
    except:
        return None
    try:
        return map(lambda line: line.rstrip('\n'), f.readlines())
    except:
        return None
    finally:
        f.close()

def ProcessAt(argument):
    if argument.startswith('@'):
        strings = File2Strings(argument[1:])
        if strings == None:
            raise Exception('Error reading %s' % argument)
        else:
            return strings
    else:
        return [argument]

def LoadDecoders(decoders, verbose):
    if decoders == '':
        return
    scriptPath = GetScriptPath()
    for decoder in sum(map(ProcessAt, decoders.split(',')), []):
        try:
            if not decoder.lower().endswith('.py'):
                decoder += '.py'
            if os.path.dirname(decoder) == '':
                if not os.path.exists(decoder):
                    scriptDecoder = os.path.join(scriptPath, decoder)
                    if os.path.exists(scriptDecoder):
                        decoder = scriptDecoder
            exec(open(decoder, 'r').read(), globals(), globals())
        except Exception as e:
            print('Error loading decoder: %s' % decoder)
            if verbose:
                raise e


def ParseINIFile():
    oConfigParser = ConfigParser.ConfigParser(allow_no_value=True)
    oConfigParser.optionxform = str
    oConfigParser.read(os.path.join(GetScriptPath(), 'pdfid.ini'))
    keywords = []
    if oConfigParser.has_section('keywords'):
        for key, value in oConfigParser.items('keywords'):
            if not key in keywords:
                keywords.append(key)
    return keywords


def Timestamp(epoch=None):
    if epoch == None:
        localTime = time.localtime()
    else:
        localTime = time.localtime(epoch)
    return '%04d%02d%02d-%02d%02d%02d' % localTime[0:6]


def YARACompile(ruledata):
    # if ruledata.startswith('#'):
    #     if ruledata.startswith('#h#'):
    #         rule = binascii.a2b_hex(ruledata[3:])
    #     elif ruledata.startswith('#b#'):
    #         rule = binascii.a2b_base64(ruledata[3:])
    #     elif ruledata.startswith('#s#'):
    #         rule = 'rule string {strings: $a = "%s" ascii wide nocase condition: $a}' % ruledata[3:]
    #     elif ruledata.startswith('#q#'):
    #         rule = ruledata[3:].replace("'", '"')
    #     else:
    #         rule = ruledata[1:]
    #     return yara.compile(source=rule)
    # else:
    #     dFilepaths = {}
    #     if os.path.isdir(ruledata):
    #         for root, dirs, files in os.walk(ruledata):
    #             for file in files:
    #                 filename = os.path.join(root, file)
    #                 dFilepaths[filename] = filename
    #     else:
    #         for filename in ProcessAt(ruledata):
    #             dFilepaths[filename] = filename
    #     return yara.compile(filepaths=dFilepaths)
    return ""

def EqualCanonical(s1, s2):
    return Canonicalize(s1) == s2






def TrimLWhiteSpace(data):
    while data != [] and data[0][0] == CHAR_WHITESPACE:
        data = data[1:]
    return data


def TrimRWhiteSpace(data):
    while data != [] and data[-1][0] == CHAR_WHITESPACE:
        data = data[:-1]
    return data


def ConditionalCanonicalize(sIn, nocanonicalizedoutput):
    if nocanonicalizedoutput:
        return sIn
    else:
        return Canonicalize(sIn)



# Convert 2 String If Python 3
def C2SIP3(bytes):
    if sys.version_info[0] > 2:
        return ''.join([str(byte) for byte in bytes])
    else:
        return bytes



def FormatOutput(data, raw):
    if raw:
        if type(data) == type([]):
            return ''.join(map(lambda x: x[1], data))
        else:
            return data
    elif sys.version_info[0] > 2:
        return ascii(data)
    else:
        return repr(data)

def PrintObject(object, options):
    if options.generate:
        PrintGenerateObject(object, options)
    else:
        PrintOutputObject(object, options)



def PrintGenerateObject(object, options, newId=None):
    if newId == None:
        objectId = object.id
    else:
        objectId = newId
    dataPrecedingStream = object.ContainsStream()
    if dataPrecedingStream:
        if options.filter:
            decompressed = object.Stream(True, options.overridingfilters)
            if decompressed == 'No filters' or decompressed.startswith('Unsupported filter: '):
                print('    oPDF.stream(%d, %d, %s, %s)' % (
                objectId, object.version, repr(object.Stream(False, options.overridingfilters).rstrip()),
                repr(re.sub('/Length\s+\d+', '/Length %d', FormatOutput(dataPrecedingStream, True)).strip())))
            else:
                dictionary = FormatOutput(dataPrecedingStream, True)
                dictionary = re.sub(r'/Length\s+\d+', '', dictionary)
                dictionary = re.sub(r'/Filter\s*/[a-zA-Z0-9]+', '', dictionary)
                dictionary = re.sub(r'/Filter\s*\[.+\]', '', dictionary)
                dictionary = re.sub(r'^\s*<<', '', dictionary)
                dictionary = re.sub(r'>>\s*$', '', dictionary)
                dictionary = dictionary.strip()
                print("    oPDF.stream2(%d, %d, %s, %s, 'f')" % (
                objectId, object.version, repr(decompressed.rstrip()), repr(dictionary)))
        else:
            print('    oPDF.stream(%d, %d, %s, %s)' % (
            objectId, object.version, repr(object.Stream(False, options.overridingfilters).rstrip()),
            repr(re.sub('/Length\s+\d+', '/Length %d', FormatOutput(dataPrecedingStream, True)).strip())))
    else:
        print('    oPDF.indirectobject(%d, %d, %s)' % (
        objectId, object.version, repr(FormatOutput(object.content, True).strip())))



def IfWIN32SetBinary(io):
    if sys.platform == 'win32':
        import msvcrt
        msvcrt.setmode(io.fileno(), os.O_BINARY)

# Fix for http://bugs.python.org/issue11395
def StdoutWriteChunked(data):
    if sys.version_info[0] > 2:
        sys.stdout.buffer.write(data)
    else:
        while data != '':
            sys.stdout.write(data[0:10000])
            try:
                sys.stdout.flush()
            except IOError:
                return
            data = data[10000:]


def CombineHexAscii(hexDump, asciiDump):
    if hexDump == '':
        return ''
    return hexDump + '  ' + (' ' * (3 * (dumplinelength - len(asciiDump)))) + asciiDump


# def HexAsciiDump(data):
#     oDumpStream = cDumpStream()
#     hexDump = ''
#     asciiDump = ''
#     for i, b in enumerate(data):
#         if i % dumplinelength == 0:
#             if hexDump != '':
#                 oDumpStream.Addline(CombineHexAscii(hexDump, asciiDump))
#             hexDump = '%08X:' % i
#             asciiDump = ''
#         hexDump += ' %02X' % ord(b)
#         asciiDump += IFF(ord(b) >= 32, b, '.')
#     oDumpStream.Addline(CombineHexAscii(hexDump, asciiDump))
#     return oDumpStream.Content()

def HexAsciiDumpLine(data):
    return HexAsciiDump(data[0:16])[10:-1]

def PrintOutputObject(object, options):
    if options.dump == '-':
        filtered = object.Stream(options.filter == True, options.overridingfilters)
        if filtered == []:
            filtered = ''
        IfWIN32SetBinary(sys.stdout)
        StdoutWriteChunked(filtered)
        return

    print('obj %d %d' % (object.id, object.version))
    if object.objstm != None:
        print(' Containing /ObjStm: %d %d' % object.objstm)
    print(' Type: %s' % ConditionalCanonicalize(object.GetType(), options.nocanonicalizedoutput))
    print(' Referencing: %s' % ', '.join(map(lambda x: '%s %s %s' % x, object.GetReferences())))
    dataPrecedingStream = object.ContainsStream()
    oPDFParseDictionary = None
    if dataPrecedingStream:
        print(' Contains stream')
        if options.debug:
            print(' %s' % FormatOutput(dataPrecedingStream, options.raw))
        oPDFParseDictionary = cPDFParseDictionary(dataPrecedingStream, options.nocanonicalizedoutput)
        if options.hash:
            streamContent = object.Stream(False, options.overridingfilters)
            print('  unfiltered')
            print('   len: %6d md5: %s' % (len(streamContent), hashlib.md5(streamContent).hexdigest()))
            print('   %s' % HexAsciiDumpLine(streamContent))
            streamContent = object.Stream(True, options.overridingfilters)
            print('  filtered')
            print('   len: %6d md5: %s' % (len(streamContent), hashlib.md5(streamContent).hexdigest()))
            print('   %s' % HexAsciiDumpLine(streamContent))
            streamContent = None
    else:
        if options.debug or options.raw:
            print(' %s' % FormatOutput(object.content, options.raw))
        oPDFParseDictionary = cPDFParseDictionary(object.content, options.nocanonicalizedoutput)
    print('')
    oPDFParseDictionary.PrettyPrint('  ')
    print('')
    if options.filter and not options.dump:
        filtered = object.Stream(overridingfilters=options.overridingfilters)
        if filtered == []:
            print(' %s' % FormatOutput(object.content, options.raw))
        else:
            print(' %s' % FormatOutput(filtered, options.raw))
    if options.content:
        if object.ContainsStream():
            stream = object.Stream(False, options.overridingfilters)
            if stream != []:
                print(' %s' % FormatOutput(stream, options.raw))
        else:
            print(''.join([token[1] for token in object.content]))

    if options.dump:
        filtered = object.Stream(options.filter == True, options.overridingfilters)
        if filtered == []:
            filtered = ''
        try:
            fDump = open(options.dump, 'wb')
            try:
                fDump.write(C2BIP3(filtered))
            except:
                print('Error writing file %s' % options.dump)
            fDump.close()
        except:
            print('Error writing file %s' % options.dump)
    print('')
    return





def MatchObjectID(id, selection):
    return str(id) in selection.split(',')


def CharacterClass(byte):
    if byte == 0 or byte == 9 or byte == 10 or byte == 12 or byte == 13 or byte == 32:
        return CHAR_WHITESPACE
    if byte == 0x28 or byte == 0x29 or byte == 0x3C or byte == 0x3E or byte == 0x5B or byte == 0x5D or byte == 0x7B or byte == 0x7D or byte == 0x2F or byte == 0x25:
        return CHAR_DELIMITER
    return CHAR_REGULAR




def getFileSize(infile):
    return Path(r'{}'.format(infile)).stat().st_size