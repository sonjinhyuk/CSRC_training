from CSRC_parser.PDFparser.cPDFs.cPDFUtil import PDF_ELEMENT_INDIRECT_OBJECT, CHAR_WHITESPACE, CHAR_REGULAR, CHAR_DELIMITER, CopyWithoutWhiteSpace, EqualCanonical, IsNumeric
from CSRC_parser.PDFparser.cPDFs.cPDFUtil import Canonicalize, IIf, FlateDecode, ASCII85Decode, ASCIIHexDecode, LZWDecode, RunLengthDecode
import regex as re
import zlib

class cPDFElementIndirectObject:
    def __init__(self, id, version, content, objstm=None):
        self.type = PDF_ELEMENT_INDIRECT_OBJECT
        self.id = id
        self.version = version
        self.content = content
        self.objstm = objstm
        #fix stream for Ghostscript bug reported by Kurt
        if self.ContainsStream():
            position = len(self.content) - 1
            if position < 0:
                return
            while self.content[position][0] == CHAR_WHITESPACE and position >= 0:
                position -= 1
            if position < 0:
                return
            if self.content[position][1].endswith('endstream\n'):
                self.content = self.content[0:position] + [(self.content[position][0], self.content[position][1][:-len('endstream\n')])] + [(CHAR_REGULAR, 'endstream')] + self.content[position+1:]
                return
            if self.content[position][0] != CHAR_REGULAR:
                return
            if self.content[position][1] == 'endstream':
                return
            if not self.content[position][1].endswith('endstream'):
                return
            self.content = self.content[0:position] + [(self.content[position][0], self.content[position][1][:-len('endstream')])] + [(self.content[position][0], 'endstream')] + self.content[position+1:]

    def GetType(self):
        content = CopyWithoutWhiteSpace(self.content)
        dictionary = 0
        for i in range(0, len(content)):
            if content[i][0] == CHAR_DELIMITER and content[i][1] == '<<':
                dictionary += 1
            if content[i][0] == CHAR_DELIMITER and content[i][1] == '>>':
                dictionary -= 1
            if dictionary == 1 and content[i][0] == CHAR_DELIMITER and EqualCanonical(content[i][1], '/Type') and i < len(content) - 1:
                return content[i+1][1]
        return ''

    def GetReferences(self):
        content = CopyWithoutWhiteSpace(self.content)
        references = []
        for i in range(0, len(content)):
            if i > 1 and content[i][0] == CHAR_REGULAR and content[i][1] == 'R' and content[i-2][0] == CHAR_REGULAR and IsNumeric(content[i-2][1]) and content[i-1][0] == CHAR_REGULAR and IsNumeric(content[i-1][1]):
                references.append((content[i-2][1], content[i-1][1], content[i][1]))
        return references

    def References(self, index):
        for ref in self.GetReferences():
            if ref[0] == index:
                return True
        return False

    def ContainsStream(self):
        for i in range(0, len(self.content)):
            if self.content[i][0] == CHAR_REGULAR and self.content[i][1] == 'stream':
                return self.content[0:i]
        return False

    def Contains(self, keyword):
        data = ''
        for i in range(0, len(self.content)):
            if self.content[i][1] == 'stream':
                break
            else:
                data += Canonicalize(self.content[i][1])
        return data.upper().find(keyword.upper()) != -1

    def ContainsName(self, keyword, regex=None):
        for token in self.content:
            if token[1] == 'stream':
                return False
            if keyword[0] == "/" and token[0] == CHAR_DELIMITER and EqualCanonical(token[1], keyword):
                return True
            elif keyword[0] != "/" and token[0] == CHAR_REGULAR:
                if keyword in token[1] and regex != None:
                    return True
                elif regex is None:
                    return False
                if regex and type(regex) != type([]):
                    try:
                        a = re.search(regex, token[1], IIf(False, 0, re.I))
                    except TypeError:
                        regexd = regex.encode()
                        a = re.search(regexd, token[1], IIf(False, 0, re.I))
                    return a
                elif regex and type(regex) == type([]):
                    for regex_ in regex:
                        try:
                            a = re.search(regex_, token[1], IIf(False, 0, re.I))
                        except TypeError:
                            regexd = regex_.encode()
                            a = re.search(regexd, token[1], IIf(False, 0, re.I))
                        return a
        return False

    def getContainsValue(self, keyword):
        get_key = False
        return_data = ""
        for index, token in enumerate(self.content):
            if token[0] == CHAR_DELIMITER and EqualCanonical(token[1], keyword):
                get_key = True
            elif get_key and token[0] == CHAR_REGULAR:
                if keyword == "/JS":
                    in_value = self.getContainsvalueJS(filter=False, overridingfilters="raw", index=index)
                    return in_value
                else:
                    return token[-1]
        return return_data

    def getContainsvalueJS(self, filter=True, overridingfilters='', index=0):
        state = 'start'
        data = '('
        countDirectories = 1
        for i in range(index, len(self.content)):
            ##test
            content_test = self.content[i]
            ##
            if self.content[i][0] == CHAR_DELIMITER and self.content[i][1] == "(":
                countDirectories += 1
            elif self.content[i][0] == CHAR_DELIMITER and self.content[i][1] == ")":
                countDirectories += 1


            if countDirectories != 0:
                data += self.content[i][-1]
            else:
                return data
        if data == "(":
            return ""
        else:
            return data


    def getStreamValue(self):
        if not self.ContainsStream():
            return False
        streamData = self.Stream(filter)
        return streamData

    def rfindall(self, regex, streamData, casesensitive=False):
        try:
            a = re.findall(regex, streamData, IIf(casesensitive, 0, re.I))
        except TypeError:
            regexd = regex.encode()
            a = re.findall(regexd, streamData, IIf(casesensitive, 0, re.I))
        return a

    def StreamContains(self, keyword, filter, casesensitive, regex, overridingfilters):
        if not self.ContainsStream():
            return False
        streamData = self.Stream(filter, overridingfilters)
        if (filter and streamData == 'No filters') or (isinstance(streamData, str) and "Unsupported filter" in streamData):
        # if filter and streamData == 'No filters':
            streamData = self.Stream(False, overridingfilters)
        if isinstance(streamData, bytes):
            keyword = keyword.encode()
        if len(streamData) == 0:
            return False
        if regex and type([]) != type(regex):
            # return re.search(keyword, streamData, IIf(casesensitive, 0, re.I))
            return self.rfindall(regex=regex, streamData=streamData, casesensitive=casesensitive)
        elif regex and type([]) == type(regex):
            temp = []
            for regex_ in regex:
                temp.append(self.rfindall(regex=regex_, streamData=streamData, casesensitive=casesensitive))
            return_temp = []
            for t in temp:
                return_temp.append(t)
            return return_temp
        elif casesensitive:
            return keyword in streamData
        else:
            return keyword.lower() in streamData.lower()

    def Stream(self, filter=True, overridingfilters=''):
        state = 'start'
        countDirectories = 0
        data = ''
        filters = []
        for i in range(0, len(self.content)):
            ##test
            content_test = self.content[i]
            ##
            if state == 'start':
                if self.content[i][0] == CHAR_DELIMITER and self.content[i][1] == '<<':
                    countDirectories += 1
                if self.content[i][0] == CHAR_DELIMITER and self.content[i][1] == '>>':
                    countDirectories -= 1
                if countDirectories == 1 and self.content[i][0] == CHAR_DELIMITER and EqualCanonical(self.content[i][1], '/Filter'):
                    state = 'filter'
                elif countDirectories == 0 and self.content[i][0] == CHAR_REGULAR and self.content[i][1] == 'stream':
                    state = 'stream-whitespace'
            elif state == 'filter':
                if self.content[i][0] == CHAR_DELIMITER and self.content[i][1][0] == '/':
                    filters = [self.content[i][1]]
                    state = 'search-stream'
                elif self.content[i][0] == CHAR_DELIMITER and self.content[i][1] == '[':
                    state = 'filter-list'
            elif state == 'filter-list':
                if self.content[i][0] == CHAR_DELIMITER and self.content[i][1][0] == '/':
                    filters.append(self.content[i][1])
                elif self.content[i][0] == CHAR_DELIMITER and self.content[i][1] == ']':
                    state = 'search-stream'
            elif state == 'search-stream':
                if self.content[i][0] == CHAR_REGULAR and self.content[i][1] == 'stream':
                    state = 'stream-whitespace'
            elif state == 'stream-whitespace':
                if self.content[i][0] == CHAR_WHITESPACE:
                    whitespace = self.content[i][1]
                    if whitespace.startswith('\x0D\x0A') and len(whitespace) > 2:
                        data += whitespace[2:]
                    elif whitespace.startswith('\x0A') and len(whitespace) > 1:
                        data += whitespace[1:]
                else:
                    data += self.content[i][1]
                state = 'stream-concat'
            elif state == 'stream-concat':
                if self.content[i][0] == CHAR_REGULAR and self.content[i][1] == 'endstream':
                    if filter:
                        if overridingfilters == '':
                            return self.Decompress(data, filters)
                        elif overridingfilters == 'raw':
                            return data
                        else:
                            return self.Decompress(data, overridingfilters.split(' '))
                    else:
                        return data
                else:
                    data += self.content[i][1]
            else:
                return 'Unexpected filter state'
        if len(data) != 0:
            return data
        return filters

    def Decompress(self, data, filters):
        for filter in filters:
            if EqualCanonical(filter, '/FlateDecode') or EqualCanonical(filter, '/Fl'):
                try:

                    data = FlateDecode(data)
                except zlib.error as e:
                    message = 'FlateDecode decompress failed'
                    if len(data) > 0 and ord(data[0]) & 0x0F != 8:
                        message += ', unexpected compression method: %02x' % ord(data[0])
                    return message + '. zlib.error %s' % e
            elif EqualCanonical(filter, '/ASCIIHexDecode') or EqualCanonical(filter, '/AHx'):
                try:
                    data = ASCIIHexDecode(data)
                except:
                    return 'ASCIIHexDecode decompress failed'
            elif EqualCanonical(filter, '/ASCII85Decode') or EqualCanonical(filter, '/A85'):
                try:
                    data = ASCII85Decode(data.rstrip('>'))
                except:
                    return 'ASCII85Decode decompress failed'
            elif EqualCanonical(filter, '/LZWDecode') or EqualCanonical(filter, '/LZW'):
                try:
                    data = LZWDecode(data)
                except:
                    return 'LZWDecode decompress failed'
            elif EqualCanonical(filter, '/RunLengthDecode') or EqualCanonical(filter, '/R'):
                try:
                    data = RunLengthDecode(data)
                except:
                    return 'RunLengthDecode decompress failed'
#            elif i.startswith('/CC')                        # CCITTFaxDecode
#            elif i.startswith('/DCT')                       # DCTDecode
            else:
                return 'Unsupported filter: %s' % repr(filters)
        if len(filters) == 0:
            return 'No filters'
        else:
            return data

    def StreamYARAMatch(self, rules, decoders, decoderoptions, filter, overridingfilters):
        if not self.ContainsStream():
            return None
        streamData = self.Stream(filter, overridingfilters)
        if filter and streamData == 'No filters':
            streamData = self.Stream(False, overridingfilters)

        oDecoders = [cIdentity(streamData, None)]
        for cDecoder in decoders:
            try:
                oDecoder = cDecoder(streamData, decoderoptions)
                oDecoders.append(oDecoder)
            except Exception as e:
                print('Error instantiating decoder: %s' % cDecoder.name)
                raise e
        results = []
        for oDecoder in oDecoders:
            while oDecoder.Available():
                yaraResults = rules.match(data=oDecoder.Decode())
                if yaraResults != []:
                    results.append([oDecoder.Name(), yaraResults])

        return results
