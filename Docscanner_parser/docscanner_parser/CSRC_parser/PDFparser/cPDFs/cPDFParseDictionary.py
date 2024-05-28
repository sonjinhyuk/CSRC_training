from .cPDFTokenizer import cPDFTokenizer
from io import StringIO
import regex as re

CHAR_WHITESPACE = 1
CHAR_DELIMITER = 2
CHAR_REGULAR = 3

CONTEXT_NONE = 1
CONTEXT_OBJ = 2
CONTEXT_XREF = 3
CONTEXT_TRAILER = 4

PDF_ELEMENT_COMMENT = 1
PDF_ELEMENT_INDIRECT_OBJECT = 2
PDF_ELEMENT_XREF = 3
PDF_ELEMENT_TRAILER = 4
PDF_ELEMENT_STARTXREF = 5
PDF_ELEMENT_MALFORMED = 6

dumplinelength = 16


def TrimLWhiteSpace(data):
    while data != [] and data[0][0] == CHAR_WHITESPACE:
        data = data[1:]
    return data


def TrimRWhiteSpace(data):
    while data != [] and data[-1][0] == CHAR_WHITESPACE:
        data = data[:-1]
    return data

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



def ConditionalCanonicalize(sIn, nocanonicalizedoutput):
    if nocanonicalizedoutput:
        return sIn
    else:
        return Canonicalize(sIn)


def IsNumeric(str):
    return re.match('^[0-9]+', str)

class cPDFParseDictionary:
    def __init__(self, content, nocanonicalizedoutput):
        self.content = content
        self.nocanonicalizedoutput = nocanonicalizedoutput
        dataTrimmed = TrimLWhiteSpace(TrimRWhiteSpace(self.content))
        if dataTrimmed == []:
            self.parsed = None
        elif self.isOpenDictionary(dataTrimmed[0]) and (
                self.isCloseDictionary(dataTrimmed[-1]) or self.couldBeCloseDictionary(dataTrimmed[-1])):
            self.parsed = self.ParseDictionary(dataTrimmed)[0]
        else:
            self.parsed = None

    def isOpenDictionary(self, token):
        return token[0] == CHAR_DELIMITER and token[1] == '<<'

    def isCloseDictionary(self, token):
        return token[0] == CHAR_DELIMITER and token[1] == '>>'

    def couldBeCloseDictionary(self, token):
        return token[0] == CHAR_DELIMITER and token[1].rstrip().endswith('>>')

    def ParseDictionary(self, tokens):
        state = 0  # start
        dictionary = []
        while tokens != []:
            if state == 0:
                if self.isOpenDictionary(tokens[0]):
                    state = 1
                else:
                    return None, tokens
            elif state == 1:
                if self.isOpenDictionary(tokens[0]):
                    pass
                elif self.isCloseDictionary(tokens[0]):
                    return dictionary, tokens
                elif tokens[0][0] != CHAR_WHITESPACE:
                    key = ConditionalCanonicalize(tokens[0][1], self.nocanonicalizedoutput)
                    value = []
                    state = 2
            elif state == 2:
                if self.isOpenDictionary(tokens[0]):
                    value, tokens = self.ParseDictionary(tokens)
                    dictionary.append((key, value))
                    state = 1
                elif self.isCloseDictionary(tokens[0]):
                    dictionary.append((key, value))
                    return dictionary, tokens
                elif value == [] and tokens[0][0] == CHAR_WHITESPACE:
                    pass
                elif value == [] and tokens[0][1] == '[':
                    value.append(tokens[0][1])
                elif value != [] and value[0] == '[' and tokens[0][1] != ']':
                    value.append(tokens[0][1])
                elif value != [] and value[0] == '[' and tokens[0][1] == ']':
                    value.append(tokens[0][1])
                    dictionary.append((key, value))
                    value = []
                    state = 1
                elif value == [] and tokens[0][1] == '(':
                    value.append(tokens[0][1])
                elif value != [] and value[0] == '(' and tokens[0][1] != ')':
                    if tokens[0][1][0] == '%':
                        tokens = [tokens[0]] + cPDFTokenizer(StringIO(tokens[0][1][1:])).Tokens() + tokens[1:]
                        value.append('%')
                    else:
                        value.append(tokens[0][1])
                elif value != [] and value[0] == '(' and tokens[0][1] == ')':
                    value.append(tokens[0][1])
                    balanced = 0
                    for item in value:
                        if item == '(':
                            balanced += 1
                        elif item == ')':
                            balanced -= 1
                    if balanced < 0 and self.verbose:
                        print('todo 11: ' + repr(value))
                    if balanced < 1:
                        dictionary.append((key, value))
                        value = []
                        state = 1
                elif value != [] and tokens[0][1][0] == '/':
                    dictionary.append((key, value))
                    key = ConditionalCanonicalize(tokens[0][1], self.nocanonicalizedoutput)
                    value = []
                    state = 2
                else:
                    value.append(ConditionalCanonicalize(tokens[0][1], self.nocanonicalizedoutput))
            tokens = tokens[1:]
        return None, tokens

    def Retrieve(self):
        return self.parsed

    def PrettyPrintSubElement(self, prefix, e):
        if e[1] == []:
            print('%s  %s' % (prefix, e[0]))
        elif type(e[1][0]) == type(''):
            if len(e[1]) == 3 and IsNumeric(e[1][0]) and e[1][1] == '0' and e[1][2] == 'R':
                joiner = ' '
            else:
                joiner = ''
            value = joiner.join(e[1]).strip()
            reprValue = repr(value)
            if "'" + value + "'" != reprValue:
                value = reprValue
            print('%s  %s %s' % (prefix, e[0], value))
        else:
            print('%s  %s' % (prefix, e[0]))
            self.PrettyPrintSub(prefix + '    ', e[1])

    def PrettyPrintSub(self, prefix, dictionary):
        if dictionary != None:
            print('%s<<' % prefix)
            for e in dictionary:
                self.PrettyPrintSubElement(prefix, e)
            print('%s>>' % prefix)

    def PrettyPrint(self, prefix):
        self.PrettyPrintSub(prefix, self.parsed)

    def Get(self, select):
        for key, value in self.parsed:
            if key == select:
                return value
        return None

    def GetNestedSub(self, dictionary, select):
        for key, value in dictionary:
            if key == select:
                return self.PrettyPrintSubElement('', [select, value])
            if type(value) == type([]) and len(value) > 0 and type(value[0]) == type((None,)):
                result = self.GetNestedSub(value, select)
                if result != None:
                    return self.PrettyPrintSubElement('', [select, result])
        return None

    def GetNested(self, select):
        return self.GetNestedSub(self.parsed, select)
