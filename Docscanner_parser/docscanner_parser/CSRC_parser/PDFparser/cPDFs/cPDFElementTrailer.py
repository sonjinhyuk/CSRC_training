from .cPDFUtil import PDF_ELEMENT_TRAILER
from .cPDFUtil import Canonicalize
class cPDFElementTrailer:
    def __init__(self, content):
        self.type = PDF_ELEMENT_TRAILER
        self.content = content

    def Contains(self, keyword):
        data = ''
        for i in range(0, len(self.content)):
            if self.content[i][1] == 'stream':
                break
            else:
                data += Canonicalize(self.content[i][1])
        return data.upper().find(keyword.upper()) != -1


    def getContainsValue(self):
        get_key = False
        for token in self.content:
            if token[-1] == "/Size":
                get_key = True
                continue
            if get_key:
                return int(token[-1])
        return 0