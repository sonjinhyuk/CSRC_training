from .cPDFDefine import PDF_ELEMENT_MALFORMED
class cPDFElementMalformed:
    def __init__(self, content):
        self.type = PDF_ELEMENT_MALFORMED
        self.content = content
