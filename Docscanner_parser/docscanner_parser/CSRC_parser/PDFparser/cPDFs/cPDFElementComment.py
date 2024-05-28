from .cPDFUtil import PDF_ELEMENT_COMMENT
class cPDFElementComment:
    def __init__(self, comment):
        self.type = PDF_ELEMENT_COMMENT
        self.comment = comment
#                        if re.match('^%PDF-[0-9]\.[0-9]', self.token[1]):
#                            print(repr(self.token[1]))
#                        elif re.match('^%%EOF', self.token[1]):
#                            print(repr(self.token[1]))