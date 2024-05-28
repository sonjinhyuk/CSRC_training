from .cPDFUtil import PDF_ELEMENT_STARTXREF
class cPDFElementStartxref:
    def __init__(self, index):
        self.type = PDF_ELEMENT_STARTXREF
        self.index = index
