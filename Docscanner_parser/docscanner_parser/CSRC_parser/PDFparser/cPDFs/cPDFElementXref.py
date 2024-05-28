from .cPDFUtil import PDF_ELEMENT_XREF
class cPDFElementXref:
    def __init__(self, content):
        self.type = PDF_ELEMENT_XREF
        self.content = content

    def getXrefSize(self):
        cur_size = 0
        state = 0  # start
        # content_data = []
        # for incontent in self.content:
        #     content_data.append(ascii(incontent))
        # for token in content_data:
        for token in self.content:
            token_len = len(token[-1])
            if token[-1] == "xref":
                state = 1
            elif token_len == 10:
                state = 3
            elif state == 1: #start index
                state = 2
            elif state == 2:
                state = 3
                try:
                    cur_size += int(token[-1])
                except ValueError:
                    try:
                        cur_size += int(ascii(token[-1]).replace("\\", '0').replace('\'', ''), 16)
                    except ValueError:
                        pass

            elif token[-1] == "f" or token[-1] == "n":
                state = 1
        return cur_size
