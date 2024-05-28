__description__ = 'PDFparser, use it to parse a PDF document'
__author__ = 'Didier Stevens'
__version__ = '0.7.6'
__date__ = '2022/05/24'
__minimum_python_version__ = (2, 5, 1)
__maximum_python_version__ = (3, 10, 4)

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