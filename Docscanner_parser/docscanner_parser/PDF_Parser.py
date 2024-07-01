from CSRC_parser.PDFparser import preprocessing
import os

file_path = r"D:\research\ISEC2024\malware\sample\complete\pdf\pdf_sample_1.pdf"
file_path = r"D:\research\ISEC2024\malware\sample\complete\pdf\aa\VirusShare_3dbe868775933d0620f63a6f44893afc\3777e556ddbafa08d7dcb35876bc47ee1226a8ad7d014d94ec5c6f6fc191a34d"
file_path = r"D:\research\ISEC2024\malware\sample\complete\pdf\pdf_sample_1.pdf"

result = preprocessing.pdfparser(file_path)


print(result.info)
print('-'*100)
print(result.model_input)

result.info.to_json('basic_data.json', indent=4)
result.model_input.to_json('model_data.json', indent=4)

exit(0)

# # Parser Test
# dir_path = r'D:\pdf\pdf'
# for root, dirs, files in os.walk(dir_path):
#     for file in files:
#         file_path = os.path.join(root, file)
#         result = preprocessing.pdfparser(file_path)
#
#         print(os.path.basename(file_path))
#
#
#         # json result
#         if not os.path.exists("PDF_paser_json"):
#             os.makedirs("PDF_paser_json")
#         result.info.to_json("PDF_paser_json/" + os.path.basename(file_path) + "_basic_data.json", indent=4)
#         result.model_input.to_json("PDF_paser_json/" + os.path.basename(file_path) + "_model_data.json", indent=4)