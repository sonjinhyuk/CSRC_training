import CSRC_parser.DocParser
import pandas as pd

# row 생략 없이 출력
pd.set_option('display.max_rows', None)
# col 생략 없이 출력
pd.set_option('display.max_columns', None)

file_path = r"D:\hwpx\9F1D297B5C58CEE07F6EAD462593EA4553C01115BA029E0417C953095FBB8609"

# OOXML Parsing
result, app = CSRC_parser.DocParser.ooxml_main(file=file_path)

print(result.info)
print('-'*100)
print(result.model_input)

result.info.to_json('basic_data.json', indent=4)
result.model_input.to_json('model_data.json', indent=4)


# # OLE Parsing
# file_path = r"C:\Users\csrc\Downloads\위협모델_RFP.hwp"
# result, app = CSRC_parser.DocParser.ole_main(file=file_path)
#
# print(result.info)
# print('-'*100)
# print(result.model_input)





