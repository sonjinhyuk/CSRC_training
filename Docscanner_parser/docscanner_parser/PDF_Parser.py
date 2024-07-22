from CSRC_parser.PDFparser import preprocessing
import pandas as pd

# row 생략 없이 출력
pd.set_option('display.max_rows', None)
# col 생략 없이 출력
pd.set_option('display.max_columns', None)

file_path = r"D:\research\ISEC2024\malware\sample\complete\pdf_sample\pdf_sample_1"

result = preprocessing.pdfparser(file_path)


print(result.info)
print('-'*100)
print(result.model_input)

# result.info.to_json('basic_data.json', indent=4)
# result.model_input.to_json('model_data.json', indent=4)