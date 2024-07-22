import CSRC_parser.DocParser
import pandas as pd

# row 생략 없이 출력
pd.set_option('display.max_rows', None)
# col 생략 없이 출력
pd.set_option('display.max_columns', None)

# OLE Parsing
file_path = r"D:\research\ISEC2024\malware\sample\complete\result\ole_sample1\ole_sample1"

result, app = CSRC_parser.DocParser.ole_main(file=file_path)

print(result.info)
print('-'*100)
print(result.model_input)
