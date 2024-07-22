import CSRC_parser.DocParser
import pandas as pd

# row 생략 없이 출력
pd.set_option('display.max_rows', None)
# col 생략 없이 출력
pd.set_option('display.max_columns', None)

file_path = r"D:\research\ISEC2024\malware\sample\complete\ooxml_sample\4F897A55374F4FE7693F5AA5B7B57D306FD39225E279556F9A785DB7523EFB90.xlsx"

# # OOXML Parsing
# result, app = CSRC_parser.DocParser.ooxml_main(file=file_path)
#
# print(result.info)
# print('-'*100)
# print(result.model_input)
#
# result.info.to_json('basic_data.json', indent=4)
# result.model_input.to_json('model_data.json', indent=4)