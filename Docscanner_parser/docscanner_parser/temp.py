import yara

# Yara 룰 정의
rule = """
rule UrlPattern
{
    strings:
        $url_pattern = /(http|https):\\/\\/([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,}/ nocase
    condition:
        $url_pattern
}
"""

# 컴파일 Yara 룰
compiled_rule = yara.compile(source=rule)

# 분석할 데이터 (예제 파일)
data = """
Here are some URLs:
http://example.com
https://sub-domain.example.co.uk
http://123abc.net
"""

# # 매칭된 문자열 추출
# matches = compiled_rule.match(data=data)
# for match in matches:
#     for string in match.strings:
#         start = string[0]
#         matched_string = data[start:start+len(string[2])]
#         print(f"Matched string: {matched_string}")


def extract_matched_strings(matches):
    """Extract matched strings from YARA match objects."""
    matched_strings = []
    for match in matches:
        for string in match.strings:
            offset, identifier, data = string
            matched_strings.append({
                'rule': match.rule,
                'offset': offset,
                'identifier': identifier,
                'data': data.decode('utf-8', errors='ignore')
            })
    return matched_strings
compiled_rule = yara.compile(source=rule)
matches = compiled_rule.match(data=data)
print(extract_matched_strings(matches))