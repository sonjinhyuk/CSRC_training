
def get_regex(keyword, regex):
    # if keyword == "domain":
    #     regex = ["([a-z0-9\w]+\.*)+[a-z0-9]{2,4}([\/a-z0-9-%#?&=\w])+(\.[a-z0-9]{2,4}(\?[\/a-z0-9-%#?&=\w]+)*)*"]
    # elif keyword == "filepath":
    if keyword == "filepath":
        regex = ["^((?:\/[a-zA-Z0-9]+(?:_[a-zA-Z0-9]+)*(?:\-[a-zA-Z0-9]+)*(?:.+))+)",
                 # "^[a-zA-Z]:(\\([_a-zA-Z0-9가-힣]+))+\\"]
                 "^[a-zA-Z]:"]
    elif keyword == "ascii":
        regex = ["([`~!@#$%^&*()-_=+][0-9][0-9A-z]{0,1}){2,}"]

    return regex

def set_regex(_list, _type="HWP"):
    return_list = []
    if _type == "HWP":
        nomal_regex = []
        exec_list = []
        scdbg_list = []
        dhfa_keyword = []#domain, http, filepath, ascii

        for keyword in _list:
            if not(keyword == "domain" or keyword == "filepath" or keyword == "ascii"):
                if "string" in keyword or "putinterval" in keyword or "repeat" in keyword:
                    scdbg_list.append(keyword)
                elif "exec|" in keyword:
                    exec_list.append(keyword)
                else:
                    nomal_regex.append(keyword)

            else:
                dhfa_keyword.append(keyword)
        return_list.append("|".join(nomal_regex))
        return_list.append("|".join(scdbg_list))



        for exec in exec_list:
            return_list.append(exec)

        for key in dhfa_keyword:
            return_list.append(key)

        return return_list
    elif _type == "OLE":
        nomal_regex = []
        exec_list = []
        dhfa_keyword = []  # domain, http, filepath, ascii

        for keyword in _list:
            if not (keyword == "domain" or keyword == "filepath" or keyword == "ascii"):
                nomal_regex.append(keyword)
            else:
                dhfa_keyword.append(keyword)
        return_list.append("|".join(nomal_regex))

        for exec in exec_list:
            return_list.append(exec)

        for key in dhfa_keyword:
            return_list.append(key)

        return return_list
