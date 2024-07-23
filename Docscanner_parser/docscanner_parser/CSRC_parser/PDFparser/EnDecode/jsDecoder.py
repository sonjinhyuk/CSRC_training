import js2py
import subprocess

def ex_eval(js_string):
    js2 = ""
    try:
        js2 = js_string.replace('eval(', 'console.log(')
    except TypeError:
        pass
    # js2 = js_string.replace('eval(', '(')
    return js2

def head_eval_js(js):
    a = str(js).replace('b\'', '').replace('b\"', '')
    a = a.replace("\\n", " ksshin ").replace("\\r", " ksshin ").replace("\r\n", " ksshin ")
    a = a.replace("\\t", " kstab ")
    a = a.replace("\\", "")
    a = a.replace("ksshin", "\n")
    a = a.replace("kstab", "\t")

    if a[-1] == ';':
        pass
    else:
        if (a[-1] == '\'') or (a[-1] == '\"'):
            a = a[:-1]
    js2 = a.replace('eval(', 'console.log(').replace('eval','console.log')
    # js2 = a.replace('eval(', '(').replace('eval','')

    return js2

def run_js_csrc_node(jsfile):
    p = subprocess.Popen(['node', jsfile], stdout=subprocess.PIPE)
    print(p)
    try:
        out = p.stdout.read().decode('utf8')
    except TypeError:
        print("TypeError " + jsfile)
        out = None
    except ReferenceError:
        print("ReferenceError " + jsfile)
        out = None
    print(out)
    return out
def recuv_js(js_file):
    file_js_0 = js2py.get_file_contents(js_file)
    if file_js_0 != "None":
        if file_js_0[0] in 'b':
            js1 = head_eval_js(file_js_0)
        else:
            if file_js_0 != "None":
                js1 = ex_eval(file_js_0)
        temp_file_name = js_file.split(".js")[0]
        new_index = int(temp_file_name[-1])+1
        temp_file_name = temp_file_name[:-1]
        new_jsfile_name = temp_file_name + str(new_index) + ".js"
        js2py.write_file_contents(f'{new_jsfile_name}', js1)

        eval_flag = True
        for ji in range(2, 11):
            if eval_flag:
                try:
                    eval_flag = recuv_eval(f'{temp_file_name}{ji}.js', f'{temp_file_name}{ji + 1}.js')
                except FileNotFoundError:
                    break
            else:
                break

def recuv_eval(j1, j2):
    checkdata = js2py.get_file_contents(j1)
    if ('eval' in checkdata) or ('console' in checkdata):
        js = run_js_csrc_node(j1)
        # js = run_js_csrc(checkdata)
        if js is not None:
            js_string = ex_eval(js)
        else:
            js_string = ""
    else:
        return False

    if "" == js_string :
        return False
    else:
        js2py.write_file_contents(j2, js_string)
        return True
from pathlib import Path
def get_max_filter_js(out_dir):
    path = Path(f'{out_dir}/js')
    max = 0
    for p in path.glob('**/*.js'):
        index = int(p.stem.split(".js")[0].split("_")[-1])
        if max < index:
            max = index
    return max