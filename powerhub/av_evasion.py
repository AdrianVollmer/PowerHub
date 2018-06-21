import re


def ps1_remove_comments(code):
    code = re.sub(r'<#.*?#>', '', code, flags=re.DOTALL)
    code = re.sub(r'\s+#.*', '', code)
    return code


def ps1_rename_mimikatz_functions(code):
    code = re.sub(r'Mimikatz', 'Ninikratz', code)
    code = re.sub(r'DumpCreds', 'CrumpDeds', code)
    return code


def clean_ps1(code):
    try:
        code = code.decode()
    except UnicodeDecodeError:
        code = code.decode("utf-16le")
    code = ps1_remove_comments(code)
    code = ps1_rename_mimikatz_functions(code)
    return code.encode()
