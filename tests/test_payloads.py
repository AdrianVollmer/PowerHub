
def test_gcc():
    from powerhub.payloads import create_exe
    args = {
        "GroupLauncher": "mingw32-64bit",
        "GroupAmsi": "reflection",
        "GroupTransport": "http",
        "GroupClipExec": "none",
        "CheckboxProxy": "false",
        "CheckboxTLS1.2": "false",
        "RadioFingerprint": "true",
        "RadioNoVerification": "false",
        "RadioCertStore": "false",
    }
    filename, payload = create_exe(args)
    assert filename == 'powerhub-mingw32-64bit-reflection-http.exe'
    assert b"DOS" in payload
    assert payload.startswith(b'MZ')


def test_mcs():
    from powerhub.payloads import create_dotnet
    args = {
        "GroupLauncher": "dotnetexe-64bit",
        "GroupAmsi": "reflection",
        "GroupTransport": "http",
        "GroupClipExec": "none",
        "CheckboxProxy": "false",
        "CheckboxTLS1.2": "false",
        "RadioFingerprint": "true",
        "RadioNoVerification": "false",
        "RadioCertStore": "false",
    }
    filename, payload = create_dotnet(args)
    assert filename == 'powerhub-dotnetexe-64bit-reflection-http.exe'
    assert b"DOS" in payload
    assert payload.startswith(b'MZ')
