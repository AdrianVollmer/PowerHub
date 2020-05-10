
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
