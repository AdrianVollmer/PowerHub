"""Define the parameters for the download cradle and the main PowerShell
module

From the parameter collection, an HTML form will be generated in the Hub tab
of the webapp.

Some parameters are also relevant to power-obfuscate.
"""

import urllib


class Parameter(object):
    def __init__(self, label, default_value, description, _type, options=[],
                 classes="relevant-to-http relevant-to-https", get_arg=None,
                 cli_arg=None, help=""):
        if options:
            assert default_value in [o[0] for o in options],\
                    "%s not in list: %s" % (default_value, options)
        assert _type in 'selection checkbox radio'.split()

        self.label = label
        self.default_value = default_value
        self.description = description
        self._type = _type
        self.options = options

        # Classes can be used so the JavaScript code knows when to display
        # which elements
        self.classes = classes

        # This GET argument will be used for this parameter when loading the
        # stager via HTTP(S)
        self.get_arg = get_arg

        # If the stager is created via CLI, this can be passed to argparse
        self.cli_arg = cli_arg

        self.help = help

        self._value = None

    @property
    def value(self):
        return self._value or self.default_value

    @value.setter
    def set_value(self, _value):
        if self.options and _value not in [o[0] for o in self.options]:
            raise ValueError("%s not in list: %s" % (_value, self.options))
        self._value = _value

    def as_query_fragment(self):
        if self.value == self.default_value:
            return ''
        result = urllib.parse.urlencode([(self.get_arg, self.value)])
        return result

    def __repr__(self):
        return '<Parameter: %s=%s>' % (self.label, self.value)


class ParameterCollection(object):
    def __init__(self, parameters):
        self.parameters = parameters

    def __repr__(self):
        return str(self.parameters)

    def update_options(self, label, options):
        p = self.get_by_label(label)
        p.options = options

    def get_by_label(self, label):
        for p in self.parameters:
            if p.label == label:
                return p

    def __getitem__(self, label):
        p = self.get_by_label(label)
        if p:
            return self.get_by_label(label).value
        else:
            raise KeyError("Unknown parameter: %s" % label)

    def get_by_get_arg(self, arg):
        for p in self.parameters:
            if p.get_arg == arg:
                return p

    def parse_get_args(self, get_args):
        for p in self.parameters:
            p._value = get_args.get(p.label, p.default_value)


params = [
    Parameter(
        'launcher', 'powershell', "Launcher", 'selection',
        options=[
            ("powershell", "PowerShell"),
            ("cmd", "CMD"),
            ("cmd_enc", "CMD Encoded"),
            ("bash", "Bash"),
            ("mingw32", "Mingw32 Executable"),
            ("dotnetexe", ".NET Executable"),
            ("vbs", "VBScript"),
            #  ("wordmacro" , "MS Word Macro"),
            #  ("rundll32" , "Rundll32"),
            #  ("installutil" , "InstallUtil"),
        ],
    ),
    Parameter(
        'amsi', 'reflection', 'AMSI Bypass', 'selection',
        options=[
            ("reflection", "Matt Graber's Reflection method"),
            ("reflection2", "Matt Graber's 2nd Reflection method"),
            ("rasta-mouse", "Rasta Mouse"),
            ("am0nsec", "am0nsec (Requires PowerShell Version 5)"),
            ("adam-chester",
             "Adam Chester (Requires PowerShell Version 5; caught by latest Defender)"),
            ("zc00l", "zc00l (caught by latest Defender)"),
            ("none", "None"),
        ],
        get_arg='a',
    ),
    Parameter(
        'transport', 'https', 'Transport', 'selection',
        options=[('https', 'HTTPS'), ('http', 'HTTP')],
        get_arg='t',
    ),
    Parameter(
        'kex', 'dh', 'Key Exchange', 'selection',
        options=[
            ("dh", "Diffie-Hellman (secure; requires extra request)"),
            ("oob", "Out of Band (less secure; less compact)"),
            ("embedded", "Embedded (least secure; most compact)"),
        ],
        get_arg='k',
    ),
    Parameter('clip-exec', '-1', 'Clip-Exec', 'selection', get_arg='c'),
    Parameter(
        'minimal', 'false', 'Minimal Mode', 'checkbox', get_arg='m',
        help=(
            "In minimal mode, help strings and some obviously "
            "malicious functions are removed. Run-Exe and Run-Shellcode "
            "won't be available."),
    ),
    Parameter(
        'natural', 'false', 'Natural Variables', 'checkbox', get_arg='n',
        help="Use natural sounding variable names instead of randomly generated ones.",
    ),
    Parameter('proxy', 'false', 'Use Web Proxy', 'checkbox'),
    Parameter('tlsv1.2', 'false', 'Force TLSv1.2', 'checkbox',
              classes='relevant-to-https'),
    Parameter(
        'verification', 'noverification', 'Verification', 'radio',
        options=[
            ('noverification', 'No TLS verification'),
            ('fingerprint', 'Verify by fingerprint'),
            ('certstore', 'Use local certificate store'),
        ],
        classes='relevant-to-https',
    ),
    Parameter(
        'arch', '64bit', 'Architecture', 'radio',
        options=[('64bit', '64 Bit'), ('32bit', '32 Bit')],
        classes='relevant-to-dotnetexe relevant-to-mingw32',
    ),
]

param_collection = ParameterCollection(params)
