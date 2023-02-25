"""Define the parameters for the download cradle and the main PowerShell
module

From the parameter collection, an HTML form will be generated in the Hub tab
of the webapp.

Some parameters are also relevant to power-obfuscate.
"""

import urllib


class Parameter(object):
    """A Parameter object that servers as GET argument in either the cradle
    builder or the stager request, or as a CLI parameter

    `value` can never be `None`, because then `default_value` is returned,
    which must not be `None`.
    Type of `value` is always bool (if it's a checkbox) or string.
    """

    def __init__(self, label, default_value, description, _type, options=[],
                 classes="relevant-to-http relevant-to-https", get_arg=None,
                 cli_arg=None, help=""):
        if options:
            assert default_value in [str(o[0]) for o in options],\
                    "%s not in list: %s" % (default_value, options)
        assert _type in 'selection checkbox radio text'.split()
        assert default_value is not None
        if _type == 'checkbox':
            assert default_value in [True, False]
        else:
            assert isinstance(default_value, str)

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
        if self._value is None:
            return self.default_value
        return self._value

    @value.setter
    def value(self, _value):
        __value = _value
        if isinstance(_value, tuple):
            __value = _value[0]
        if self.options and __value not in [str(o[0]) for o in self.options]:
            raise ValueError("%s not in list: %s" % (__value, self.options))
        if self._type == "checkbox":
            if isinstance(_value, str):
                self._value = (_value.lower().startswith('t'))
            else:
                self._value = bool(_value)
        else:
            self._value = _value

    def as_query_fragment(self):
        if self.value == self.default_value:
            return ''
        result = urllib.parse.urlencode([(self.get_arg, self.value)])
        result = '&' + result
        return result

    def __repr__(self):
        return '<Parameter: %s=%s>' % (self.label, self.value)


class ParameterCollection(object):
    def __init__(self, parameters):
        self.parameters = parameters

        # assert get_args are unique
        get_args = [p.get_arg.lower() for p in parameters if p.get_arg]
        assert len(set(get_args)) == len(get_args),\
            "Duplicate get_arg detected"

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
        """Parse dictionary of GET arguments where the keys correspond to
        each parameter's `label`"""
        for p in self.parameters:
            p.value = get_args.get(p.label, p.default_value)

    def parse_get_args_short(self, get_args):
        """Parse dictionary of GET arguments where the keys correspond to
        each parameter's `get_arg`"""
        for p in self.parameters:
            p.value = get_args.get(p.get_arg, p.default_value)


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
        get_arg='launcher',
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
        'kex', 'oob', 'Key Exchange', 'selection',
        options=[
            ("oob", "Out of Band (most secure; least compact)"),
            ("dh", "Diffie-Hellman (medium secure; compact; requires extra request)"),
            ("embedded", "Embedded (least secure; compact; self-contained)"),
        ],
        get_arg='k',
    ),
    Parameter('clip-exec', '-1', 'Clip-Exec', 'selection', get_arg='c'),
    Parameter(
        'preloaded', '', 'Preload', 'text', get_arg='p',
        help="Enter a compactified CSV list (e.g. '1,2,4-8,12') of modules "
             "that should come preloaded and press return. "
             "Only makes sense with key exchange 'embedded'."
    ),
    Parameter(
        'minimal', False, 'Minimal Mode', 'checkbox', get_arg='m',
        help=(
            "In minimal mode, comment-based help of Cmdlets and some obviously "
            "malicious functions are removed. Run-Exe and Run-Shellcode "
            "won't be available."),
    ),
    Parameter(
        'natural', False, 'Natural Variables', 'checkbox', get_arg='n',
        help="Use natural sounding variable names instead of randomly generated ones.",
    ),
    Parameter(
        'incremental', False, 'Incremental Delivery', 'checkbox',
        help="Deliver first stage in several requests.",
    ),
    Parameter(
        'split_cradle', False, 'Split Cradle', 'checkbox',
        help="Separate 'Invoke-Expression' from 'DownloadString' to cause less suspicion. "
             "Requires interactive execution.",),
    Parameter(
        'decoy', False, 'Include Decoys', 'checkbox', get_arg='d',
        help="Wrap suspicious code in real code from legitimate sources.",
    ),
    Parameter(
        'obfuscate_setalias', False, "Obfuscate 'Set-Alias'", 'checkbox', get_arg='o',
        help="Wrap suspicious code in real code from legitimate sources.",
    ),
    Parameter(
        'slowenc', False, 'Slow Encryption', 'checkbox', get_arg='s',
        help="Avoid API calls to fast encryption routines for more stealth.",
    ),
    Parameter(
        'useragent', False, 'Set User-Agent', 'checkbox',
        help="By default, PowerShell sets no or a revealing user-agent. "
             "This option sets a more natural user-agent.",
    ),
    Parameter('proxy', False, 'Use Web Proxy', 'checkbox'),
    Parameter('tlsv1.2', False, 'Force TLSv1.2', 'checkbox',
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
