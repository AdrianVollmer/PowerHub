# Installation and Quickstart

It's a Python package hosted on [PyPI](https://pypi.org/project/PowerHub/). You install it like any other
Python package:

```console
$ python3 -m pip install powerhub
```

Installation from the GitHub repository should be avoided, unless you are
willing to test out new features. You will be more likely to encounter bugs
than if you install the releases.

To build the [binary payloads](binary_payloads), you will need the MinGW GCC and Mono C#
compilers. On Debian-like systems, you can install them with `apt-get
install mono-mcs gcc-mingw-w64-x86-64 gcc-mingw-w64-i686`.

After the installation, two new executables will be placed in `~/.local/bin`:

1. `powerhub`
2. `power-obfuscate`

Execute `powerhub <CALLBACK HOST> --auth powerhub:<PASSWORD>`, where
`<CALLBACK HOST>` is an IP address or hostname from which the victim system
can reach your system and `<PASSWORD>` is a strong password of your choice.
Then, browse to `https://<CALLBACK HOST>:8443` either from your system or
the victim system and accept the self-sigend certificate.
