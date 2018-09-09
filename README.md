PowerHub
========

PowerHub is a web application which aids a pentester in transferring files,
in particular code which may get flagged by endpoint protection.


![PowerHub Webapp](https://github.com/AdrianVollmer/PowerHub/blob/master/img/powerhub-webapp.png)

The web application is made with Django 1.11 and consists of three parts.


The Hub
-------

The hub uses PowerShell to load modules and binaries in memory. The binaries
can be executed directly from memory with
[PowerSploit's](https://github.com/PowerShellMafia/PowerSploit)
`Invoke-ReflectivePEInjection`.

Modules have to be placed in `./modules` and can be either PowerShell
scripts or PE executables. You can activate the individual modules in the
web interface. "Activated" means they will be transferred with the download
cradle. However, you can also load them on the target via PowerShell with
`Load-HubModule`. Run `Help-PowerHub` for more information.

PowerHub on the attacker system simply looks for `*.ps1` or `*.exe` files.
The `*.ps1` files are imported on the target via `[Scriptblock]::Create()`.

The Clipboard
-------------

The clipboard functionality is meant for exchanging small snippets, such as
hashes, passwords, one liners, and so forth. It's like an extremely basic
etherpad.

File Dropper
------------

The file dropper offers a way to transfer files via HTTP back to the host.
Think [Droopy](https://github.com/stackp/Droopy).

Usage
=====

PowerHub has one mandatory argument: the callback host (can be an IP
address). This hostname is used by the stager to download the payload. If
the callback port or path differ from the default, it can also be changed.

Read `./powerhub.py --help` for details.

Author
======

Adrian Vollmer, 2018

License (MIT)
============

Copyright (c) 2018, Adrian Vollmer

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.

Disclaimer
==========

Use at your own risk. Do not use without full consent of everyone involved.
For educational purposes only.
