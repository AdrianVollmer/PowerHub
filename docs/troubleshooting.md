# Troubleshooting

It's inevitable that PowerHub will be caught by some antivirus product
eventually. It's a cat and mouse game, as everybody knows.

When that happens, try to find out what it is that triggers the response.
For many detection techniques, PowerHub comes pre-equipped with evasion
features. Play around with those, which might already help.

If you want to drill down further, make use of the [Incremental
Delivery](incremental_delivery) feature. It will execute parts of the stager
individually and the antivirus response to each part might help us learn
which part triggers it. Running PowerHub in debug mode will cause a few more
helpful messages to be printed on both systems.

To find the exact line that is causing the trigger, it helps to first find
the file and then to perform something like a binary search. Meaning: you delete
one half of the file and see if it passes or not, then proceed with the
problematic half by halving it even further, etc. This cannot be automated
easily, because we still want the file to be well-behaved PowerShell code,
so we have to find good positions that are near the middle to delete
from/to.

Note that you don't have to restart PowerHub each time you make changes to
one of the template files. The files that you are going to want to modify
are probably in `~/.local/lib/python3.*/site-packages/powerhub/templates`,
if you installed it as recommended. I'd start with `stage1.ps1`.

Personally, when developing I perform an editable install from the git
repository, i.e. `pip install -e .` and then just edit the files in the
repository. Using [venv](https://docs.python.org/3/library/venv.html) is
also a good option in this case.

And when you found the culprit, please consider opening an
[issue](https://github.com/AdrianVollmer/PowerHub/issues/new) or a
pull request so everyone can profit from your findings.
