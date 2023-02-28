# Contributing

If you find PowerHub useful and want to give back, there are a number of options:

* **Say thanks.** It means more than you might think.
* **Spread the word.** It's motivating to see your product being used.
* **Report bugs.** Help make PowerHub better.
* **Create pull requests.** Bug reports that come with a solution are the best
  reports.

## Creating bug reports

Since PowerHub is obfuscating everything under the sun, debugging can be
hard. Even more so if I as the developer cannot reproduce what is going
on.

To make bug reports more useful, run PowerHub in debug mode by using the
`--debug` flag. This will make PowerHub somewhat more susceptible to
detection, so let's hope that this doesn't interfere. Before you execute the
download cradle, run `$ErrorActionPreference="Stop"`. Usually the first
error is the most important one. If you think the first error is not
helpful, run `$ErrorActionPreference="Continue"`, but try to trim the output
and only submit the first three PowerShell errors or so.

Include the output of the Python program as well in the bug report. Don't
forget to use code fences (three backticks) to format the output properly,
or else it will become unreadable. You may trim the Python output to the
relevant parts as well, but when in doubt, err on the side of more
verbosity. Besides the versions of all software packages involved (on both
machines), the download cradle parameters will be particularly important.

In short, try to include everything so the issue can be reproduced.
