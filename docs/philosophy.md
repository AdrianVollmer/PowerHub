# Motivation & Philosophy

## Motivation

Pentesters are often tasked to analyze a client system or are given one as
part of an assessment. They are often locked down to various degrees, and
almost all of them have some sort of antivirus solution on them. One of the
first things I want to do on them is to run a local privesc check and
SharpHound, which is typically considered malware. I needed a way to
conveniently load PowerShell scripts and binaries onto the system without
having to mess around too much with AV evasion techniques. Pretty much all
of those systems are able to communicate with the outside world (or at least
another machine on the network) via HTTP, so a web-based solution seemed
obvious.

Since I also found myself wanting to be able to have some sort of shared
clipboard between the Windows client I was provided with during a pentest
and my attacker machine, let's say to transfer hashes or PowerShell
one-liners, I decided to pack it all in one web application and called it
PowerHub.

Something was still missing, and that is a good interactive shell on remote
Windows systems to deliver my code. I don't see the point of using something
like the Meterpreter shell if a much more powerful shell is already
available: The Windows PowerShell. It already provides so much
functionality, in particular the ability to load code over the network, that
I don't need anything else. This is also why I never use Meterpreter on a
Linux machine. Bash can already do everything I need. Now, the old
`cmd.exe` may not, that's why you'd need a Meterpreter. But PowerShell is
just as powerful as bash, if not more so. Fire up PowerShell, load
your exploit, e.g. Mimikatz, via a safe transport mechanism, execute it in
memory and transfer the results back.

So what PowerHub does is to "upgrade" an existing PowerShell session and
endows it with the capability of loading and executing code remotely without
touching the disk as well as sending files back and forth. All with an
additional layer of encryption on top of HTTPS.


## Philosophy

PowerHub does not come with any exploits. I believe it's best to let other
people focus on developing their exploits independently, and then provide
some infrastructure to transfer them conveniently and without triggering
antivirus products to the target machine if necessary.

And contrary to popular believe, I'm convinced PowerShell is not dead yet.
There seems to be a shift back to binary exploits using the .NET framework
happening. First, PowerShell is still more available on end points compared
to .NET. Second, the best antivirus evasion in my opinion is still execution
in memory, which you cannot do with binaries alone. The concerns about AMSI
and PowerShell logging are valid, but they can be bypassed much more easily
than regular antivirus solutions.

So what PowerHub does is to disable AMSI and PowerShell logging first,
encrypt exploits with RC4, transfer them via HTTP (more transport methods
are planned), decrypt them in-memory and keep them there. Then they can be
imported as script blocks or executed via reflective PE injection -- thanks
to PowerSploit.

While this is still not a panacea and is or will be caught by some endpoint
protection solutions, the vast majority -- in particular Windows Defender
and Device Guard -- are fooled this way.

I also believe in good UX and aimed at making the usage of PowerHub as
simple as possible. That means having a sensible default configuration,
providing a clear user interface and automating as much as possible, but not
more.
