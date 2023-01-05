# Antivirus Evasion Techniques

Let's discuss some common antivirus detection techniques and how PowerHub
attempts to bypass them.

## Network Monitoring

### Technique

Antivirus Detection does not necessarily have to happen on the endpoint.
It's common to check files transferred from the network for malicious code
before it even reaches the endpoint. Usually, this happens in web proxies.

### Our Bypass

PowerHub support HTTPS. Since some antivirus products perform TLS
inspection, almost all data is encrypted on an additional layer using either
RC4 or AES. Yes, RC4 is insecure, but practical attacks are still
sufficiently difficult for antivirus products.

## File System Monitoring

### Technique

Whenever a file is written to disk, antivirus checks it against known
malware.

### Our Bypass

Easy: Don't write anything to disk. PowerShell makes it possible to execute
code entirely in-memory.

## AMSI

### Technique

Whenever PowerShell executes a script, it is first passed to the antivirus
product which checks it for malicious code. This check is often quite
primitive, such that it was at some point sufficient to replace
`Invoke-Mimikatz` with `Invoke-Mimidogz`. The mere presence of some IT
security researcher's name is sometimes enough to trigger an antivirus.

### Our Bypass

PowerHub doesn't use any novel AMSI bypass. There are long
[lists](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) of AMSI
bypasses, because PowerShell is so powerful, it can modify its own behavior.

The challenge is to get one of the bypasses by AMSI, because the
bypasses are obviously immediately detected if executed naively. Some
bypasses are quite short and the only suspicious thing about them are some
strings. For example, this is one of the first bypasses by Matt Graeber and
fits in a Tweet:

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

In fact, Windows Defender will consider this malware simply because it
contains the string `AmsiUtils`. Try it out: Open a PowerShell and type
`"AmsiUtil"`. Then type `"AmsiUtils"`:

TODO screenshot.

Imagine we replaced the strings:

```powershell
[Ref].Assembly.GetType($string1).GetField($string2,string3).SetValue($null,$true)
```

Surely this line cannot be considered malware, or else it would break
legitimate scripts. So if we manage to obfuscate the original strings, we
should be good. There are infinite ways to obfuscate a string. You can split
them up, rearrange them using format strings, put them together from bytes,
work with replacement rules, and much, much more.
Daniel Bohannon has worked out a [whole bunch of obfuscation
methods](https://github.com/danielbohannon/Invoke-Obfuscation), not only for
strings, but also for other PowerShell "tokens".

In PowerHub, we take an even more systematic approach: Strings are
"obfuscated" using the RC4 encryption algorithm. It's simple enough so it
can be implemented in a couple of lines of pure PowerShell, and while
technically broken, still strong enough to throw off automated detection
techniques, especially if they are supposed to work in the background
without affecting the user's workflow.


## Entropy Analysis

### Technique

Overly obfuscated code looks *weird*. You'd be able to spot it a mile away.
Machines can be made to recognize it as well, by means of frequency analysis
of individual letters or, more generally, entropy analysis. Daniel Bohannon,
who worked on obfuscating code, also suggested ways to [defeat code
obfuscation](https://www.blackhat.com/docs/us-17/thursday/us-17-Bohannon-Revoke-Obfuscation-PowerShell-Obfuscation-Detection-And%20Evasion-Using-Science-wp.pdf) together with Lee Holems.

### Our Bypass

We wrap our code in legit PowerShell code. Downloaded from one of
Microsoft's GitHub repositories, PowerHub has hundreds of modules that do
nothing and which will be randomly chosen to pad supsicious code. Plus,
instead of using randomly generated variable names, PowerHub can use
variable names inspired by real code to make it look more natural.

We will still have large encoded binary blobs in our code, but let's just
assume that it won't be feasible for antivirus products to block all scripts
with blobs in them.

## API Hooking

### Technique

TODO

### Our Bypass

TODO

## Behavior Analysis

### Technique

Some actions that malware typically performs are inherently suspicious:
Process hollowing, accessing honey tokens, getting a handle on the LSASS
process, etc.

These actions are detectable in principle, and that's one of the techniques
employed by modern antivirus products. The only issue is that not all
actions are inherently suspicious but still considered malware. Whatever
[BloodHound](https://github.com/BloodHoundAD/BloodHound) does, for example.

### Our Bypass

Yeah I got nothing. Dear friends from Kaspersky, Palo Alto and Windows
Defender: That's where I'd focus. Good luck.

## Counter measures

So what you can do as a defender about software like PowerHub?

It's simple:

1. Enable constrained language mode
1. Make sure PowerShell version 2 is disabled
1. Block all executables in user-writable directories as well as [these LOLBINs](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules)

(Hey, no one said it would be easy, I only said it was simple ...)

And don't get too hung up on this tool. These techniques are not new and not
unique to PowerHub. Antivirus products can *always* be tricked. They are
insufficient and you should apply application control instead, for example
using AppLocker or Application Guard.
