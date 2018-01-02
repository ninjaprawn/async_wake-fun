Fun additions to async_wake

Features:
- setuid(0) with no kernel panic
- mount / as rw
- AMFI bypass via trustcache injection
- amfid patch - utilises the AMFI bypass to inject into amfid and replace MISValidateSignatureAndCopyInfo with our own version

See the comments for an explanation for some of the things going on. Better `kexecute` explanations can be found by people like Siguza and @bazad (on GH). I might consider doing a proper explanation of the AMFI.kext bypass (a good overview can be found in *OS Internals Vol. 3, but I would go in detail at code level), and the amfid bypass (I've already briefly explaned in #21, but again, go a bit deeper)

Credits:
- Ian Beer for the original exploit
- @xerub for the KPPless patches
- @s1guza for the base of the kexecute idea of modifying the vtable of a user client (which I used before I noticed Ian Beer includes it), and the resolving of the upper 4 bytes of memory addresses returned from kexecute
- @theninjaprawn for amfid patch
- @coolstarorg for doing the cooler stuff (see his fork https://github.com/coolstar/async_awake-fun - he's got a jailbreakd daemon + more)
- @stek29, @nullriver
