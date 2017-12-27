Fun additions to async_wake

Features:
- setuid(0) with no kernel panic
- mount / as rw
- AMFI bypass using the disliked technique of "stuffing the trust cache", which you can read more about in *OS Internals Vol 3 , page 145 - by no other than Jonathan Levin himself!
- amfid patch - utilises the AMFI bypass to inject into amfid and replace MISValidateSignatureAndCopyInfo with our own version

Planned:
- Basic dylib injection into running process

Credits:
- Ian Beer for the original exploit
- @xerub for the KPPless patches
- @s1guza for the base of the kexecute idea of modifying the vtable of a user client (which I used before I noticed Ian Beer includes it), and the resolving of the upper 4 bytes of memory addresses returned from kexecute
- @ninjaprawn for amfid patch
- @coolstarorg for doing the cooler stuff (see his fork https://github.com/coolstar/async_awake-fun - he's got a jailbreakd daemon + more)
- @stek29, @nullriver
