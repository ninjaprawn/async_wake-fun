Fun additions to async_await

Original patchfinder64 by xerub, additions of current gadgets + fix for allproc by ninjaprawn

Currently implemented:
- setuid(0) - no panic
- KCALL - call kernel functions given an address and up to six arguments
- mount / as rw
- amfi bypass? well, run unsigned code (temporary until i figure out a master process which gives everyone everything with the right entitlements etc.) - only really used to get the amfi**d** patch
- amfi**d** patch

Planned:
- Basic dylib injection into running process without needing com.apple.private.skip-library-validation (probs not possible without the entitlement)

If libproc.h doesn't exist, delete the line

Please don't rip off any code from fun.m, or my additions to the patchfinder. If you do, please credit me (@theninjaprawn)
