# MobileGestalt cache and `bad_query` — two userland routes that stop in userland

**Status:** both closed as steps toward kernel access.
**Components:** MobileGestalt cache subsystem; IOKit `bad_query` class-13 traversal.

These are grouped because both look promising from the outside — one writes system configuration,
the other is a known IOKit bug class — and both end well before kernel memory.

## MobileGestalt cache

### Claim

The device's MobileGestalt answer cache can be rewritten from an app-group container. That grants
persistent configuration spoofing inside userland. It does not grant any privilege above the app's
sandbox, and it does not reach kernel memory.

### What was measured

* The cache file is readable and writable from the app group; a poisoned write succeeded and was
  byte-verified (10 945 bytes written, `fsync` returned success).
* Restoring the original file from a snapshot also succeeded, verified twice (11 037 bytes).
* The process that rebuilds the cache is a system helper holding its own entitlement
  (`…private.security.storage.MobileGestaltCache`); calling the public answer API
  (`MGCopyAnswer`) does **not** trigger a rebuild — the modified cache is simply served.

### Why it is not a step to the kernel

The whole effect is delivered to userland clients through the same API they already use. There is
no kernel consumer that takes the modified values as an instruction, pointer or length. Spoofing
answers is a research tool (device identity work), not a privilege boundary crossing.

## `bad_query` class-13 traversal

### Claim

The IOKit `bad_query` traversal that allows reaching otherwise-unavailable object properties is
fixed for this build. Public material places the window at iOS 26.0–26.6.1 and 27.0 beta 4; the
audited build is 27.0.1.

### What was measured

Probing class 13 on this build does not return a traversable handle. No public proof of concept
for this build exists, and the fix landed before it.

### Why it is closed

Out of window. This is a version-bound conclusion: it should be re-evaluated only if a new public
report names 27.0.1 as affected.

## How to falsify either

* MobileGestalt: show any effect of the modified cache that survives above the app's sandbox —
  for example a privileged daemon taking a length, path or pointer from it.
* `bad_query`: obtain a class-13 traversal on this build.
