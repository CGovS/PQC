"""maze — the vulnerable target application.

A tiny "vault" whose contents are sealed by whatever LockBox the crypto-agility
layer hands it. In Phase 1 that is toy RSA, so the vault is breakable by the
simulated Shor attack built in Phase 2. In Phase 4 the exact same vault code is
re-sealed with a post-quantum LockBox and the same attack fails.
"""
