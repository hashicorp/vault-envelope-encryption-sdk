# Vault Envelope Encryption SDK

This SDK provides utilities for using Vault Transit keys for large file encryption.

The use of the SDK requires a Vault Enterprise instance with the Transit secrets
engine enabled. There must be an AES key available in Transit for data key encryption.

The tests expect a Vault dev server with root token `root`.