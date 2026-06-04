"""Pure, I/O-free domain core: envelopes, errors, and boundary validation.

Nothing in ``core`` performs I/O, loads the JVM, or talks to the worker. It contains the frozen
contract types (untrusted-data envelope, error envelope) and the validation logic for tool
arguments. This is a critical path (100% coverage target — master §4).
"""
