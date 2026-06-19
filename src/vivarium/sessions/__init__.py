"""Session lifecycle: persistent per-binary sessions with TTL + idle eviction.

Each session owns exactly one Ghidra worker (ADR-002); the worker is killed and the per-session
project store is verified-wiped on eviction (TTL, idle timeout, explicit close, or worker
poisoning). The session manager is also the authorization point that prevents cross-session
access (BOLA — trust boundary 1/2). Critical path: session isolation targets 100% coverage.
"""
