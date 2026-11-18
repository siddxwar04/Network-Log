"""Synthetic network log generator.

Produces realistic log files with known incidents hidden inside, plus a label file
(the answer key) for each. Deliberately independent of the backend: it must never
import from `netlog`, so the two cannot share bugs.
"""
