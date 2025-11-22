# ============================================================================
# heph/__main__.py
# ----------------
# Entry point for `python -m heph` execution.
# ============================================================================

"""
Allow running Hephaestus as a module:
    python -m heph --target https://example.com
"""

if __name__ == '__main__':
    import sys
    from .cli import main
    sys.exit(main())