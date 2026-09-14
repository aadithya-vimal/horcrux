# -*- coding: utf-8 -*-
"""Exact HORCRUX heading art (user-supplied, byte-for-byte, v3).

Plain block-letter art, no ANSI codes. Trailing whitespace is
normalized (rstrip) since it is unknowable from chat transport and
invisible on terminals. Renderers MUST print lines verbatim and MUST
NOT pass this through Rich markup parsing.
"""

from __future__ import annotations

HEADING_SPEC = '▄▄▄▄▄▄ ▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄ ▄▄▄▄▄▄ ▄▄▄▄▄▄ ▄▄▄▄▄▄\n██▄▄██ ██▄▄██ ██▄▄▄▄▄▄▄▄▄██ ██▄▄▄▄▄▄▄▄▄██  ██▄▄▄▄▄▄▄▄▄██ ██▄▄▄▄▄▄▄▄▄██  ██▄▄██ ██▄▄██ ██▄▄██ ██▄▄██\n██████ ██████ ████▀▀▀▀▀████ ████▀▀▀▀▀████  ████▀▀▀▀▀████ ████▀▀▀▀▀████  ██████ ██████ ██████ ██████\n██████ ██████ █████▄▀██████ █████▄▀██████  █████▄▀██████ █████▄▀██████  ██████ ██████ ██████ ██████\n██▒▓██ ██▒▓██ ██▒▓██ ██▒▓██ ██▓█ █ ██████  ██▓███ ▀▄▄▄▄█ ██▓█ █ ██████  ██▒▓██ ██▒▓██ ██▒▓██▄▀█▓▓██\n██░▒██ ██░▒██ ██░▒██ ██░▒██ ██▒▓ ▀▀▀█▓▓██  ██░▒██        ██▒▓ ▀▀▀█▓▓██  ██░▒██ ██░▒██  ██▒▄▄▄▄▄███\n█▓█░▓█ █▓█░▓█ █▓█░▓█ █▓█░▓█ ██░▒▒▒▒▒▒▒▒ █  █▓█░▓█        ██░▒▒▒▒▒▒▒▒ █  █▓█░▓█ █▓█░▓█ █▓█░▓▄▄▄▓▒░▓█\n█▒▓█▒█ █▒▓█▒█ █▒▓█▒█ █▒▓█▒█ █▓█░▓▄▄▓▒▒█░   █▒▓█▒█ ▄▀▀▀▀█ █▓█░▓▄▄▓▒▒█░   █▒▓█▒█ █▒▓█▒█ █▒▓█▒█ █░▒░▒█\n█░▒▓░▀▀▀░▒▓░█ █░▒▓░█ █░▒▓░█ █▒▓█▒█▐▌▓░░█▀▄ █░▒▓░█ █ ▓▓ █ █▒▓█▒█▐▌▓░░█▀▄ █░▒▓░█ █░▒▓░█ █░▒▓░█ █▓░▓░█\n█ ░▒▒▒▒▒▒▒▒ █ █ ░▒▒█▄▀▒▒▒ █ █ ░▒ █ █░█▓▒ █ █ ░▒ ▀▀▀ ▒▒ █ █ ░▒ █ █░█▓▒ █ █ ░▒▒█▄▀▒▒▒ █ █ ▒▒ █ █ ▒▒ █\n█ ░░ ▄▄▄ ░░ █ █ ░░░░░░░░░ █ █ ░░ █ ▐█ ░░ █ █ ░░░░░░░░░ █ █ ░░ █ ▐█ ░░ █ █ ░░░░░░░░░ █ █ ░░ █ █ ░░ █\n█▄▄▄▄▀ █▄▄▄▄▀ █▄▄▄▄▄▄▄▄▄▄▄▀ █▄▄▄▄▀  █▄▄▄▄▀ █▄▄▄▄▄▄▄▄▄▄▄▀ █▄▄▄▄▀  █▄▄▄▄▀ █▄▄▄▄▄▄▄▄▄▄▄▀ █▄▄▄▄▀ █▄▄▄▄▀'

HEADING_LINES_SPEC = HEADING_SPEC.split(chr(10))

VISIBLE_WIDTH = 99

def render() -> str:
    """Terminal-ready text, verbatim."""
    return HEADING_SPEC

def render_lines() -> list[str]:
    return HEADING_SPEC.split(chr(10))

def strip_ansi(text: str) -> str:
    """Identity for the plain v3 art (kept for API compatibility)."""
    return text
