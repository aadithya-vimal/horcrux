from __future__ import annotations

import itertools
import random
import time

from rich.align import Align
from rich.console import Console
from rich.live import Live
from rich.text import Text


# ---------------------------------------------------------------------------
# HORCRUX TITLE
# ---------------------------------------------------------------------------

TITLE_FRAMES = [
r"""
██╗  ██╗ ██████╗ ██████╗  ██████╗██████╗ ██╗   ██╗██╗  ██╗
██║  ██║██╔═══██╗██╔══██╗██╔════╝██╔══██╗╚██╗ ██╔╝╚██╗██╔╝
███████║██║   ██║██████╔╝██║     ██████╔╝ ╚████╔╝  ╚███╔╝
██╔══██║██║   ██║██╔══██╗██║     ██╔══██╗  ╚██╔╝   ██╔██╗
██║  ██║╚██████╔╝██║  ██║╚██████╗██║  ██║   ██║   ██╔╝ ██╗
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
""",
r"""
██╗  ██╗ ██████╗ ██████╗  ██████╗██████╗ ██╗   ██╗██╗  ██╗
██║  ██║██╔═══██╗██╔══██╗██╔════╝██╔══██╗╚██╗ ██╔╝╚██╗██╔╝
███████║██║   ██║██████╔╝██║     ██████╔╝ ╚████╔╝  ╚███╔╝
██╔══██║██║   ██║██╔══██╗██║     ██╔══██╗  ╚██╔╝   ██╔██╗
██║  ██║╚██████╔╝██║  ██║╚██████╗██║  ██║   ██║   ██╔╝ ██╗
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
"""
]


# ---------------------------------------------------------------------------
# SMALL HARRY POTTER-THEMED GRAPHIC POOL
# One graphic is randomly selected at startup.
# ---------------------------------------------------------------------------

GRAPHICS = [
    # Elder wand
r"""
      ·
      │
     ░█░
      │
     ▓█▓
    ░███░
     ▓█▓
      │
     ╲█╱
    ░▓█▓░
      │
     ▓█▓
      ▾
""",

    # Golden snitch
r"""
       .-.
     .'   '.
    /  .-.  \
   |  ( ✦ )  |
    \  `-'  /
     '.___.'
      /   \
     /     \
""",

    # Sorting hat
r"""
        ___
      .'   '.
     /  .-.  \
    /  /   \  \
   |  |  _  |  |
   |   \___/   |
    \  /   \  /
     `'-- --'`
""",

    # Potion bottle
r"""
       .--.
      /    \
     /_    _\
       |  |
     .-====-.
    /  ✦✦  \
   |         |
    \_______/
       | |
""",

    # Quill
r"""
           __
          / /
         / /
        / /
       / /
      / /
     / /
    / /
   /_/ 
    ||
    ||
""",

    # Lightning scar
r"""
       \   /
        \ /
         V
        / \
       /   \
""",

    # Glasses
r"""
      .-----.   .-----.
     /       \ /       \
    |         X         |
     \       / \       /
      '-----'   '-----'
""",

    # Broom
r"""
        /////////
     ///         \\\
   ///             \\\
  =======================
           \
            \
             \
              \__
""",

    # Chess knight
r"""
         /\
        /  \_
       / /\  \
      / /  \  \
     /_/____\__\
        ||||
        ||||
""",

    # Castle / Hogwarts-like school
r"""
          /\        /\
         /  \______/  \
        /      /\      \
       /  /\  /  \  /\  \
      /__/  \/____\/  \__\
         |  |    |  |
         |__|    |__|
""",

    # Cauldron
r"""
        ___________
      /             \
     /               \
    |      ~ ~ ~      |
    |     ( ✦ )       |
     \               /
      \_____________/
        /         \
       /___________\
""",

    # Deathly Hallows-inspired symbol
r"""
            /\
           /  \
          /____\
          \    /
           \  /
            \/
            │
""",

    # Marauder-style map
r"""
      __________________
     /                 /|
    /  .------------. / |
   |   |  *  *  *   | | |
   |   |   _/\_      | | |
   |   |  /    \     | | /
   |   '------------' |/
    \________________/
""",

    # Time-turner style pendant
r"""
         .--------.
       .'          '.
      /     ◎◎       \
     |      ◎◎        |
      \              /
       '.          .'
         '---.  .---'
             \/
""",

    # Spell wand + spark
r"""
                     *
                    ***
                     *
        ------------------------\
                                 \
                                  \
""",
]


ELDER_WAND = GRAPHICS[0]


def render(frame: int, version: str | None = None) -> Text:
    graphic = GRAPHICS[frame % len(GRAPHICS)]

    text = Text()

    # Title only is animated.
    text.append(
        TITLE_FRAMES[frame % len(TITLE_FRAMES)],
        style="bold magenta",
    )

    text.append(
        "\nTHE FRAGMENTS REVEAL THE WHOLE",
        style="dim",
    )

    if version:
        text.append(
            f"\nVersion {version}",
            style="dim cyan",
        )

    text.append(
        "\n\n" + graphic,
        style="bold magenta",
    )

    return text


def banner(
    console: Console,
    version: str | None = None,
    duration: float = 1.2,
):
    # Random graphic, while the title itself remains animated.
    graphic_offset = random.randrange(len(GRAPHICS))

    original_len = len(GRAPHICS)
    frame = graphic_offset
    deadline = time.monotonic() + duration

    with Live(
        Align.center(render(frame, version)),
        console=console,
        refresh_per_second=10,
        transient=False,
    ) as live:

        while time.monotonic() < deadline:
            frame = (frame + 1) % original_len
            live.update(
                Align.center(render(frame, version))
            )
            time.sleep(0.14)

    console.print()


def loading(
    console: Console,
    message: str,
    duration: float = 0.8,
):
    bars = itertools.cycle([
        "⟦□□□□□□□□□□⟧",
        "⟦■□□□□□□□□□⟧",
        "⟦■■□□□□□□□□⟧",
        "⟦■■■□□□□□□□⟧",
        "⟦■■■■□□□□□□⟧",
        "⟦■■■■■□□□□□⟧",
        "⟦■■■■■■□□□□⟧",
        "⟦■■■■■■■□□□⟧",
        "⟦■■■■■■■■□□⟧",
        "⟦■■■■■■■■■□⟧",
        "⟦■■■■■■■■■■⟧",
    ])

    deadline = time.monotonic() + duration

    with Live(
        console=console,
        refresh_per_second=16,
    ) as live:

        while time.monotonic() < deadline:
            live.update(
                Align.center(
                    Text(
                        f"{next(bars)}  {message}",
                        style="bold magenta",
                    )
                )
            )
            time.sleep(0.07)

    console.print()
