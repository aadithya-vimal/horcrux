from __future__ import annotations

import itertools
import math
import random
import sys
import time
from typing import List, Tuple

from rich import box
from rich.align import Align
from rich.console import Console, RenderableType
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

# Ensure UTF-8 output encoding across platforms (especially Windows consoles)
if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# HORCRUX TITLE & FRAMES
# ---------------------------------------------------------------------------

TITLE = r"""
██╗  ██╗ ██████╗ ██████╗  ██████╗██████╗ ██╗   ██╗██╗  ██╗
██║  ██║██╔═══██╗██╔══██╗██╔════╝██╔══██╗╚██╗ ██╔╝╚██╗██╔╝
███████║██║   ██║██████╔╝██║     ██████╔╝ ╚████╔╝  ╚███╔╝ 
██╔══██║██║   ██║██╔══██╗██║     ██╔══██╗  ╚██╔╝   ██╔██╗ 
██║  ██║╚██████╔╝██║  ██║╚██████╗██║  ██║   ██║   ██╔╝ ██╗
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
                      HORCRUX
""".strip("\n")

TITLE_FRAMES = [
    TITLE,
r"""
██╗  ██╗ ██████╗ ██████╗  ██████╗██████╗ ██╗   ██╗██╗  ██╗
██║  ██║██╔═══██╗██╔══██╗██╔════╝██╔══██╗╚██╗ ██╔╝╚██╗██╔╝
███████║██║   ██║██████╔╝██║     ██████╔╝ ╚████╔╝  ╚███╔╝ 
██╔══██║██║   ██║██╔══██╗██║     ██╔══██╗  ╚██╔╝   ██╔██╗ 
██║  ██║╚██████╔╝██║  ██║╚██████╗██║  ██║   ██║   ██╔╝ ██╗
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
""".strip("\n"),
]


# ---------------------------------------------------------------------------
# COLOR PALETTES & GRADIENTS
# ---------------------------------------------------------------------------

PALETTES = {
    "horcrux": [
        "#4B0082", "#6A0DAD", "#8A2BE2", "#9932CC",
        "#BA55D3", "#DA70D6", "#FF00FF", "#00FFFF", "#E0FFFF",
    ],
    "cyber": [
        "#003366", "#006699", "#0099CC", "#00CCFF",
        "#00FFFF", "#33FFCC", "#66FF99", "#CCFF66",
    ],
    "emerald": [
        "#004d26", "#007a3d", "#00a854", "#00d66c",
        "#2bf78e", "#70ffb0", "#b3ffd4", "#ffffff",
    ],
    "fire": [
        "#660000", "#990000", "#cc3300", "#ff6600",
        "#ff9900", "#ffcc00", "#ffff66", "#ffffff",
    ],
    "amethyst": [
        "#330033", "#660066", "#990099", "#cc00cc",
        "#ff00ff", "#ff66ff", "#ff99ff", "#ffffff",
    ],
}


def hex_to_rgb(hex_color: str) -> Tuple[int, int, int]:
    hex_color = hex_color.lstrip("#")
    if len(hex_color) == 3:
        hex_color = "".join(c * 2 for c in hex_color)
    return tuple(int(hex_color[i:i + 2], 16) for i in (0, 2, 4))  # type: ignore


def rgb_to_hex(r: int, g: int, b: int) -> str:
    return f"#{max(0, min(255, int(r))):02x}{max(0, min(255, int(g))):02x}{max(0, min(255, int(b))):02x}"


def interpolate_color(color1: str, color2: str, factor: float) -> str:
    r1, g1, b1 = hex_to_rgb(color1)
    r2, g2, b2 = hex_to_rgb(color2)
    r = r1 + (r2 - r1) * factor
    g = g1 + (g2 - g1) * factor
    b = b1 + (b2 - b1) * factor
    return rgb_to_hex(int(r), int(g), int(b))


def generate_gradient(palette: List[str], steps: int) -> List[str]:
    if steps <= 1:
        return [palette[0]]
    gradient = []
    num_segments = len(palette) - 1
    steps_per_segment = steps / num_segments
    for i in range(steps):
        segment = min(int(i / steps_per_segment), num_segments - 1)
        factor = (i - segment * steps_per_segment) / steps_per_segment
        gradient.append(interpolate_color(palette[segment], palette[segment + 1], factor))
    return gradient


def render_gradient_text(text: str, palette_name: str = "horcrux", shift: int = 0) -> Text:
    lines = text.split("\n")
    max_len = max((len(l) for l in lines), default=1)
    palette = PALETTES.get(palette_name, PALETTES["horcrux"])
    gradient = generate_gradient(palette, max_len + 12)

    result = Text()
    for row_idx, line in enumerate(lines):
        for col_idx, char in enumerate(line):
            if char == " ":
                result.append(char)
            else:
                color_idx = (col_idx + shift + row_idx * 2) % len(gradient)
                color = gradient[color_idx]
                result.append(char, style=f"bold {color}")
        if row_idx < len(lines) - 1:
            result.append("\n")
    return result


# ---------------------------------------------------------------------------
# HORCRUX & ARCANE ARTIFACT GRAPHICS GALLERY
# ---------------------------------------------------------------------------

GRAPHIC_DATA = [
    # 0. The Elder Wand
    {
        "name": "The Elder Wand",
        "category": "Deathly Hallow",
        "description": "The Deathstick. Wand of Destiny. Unyielding conduit of raw power.",
        "color": "bright_cyan",
        "art": r"""
           · ✦ ·
             │
            ░█░
             │
           ▓███▓
          ░█████░
           ▓███▓
             │
            ╲█╱
           ░▓█▓░
             │
           ▓███▓
             ▾
""",
    },
    # 1. Tom Riddle's Diary
    {
        "name": "Tom Riddle's Diary",
        "category": "Horcrux I",
        "description": "Blank parchment drenched in memory and dark enchantments.",
        "color": "bright_magenta",
        "art": r"""
         ._____________________.
        /  _________________  /|
       /  /  T.M. RIDDLE   / / |
      /  /                / /  |
     /  /     ╭──────╮   / /   |
    |  |      │ ✦ ✦  │  | |    |
    |  |      │  ▼   │  | |    |
    |  |      ╰──────╯  | |   /
    |  |   ink bleeds   | |  /
    |  |________________|/  /
    |______________________/
""",
    },
    # 2. Marvolo Gaunt's Ring
    {
        "name": "Marvolo Gaunt's Ring",
        "category": "Horcrux II",
        "description": "Ancient gold band holding the Resurrection Stone signet.",
        "color": "bright_yellow",
        "art": r"""
             .─────────.
           .'    ___    '.
          /    .'   '.    \
         |    /   ▲   \    |
         |   |  / ┃ \  |   |
         |    \ ━━┻━━ /    |
          \    '.___.'    /
           '.           .'
             '─────────'
              │ ✦ ✦ ✦ │
               \_____/
""",
    },
    # 3. Salazar Slytherin's Locket
    {
        "name": "Salazar Slytherin's Locket",
        "category": "Horcrux III",
        "description": "Heavy golden medallion emblazoned with the serpentine crest.",
        "color": "bright_green",
        "art": r"""
              ╱╲_____╱╲
             │  \___/  │
              ╲   │   ╱
             .─┴──────┴─.
            /  ╭─────╮   \
           |   │  S  │    |
           |   │ ╭─╯ │    |
           |   │ ╰─╮ │    |
            \  ╰─────╯   /
             '.   ✦   .'
               '─────'
""",
    },
    # 4. Helga Hufflepuff's Cup
    {
        "name": "Helga Hufflepuff's Cup",
        "category": "Horcrux IV",
        "description": "Two-handled golden chalice engraved with the steadfast badger.",
        "color": "yellow",
        "art": r"""
           \╲  ✦ ✦ ✦  ╱/
            \╲_______╱/
             |       |
            (| ╭───╮ |)
             | │ ✦ │ |
             | ╰───╯ |
              \     /
               )   (
              /     \
             /_______\
""",
    },
    # 5. Rowena Ravenclaw's Diadem
    {
        "name": "Rowena Ravenclaw's Diadem",
        "category": "Horcrux V",
        "description": "Wit beyond measure is man's greatest treasure.",
        "color": "bright_blue",
        "art": r"""
              .─.     .─.
             /   \ ✦ /   \
            /  /\ \ / /\  \
           /  /  \_V_/  \  \
          /  /           \  \
         (__(    ╭───╮    )__)
              \  │ ♦ │  /
               \ ╰───╯ /
                '─────'
""",
    },
    # 6. Nagini the Serpent
    {
        "name": "Nagini",
        "category": "Horcrux VI",
        "description": "The great venomous serpent woven into Voldemort's soul.",
        "color": "bright_green",
        "art": r"""
             .-==-._
            /  ✦ ✦  \
           |   (oo)  |
            \   ==  /
             '._  _.'
                ||
            _.-'  '-._
          .'  _...._  '.
         /  .'      '.  \
        |  /          \  |
         \ '.________.' /
          '._        _.'
             `''''''`
""",
    },
    # 7. The Boy Who Lived
    {
        "name": "The Seventh Fragment",
        "category": "The Scar",
        "description": "The curse that rebounded, leaving a lightning bolt etched in fate.",
        "color": "bright_red",
        "art": r"""
              \     /
               \   /
                \ /
                 V
                / \
               /   \
                 \
             .---.   .---.
            /     \ /     \
           |   O   X   O   |
            \     / \     /
             '---'   '---'
""",
    },
    # 8. The Deathly Hallows
    {
        "name": "The Deathly Hallows",
        "category": "Master of Death",
        "description": "The Wand, the Stone, and the Cloak. Together, conquerors of mortality.",
        "color": "bright_magenta",
        "art": r"""
                 ▲
                /│\
               / │ \
              /  │  \
             /  ╭●╮  \
            /  │ │ │  \
           /   │ │ │   \
          /     ╰●╯     \
         /_______│_______\
""",
    },
    # 9. Golden Snitch
    {
        "name": "The Golden Snitch",
        "category": "Quidditch Relic",
        "description": "I open at the close. Fluttering wings of spun gold.",
        "color": "bright_yellow",
        "art": r'''
          .-""""-.       .-""""-.
        .'  /--\  '.   .'  /--\  '.
       /   /    \   \_/   /    \   \
      |   ( ✦ ✦ )   / \  ( ✦ ✦ )   |
       \   \    /  /   \  \    /  /
        '.  \--/  /  _  \  \--/  .'
          '-....-'  / \  '-....-'
                   ( ● )
                    '-'
''',
    },
    # 10. Hogwarts Citadel
    {
        "name": "Hogwarts Citadel",
        "category": "Sanctuary",
        "description": "Ancient stone towers, soaring battlements, and hidden chambers.",
        "color": "bright_cyan",
        "art": r"""
             /\              /\
            /  \    _/\_    /  \
           /    \  |    |  /    \
          |  /\  | | /\ | |  /\  |
          | |  | | | || | | |  | |
         /  |  |  \| || |/  |  |  \
        |___|__|___|_||_|___|__|___|
        |   [ ]      ||      [ ]   |
        |__________[====]__________|
""",
    },
]

GRAPHICS = [item["art"] for item in GRAPHIC_DATA]
ELDER_WAND = GRAPHICS[0]


# ---------------------------------------------------------------------------
# SPARKLE PARTICLES FOR ANIMATIONS
# ---------------------------------------------------------------------------

SPARKLES = ["✦", "✧", "✶", "✵", "✹", "✺", "·", "°", "⋆"]


def generate_sparkle_line(width: int = 50, density: float = 0.15) -> Text:
    text = Text()
    colors = ["#FF00FF", "#00FFFF", "#FFFF00", "#FFFFFF", "#BA55D3", "#00FA9A"]
    for _ in range(width):
        if random.random() < density:
            char = random.choice(SPARKLES)
            color = random.choice(colors)
            text.append(char, style=f"bold {color}")
        else:
            text.append(" ")
    return text


# ---------------------------------------------------------------------------
# RENDERING ENGINE
# ---------------------------------------------------------------------------

def render(
    frame: int,
    version: str | None = None,
    palette_name: str = "horcrux",
    graphic_index: int | None = None,
) -> RenderableType:
    idx = (frame % len(GRAPHIC_DATA)) if graphic_index is None else (graphic_index % len(GRAPHIC_DATA))
    item = GRAPHIC_DATA[idx]

    # Shimmering gradient title
    title_text = render_gradient_text(TITLE, palette_name=palette_name, shift=frame * 3)

    # Subtitle with animated sparkles
    sub = Text()
    sub.append("\n  ✦ ─── ", style="bold magenta")
    sub.append("THE FRAGMENTS REVEAL THE WHOLE", style="bold bright_white")
    sub.append(" ─── ✦  ", style="bold magenta")

    if version:
        sub.append(f"\n  [ v{version} ]  ", style="bold bright_cyan")
        sub.append("Offensive Security Reconnaissance & Operator Platform", style="dim italic")

    return Align.center(
        Panel(
            Align.center(
                Text.assemble(
                    title_text,
                    "\n",
                    sub,
                    "\n\n",
                )
            ),
            subtitle="[dim]HORCRUX ENGINE[/dim]",
            box=box.HEAVY,
            border_style="magenta",
            padding=(0, 2),
        )
    )


# ---------------------------------------------------------------------------
# ANIMATED BANNERS & EFFECTS
# ---------------------------------------------------------------------------

def banner(
    console: Console,
    version: str | None = None,
    duration: float = 1.0,
    palette: str = "horcrux",
):
    """Animated shimmering banner with particle wave."""
    art_idx = random.randrange(len(GRAPHIC_DATA))
    item = GRAPHIC_DATA[art_idx]

    deadline = time.monotonic() + duration
    frame = 0

    with Live(
        console=console,
        refresh_per_second=14,
        transient=True,
    ) as live:
        while time.monotonic() < deadline:
            title_text = render_gradient_text(TITLE, palette_name=palette, shift=frame * 4)

            header_panel = Panel(
                Align.center(
                    Text.assemble(
                        generate_sparkle_line(54, density=0.12),
                        "\n",
                        title_text,
                        "\n",
                        Text("✦ ─── THE FRAGMENTS REVEAL THE WHOLE ─── ✦", style="bold bright_magenta"),
                        f"\n[dim cyan]v{version or '1.0.0'}[/dim cyan] [dim white]• Autonomous Attack Surface Orchestration[/dim white]\n",
                        generate_sparkle_line(54, density=0.12),
                    )
                ),
                box=box.DOUBLE_EDGE,
                border_style="bright_magenta",
                padding=(0, 1),
            )

            live.update(
                Align.center(header_panel)
            )

            frame += 1
            time.sleep(0.07)

    # Print clean static banner at rest
    final_title = render_gradient_text(TITLE, palette_name=palette, shift=frame * 4)
    final_panel = Panel(
        Align.center(
            Text.assemble(
                final_title,
                "\n\n",
                Text("⚡ THE FRAGMENTS REVEAL THE WHOLE ⚡", style="bold bright_magenta"),
                f"\n[bold cyan]v{version or '1.0.0'}[/bold cyan] [dim white]• Operator Reconnaissance & Intelligence Engine[/dim white]",
            )
        ),
        box=box.ROUNDED,
        border_style="magenta",
        padding=(0, 2),
    )
    console.print()
    console.print(Align.center(final_panel))
    console.print()


def loading(
    console: Console,
    message: str,
    duration: float = 0.7,
    style: str = "sparkle",
):
    """Rich dynamic spinner animation with colorful particle waves."""
    pulse_frames = [
        "⟦  ▰▱▱▱▱▱▱▱▱▱  ⟧",
        "⟦  ▰▰▱▱▱▱▱▱▱▱  ⟧",
        "⟦  ▰▰▰▱▱▱▱▱▱▱  ⟧",
        "⟦  ▱▰▰▰▱▱▱▱▱▱  ⟧",
        "⟦  ▱▱▰▰▰▱▱▱▱▱  ⟧",
        "⟦  ▱▱▱▰▰▰▱▱▱▱  ⟧",
        "⟦  ▱▱▱▱▰▰▰▱▱▱  ⟧",
        "⟦  ▱▱▱▱▱▰▰▰▱▱  ⟧",
        "⟦  ▱▱▱▱▱▱▰▰▰▱  ⟧",
        "⟦  ▱▱▱▱▱▱▱▰▰▰  ⟧",
        "⟦  ▱▱▱▱▱▱▱▱▰▰  ⟧",
        "⟦  ▱▱▱▱▱▱▱▱▱▰  ⟧",
    ]

    spark_cycles = ["✦", "✧", "✶", "✷", "✸", "✹", "✺", "✵"]
    runes = ["᚛", "ᚠ", "ᚢ", "ᚦ", "ᚨ", "ᚱ", "ᚲ", "ᚺ", "ᚾ", "ᛃ", "ᛈ", "ᛉ", "ᛋ", "ᛏ", "ᛒ", "ᛖ", "ᛗ", "ᛚ", "᚜"]
    colors = ["magenta", "bright_magenta", "bright_cyan", "cyan", "bright_blue", "white"]

    deadline = time.monotonic() + duration
    frame = 0

    with Live(
        console=console,
        refresh_per_second=18,
        transient=True,
    ) as live:
        while time.monotonic() < deadline:
            color = colors[frame % len(colors)]
            spark = spark_cycles[frame % len(spark_cycles)]
            rune = runes[frame % len(runes)]
            pulse = pulse_frames[frame % len(pulse_frames)]

            rendered = Text()
            rendered.append(f"  {spark} ", style=f"bold {color}")
            rendered.append(f"{rune} ", style="bold bright_yellow")
            rendered.append(f"{pulse} ", style="bold magenta")
            rendered.append(f"{message}... ", style="bold bright_white")
            rendered.append(f"{spark}", style=f"bold {color}")

            live.update(rendered)
            frame += 1
            time.sleep(0.05)

    console.print(f"  [bold green]✔[/bold green] [dim white]{message}[/dim white]")


def fanfare(console: Console, message: str = "SURFACE SYNTHESIS COMPLETE"):
    """Fanfare animation celebrating scan completion."""
    console.print()
    console.print(
        Align.center(
            Panel(
                Align.center(
                    Text.assemble(
                        ("⚡ ✦ ── ", "bold bright_magenta"),
                        (message, "bold bright_white"),
                        (" ── ✦ ⚡", "bold bright_cyan"),
                    )
                ),
                box=box.ROUNDED,
                border_style="bright_magenta",
                padding=(0, 2),
            )
        )
    )
    console.print()


def show_gallery(console: Console):
    """Showcase all the Horcrux artifacts with their graphics."""
    console.print()
    console.print(
        Align.center(
            Panel(
                "[bold bright_magenta]✦ HORCRUX ARTIFACTS & RELICS GALLERY ✦[/bold bright_magenta]\n"
                "[dim]The seven soul fragments and the relics of ancient power[/dim]",
                box=box.DOUBLE,
                border_style="magenta",
                padding=(0, 2),
            )
        )
    )
    console.print()

    for idx, item in enumerate(GRAPHIC_DATA):
        card = Panel(
            Align.center(Text(item["art"].strip("\n"), style=f"bold {item['color']}")),
            title=f"[bold bright_white]#{idx + 1} {item['category']}[/bold bright_white] · [bold {item['color']}]{item['name']}[/bold {item['color']}]",
            subtitle=f"[italic dim]{item['description']}[/italic dim]",
            box=box.ROUNDED,
            border_style=item["color"],
            padding=(0, 1),
        )
        console.print(card)
        console.print()
