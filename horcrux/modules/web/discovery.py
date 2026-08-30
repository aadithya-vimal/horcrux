from __future__ import annotations

from pathlib import Path


def pick_wordlist() -> str | None:
    for candidate in [
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
        "/usr/share/dirb/wordlists/common.txt",
    ]:
        path = Path(candidate)
        if path.exists():
            return str(path)
    return None


def run(ws, runner, target: str, port: int):
    wordlist = pick_wordlist()
    if not wordlist:
        return None

    base = f"{'https' if port in {443,8443} else 'http'}://{target}:{port}"

    if runner.which("ffuf"):
        return runner.run(
            [
                "ffuf",
                "-u", base + "/FUZZ",
                "-w", wordlist,
                "-mc", "200,204,301,302,307,308,401,403",
                "-of", "json",
                "-o", str(ws.raw / f"ffuf-{port}.json"),
            ],
            f"ffuf-{port}",
            timeout=900,
        )

    if runner.which("gobuster"):
        return runner.run(
            [
                "gobuster", "dir",
                "-u", base,
                "-w", wordlist,
                "-q",
                "-o", str(ws.raw / f"gobuster-{port}.txt"),
            ],
            f"gobuster-{port}",
            timeout=900,
        )

    if runner.which("feroxbuster"):
        return runner.run(
            [
                "feroxbuster",
                "-u", base,
                "-w", wordlist,
                "--quiet",
                "--json",
                "-o", str(ws.raw / f"ferox-{port}.json"),
            ],
            f"ferox-{port}",
            timeout=900,
        )

    return None
