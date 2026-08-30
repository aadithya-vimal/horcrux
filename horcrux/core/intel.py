from horcrux.intel.search import searchsploit_workspace
from horcrux.core.runner import CommandRunner


def run_nuclei(ws, runner: CommandRunner, url: str):
    if not runner.which("nuclei"):
        return None

    return runner.run(
        [
            "nuclei",
            "-u", url,
            "-jsonl",
            "-silent",
            "-o", str(ws.raw / "nuclei.jsonl"),
        ],
        "nuclei",
        timeout=1200,
    )
