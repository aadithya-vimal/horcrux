from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional, Sequence
from urllib.parse import urljoin

import httpx

from horcrux.models import (
    DiscoveredPath,
    EvidenceClassification,
    RawObservation,
    ResponseFamily,
    ResponseFingerprint,
    ValidationState,
)
from horcrux.modules.web.fingerprint_engine import (
    cluster_response_families,
    fingerprint_response,
    same_response_family,
)
from horcrux.modules.web.wordlists import resolve_wordlist


def run_fuzzer(
    ws,
    runner,
    target: str,
    port: int,
    strategy: str = "common",
    custom_wordlist: str = "",
    baseline_fps: Sequence[ResponseFingerprint] = (),
) -> list[DiscoveredPath]:
    """
    Executes content discovery using the best available tool on the operator's machine.
    Clusters results into response families and suppresses catch-all/SPA fallback noise.
    Raw observations are preserved for forensic review while suppressed noise is removed
    from the primary attack surface.
    """
    scheme = "https" if port in {443, 8443} else "http"
    base_url = f"{scheme}://{target}:{port}"

    wordlist_path, is_fallback, wl_msg = resolve_wordlist(strategy, custom_wordlist, ws=ws)

    discovered_paths: list[DiscoveredPath] = []
    tool_used = "none"

    # Strategy 1: FFUF (Fastest, rich JSON output)
    if runner.which("ffuf"):
        tool_used = "ffuf"
        out_json = ws.raw / f"ffuf-{port}.json"
        cmd = [
            "ffuf",
            "-u", f"{base_url}/FUZZ",
            "-w", str(wordlist_path),
            "-mc", "200,204,301,302,307,308,401,403,405,500",
            "-of", "json",
            "-o", str(out_json),
            "-s",  # silent
            "-t", "40",
            "-timeout", "10",
        ]
        runner.run(cmd, f"ffuf-{port}", timeout=600)
        if out_json.exists():
            try:
                data = json.loads(out_json.read_text(encoding="utf-8", errors="replace"))
                for item in data.get("results", []):
                    input_path = item.get("input", {}).get("FUZZ", "")
                    clean_path = "/" + input_path.lstrip("/")
                    status = item.get("status", 200)
                    size = item.get("length", 0)
                    redirect = item.get("redirectlocation", "")
                    content_type = item.get("content-type", "")

                    fp = ResponseFingerprint(
                        status_code=status,
                        content_type=content_type,
                        normalized_body_length=size,
                        final_url=urljoin(base_url + "/", clean_path.lstrip("/")),
                    )

                    discovered_paths.append(
                        DiscoveredPath(
                            url=urljoin(base_url + "/", clean_path.lstrip("/")),
                            path=clean_path,
                            status=status,
                            size=size,
                            redirect=redirect,
                            content_type=content_type,
                            source="ffuf",
                            wordlist=str(wordlist_path),
                            fingerprint=fp,
                        )
                    )
            except Exception as exc:
                ws.write(f"raw/ffuf-{port}.parse-error", str(exc))

    # Strategy 2: Gobuster
    elif runner.which("gobuster"):
        tool_used = "gobuster"
        out_txt = ws.raw / f"gobuster-{port}.txt"
        cmd = [
            "gobuster", "dir",
            "-u", base_url,
            "-w", str(wordlist_path),
            "-q",
            "-o", str(out_txt),
            "-t", "30",
            "--timeout", "10s",
            "-s", "200,204,301,302,307,401,403",
        ]
        runner.run(cmd, f"gobuster-{port}", timeout=600)
        if out_txt.exists():
            for line in out_txt.read_text(encoding="utf-8", errors="replace").splitlines():
                match = re.search(r"(\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?", line)
                if match:
                    p = "/" + match.group(1).lstrip("/")
                    st = int(match.group(2))
                    sz = int(match.group(3)) if match.group(3) else 0
                    fp = ResponseFingerprint(status_code=st, normalized_body_length=sz)
                    discovered_paths.append(
                        DiscoveredPath(
                            url=urljoin(base_url + "/", p.lstrip("/")),
                            path=p,
                            status=st,
                            size=sz,
                            source="gobuster",
                            wordlist=str(wordlist_path),
                            fingerprint=fp,
                        )
                    )

    # Strategy 3: Feroxbuster
    elif runner.which("feroxbuster"):
        tool_used = "feroxbuster"
        out_json = ws.raw / f"ferox-{port}.json"
        cmd = [
            "feroxbuster",
            "-u", base_url,
            "-w", str(wordlist_path),
            "--quiet",
            "--json",
            "-o", str(out_json),
            "-t", "30",
            "--timeout", "10",
        ]
        runner.run(cmd, f"ferox-{port}", timeout=600)
        if out_json.exists():
            for line in out_json.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get("type") == "response":
                        u = entry.get("url", "")
                        st = entry.get("status", 200)
                        sz = entry.get("content_length", 0)
                        p = "/" + u.replace(base_url, "").lstrip("/")
                        fp = ResponseFingerprint(status_code=st, normalized_body_length=sz, final_url=u)
                        discovered_paths.append(
                            DiscoveredPath(
                                url=u,
                                path=p,
                                status=st,
                                size=sz,
                                source="feroxbuster",
                                wordlist=str(wordlist_path),
                                fingerprint=fp,
                            )
                        )
                except Exception:
                    pass

    # Strategy 4: Python Native Concurrent Prober (Zero-dependency fallback)
    else:
        tool_used = "python-native-fuzzer"
        ws.write(f"raw/fuzzer-{port}.notice", "No external fuzzer found; using native Horcrux HTTP prober.")
        try:
            lines = [l.strip() for l in wordlist_path.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip() and not l.startswith("#")]
            probe_limit = min(len(lines), 300)
            with httpx.Client(verify=False, timeout=6.0, headers={"User-Agent": "Horcrux/1.0"}) as client:
                for word in lines[:probe_limit]:
                    clean_path = "/" + word.lstrip("/")
                    target_url = urljoin(base_url + "/", clean_path.lstrip("/"))
                    try:
                        resp = client.get(target_url)
                        if resp.status_code in {200, 204, 301, 302, 307, 308, 401, 403, 500}:
                            fp = fingerprint_response(
                                status_code=resp.status_code,
                                text=resp.text,
                                headers=dict(resp.headers),
                                url=str(resp.url),
                            )
                            discovered_paths.append(
                                DiscoveredPath(
                                    url=target_url,
                                    path=clean_path,
                                    status=resp.status_code,
                                    size=len(resp.content),
                                    content_type=resp.headers.get("content-type", ""),
                                    source="horcrux-native",
                                    wordlist=str(wordlist_path),
                                    fingerprint=fp,
                                )
                            )
                    except Exception:
                        pass
        except Exception as exc:
            ws.write(f"raw/native-fuzzer-{port}.error", str(exc))

    # Record Raw Observation for tool execution
    ws.add_raw_observations([
        RawObservation(
            source_tool=tool_used,
            target=base_url,
            observation_type="fuzzer_output",
            data={"total_paths_observed": len(discovered_paths), "port": port},
        )
    ])

    # Cluster responses into Response Families and identify suppressed fallback noise
    fp_tuples = [
        (p.path, p.fingerprint or ResponseFingerprint(status_code=p.status, normalized_body_length=p.size))
        for p in discovered_paths
    ]
    families, path_to_fam = cluster_response_families(fp_tuples, baseline_fps=baseline_fps)

    # Detect mass-repetition catch-all if no baseline was supplied:
    # If a single family accounts for > 80% of paths when total > 20, mark as SUPPRESSED_FALLBACK
    if len(discovered_paths) >= 20:
        for fam in families:
            if fam.member_count >= len(discovered_paths) * 0.8:
                fam.classification = EvidenceClassification.SUPPRESSED_FALLBACK

    fam_dict = {f.family_id: f for f in families}

    # Tag each path with its family and classification
    for p in discovered_paths:
        f_id = path_to_fam.get(p.path, "")
        p.response_family_id = f_id
        if f_id in fam_dict:
            p.evidence_classification = fam_dict[f_id].classification

    ws.upsert_response_families(families)

    # Persist all observed paths to forensic raw storage
    ws.write_json(
        f"raw/all-fuzzer-paths-{port}.json",
        [p.model_dump(mode="json") for p in discovered_paths],
    )

    # Filter out suppressed fallback noise from the primary attack surface
    clean_surface_paths = [
        p for p in discovered_paths
        if p.evidence_classification != EvidenceClassification.SUPPRESSED_FALLBACK
    ]

    ws.upsert_discovered_paths(clean_surface_paths)
    ws.write_json(
        f"raw/discovered-paths-{port}.json",
        [p.model_dump(mode="json") for p in clean_surface_paths],
    )

    return clean_surface_paths

