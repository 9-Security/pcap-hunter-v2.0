class CarveError(Exception):
    """Raised when HTTP payload carving fails."""


def carve_http_payloads(pcap_path: str, out_dir: str, phase=None) -> list[dict]:
    import hashlib
    import logging
    import pathlib
    import subprocess

    from app.utils.common import find_bin

    logger = logging.getLogger(__name__)

    pathlib.Path(out_dir).mkdir(parents=True, exist_ok=True)

    tshark_bin = find_bin("tshark", cfg_key="cfg_tshark_bin")
    if not tshark_bin:
        msg = "Tshark binary not found for carving."
        logger.warning(msg)
        if phase:
            phase.done("Tshark missing.")
        raise CarveError(msg)

    if phase and phase.should_skip():
        phase.done("HTTP carving skipped.")
        return []

    if phase:
        phase.set(5, "Running tshark…")
    cmd = [
        tshark_bin,
        "-r",
        pcap_path,
        "-Y",
        "http && http.file_data",
        "-T",
        "fields",
        "-e",
        "frame.time_epoch",
        "-e",
        "tcp.stream",
        "-e",
        "http.content_type",
        "-e",
        "http.content_length",
        "-e",
        "http.file_data",
    ]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True)
    except Exception as e:
        if phase:
            phase.done("tshark failed.")
        raise CarveError(f"tshark exec failed: {e}") from e

    results = []
    lines = proc.stdout.splitlines()
    total = len(lines) if lines else 0
    for i, line in enumerate(lines, start=1):
        if phase and phase.should_skip():
            break
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        ts, stream_id, ctype, clen, body = parts[:5]
        if isinstance(body, str):
            data_bytes = body.encode("utf-8", "surrogateescape")
        else:
            data_bytes = body
        h = hashlib.sha256(data_bytes).hexdigest()
        fname = f"stream{stream_id}_{h[:10]}.bin"
        fpath = pathlib.Path(out_dir) / fname
        try:
            fpath.write_bytes(data_bytes)
        except OSError as e:
            logger.warning("Failed to write carved file %s: %s", fpath, e)
            continue
        results.append(
            {
                "time": ts,
                "tcp_stream": stream_id,
                "content_type": ctype,
                "content_length": clen,
                "sha256": h,
                "path": str(fpath),
            }
        )
        if phase and total:
            pct = 10 + int((i / total) * 80)
            phase.set(pct, f"Carved {i}/{total}")
    if phase:
        if phase.should_skip():
            phase.done("HTTP carving skipped.")
        else:
            phase.done(f"Carved {len(results)} bodies.")
    return results
