import os
import re
from datetime import datetime
from typing import Dict, List, Optional

from .config_cripto import ENCRYPTION_METHOD, ENCRYPTION_ENABLED

CSV_PATH = None
CSV_INITIALIZED = False
ROUND_CRYPTO_TIME = 0.0
ROUND_SUMMARIES: List[Dict[str, float]] = []
REPORT_REQUESTED = False
REPORT_GENERATED = False

def init_csv():
    global CSV_PATH, CSV_INITIALIZED
    if CSV_INITIALIZED:
        return CSV_PATH
    base_name = f"serialization_times_{ENCRYPTION_METHOD}.csv" if ENCRYPTION_ENABLED else "serialization_times_noCritto.csv"
    CSV_PATH = base_name

    # Sovrascrive se esiste già
    with open(CSV_PATH, mode="w", encoding="utf-8") as f:
        header_msg = f"Encryption enabled: {ENCRYPTION_METHOD}" if ENCRYPTION_ENABLED else "Encryption disabled"
        print(header_msg, flush=True)
        f.write(header_msg + "\n")

    CSV_INITIALIZED = True
    return CSV_PATH

def log_time(msg: str, *args) -> None:
    """
    Scrive il messaggio su console e su CSV.
    Può usare:
      - placeholder stile % -> msg % args
      - placeholder stile {} -> msg.format(*args)
      - oppure msg + args concatenati se non sono placeholder validi
    """
    csv_path = init_csv()  # crea il file solo alla prima chiamata

    if args:
        # 1) prova stile printf: "valore: %.2f" % 1.23
        try:
            output = msg % args
        except (TypeError, ValueError):
            # 2) prova stile format: "valore: {:.2f}".format(1.23)
            try:
                output = msg.format(*args)
            except Exception:
                # 3) fallback: concatena tutto
                output = " ".join([msg, *[str(a) for a in args]])
    else:
        output = msg

    print(output, flush=True)

    try:
        with open(csv_path, mode="a", encoding="utf-8") as f:
            f.write(output + "\n")
    except Exception as e:
        print(f"[log_time ERROR] Non è stato possibile scrivere su {csv_path}: {e}", flush=True)

def reset_round_timing() -> None:
    global ROUND_CRYPTO_TIME
    ROUND_CRYPTO_TIME = 0.0

def add_crypto_time(duration: float) -> None:
    global ROUND_CRYPTO_TIME
    ROUND_CRYPTO_TIME += duration

def finalize_round_timing(
    round_number: int,
    round_elapsed: float,
    *,
    accuracy_centralized: Optional[float] = None,
    accuracy_federated: Optional[float] = None,
) -> Dict[str, float]:
    without_crypto = max(round_elapsed - ROUND_CRYPTO_TIME, 0.0)
    summary = {
        "round": float(round_number),
        "round_time": round_elapsed,
        "crypto_time": ROUND_CRYPTO_TIME,
        "without_crypto": without_crypto,
    }
    if accuracy_centralized is not None:
        summary["accuracy_centralized"] = accuracy_centralized
    if accuracy_federated is not None:
        summary["accuracy_federated"] = accuracy_federated
    ROUND_SUMMARIES.append(summary)
    return summary

def request_report_generation() -> None:
    global REPORT_REQUESTED
    REPORT_REQUESTED = True

def is_report_requested() -> bool:
    return REPORT_REQUESTED

def is_report_generated() -> bool:
    return REPORT_GENERATED

def _escape_pdf_text(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

def _extract_accuracy_from_csv() -> Dict[int, Dict[str, float]]:
    accuracies: Dict[int, Dict[str, float]] = {}
    if not CSV_PATH or not os.path.exists(CSV_PATH):
        return accuracies
    pattern = re.compile(
        r"Round\s+(?P<round>\d+)\s+Accuracy\s+\((?P<kind>centralized|federated)\):\s+"
        r"(?P<value>[-+]?[\d.]+(?:e[-+]?\d+)?)",
        re.IGNORECASE,
    )
    with open(CSV_PATH, "r", encoding="utf-8") as csv_file:
        for line in csv_file:
            match = pattern.search(line)
            if not match:
                continue
            round_id = int(match.group("round"))
            kind = match.group("kind").lower()
            value = float(match.group("value"))
            entry = accuracies.setdefault(round_id, {})
            entry[kind] = value
    return accuracies

def _build_report_lines() -> List[str]:
    if not ROUND_SUMMARIES:
        return ["Nessun dato di round disponibile."]
    total_time = sum(item["round_time"] for item in ROUND_SUMMARIES)
    total_crypto = sum(item["crypto_time"] for item in ROUND_SUMMARIES)
    total_without = sum(item["without_crypto"] for item in ROUND_SUMMARIES)
    total_impact = (total_crypto / total_time * 100.0) if total_time > 0 else 0.0
    encryption_info = (
        f"Crittografia: {ENCRYPTION_METHOD}"
        if ENCRYPTION_ENABLED
        else "Crittografia: disabilitata"
    )
    accuracy_map = _extract_accuracy_from_csv()
    lines = [
        "Report risultati crittografia",
        encryption_info,
        f"Round totali: {len(ROUND_SUMMARIES)}",
        (
            "Tempo totale: "
            f"{total_time:.2f}s | critto={total_crypto:.2f}s "
            f"| senza_critto={total_without:.2f}s | impatto={total_impact:.1f}%"
        ),
        f"Generato: {datetime.now().isoformat(timespec='seconds')}",
        "Dettaglio round:",
    ]
    for item in ROUND_SUMMARIES:
        impact = (
            item["crypto_time"] / item["round_time"] * 100.0
            if item["round_time"] > 0
            else 0.0
        )
        line = (
            f"- Round {int(item['round'])}: totale={item['round_time']:.2f}s "
            f"| critto={item['crypto_time']:.2f}s "
            f"| senza_critto={item['without_crypto']:.2f}s "
            f"| impatto={impact:.1f}%"
        )
        accuracy_parts = []
        if "accuracy_centralized" in item:
            accuracy_parts.append(f"acc_cen={item['accuracy_centralized']:.4f}")
        if "accuracy_federated" in item:
            accuracy_parts.append(f"acc_fed={item['accuracy_federated']:.4f}")
        csv_accuracy = accuracy_map.get(int(item["round"]), {})
        if "centralized" in csv_accuracy and "accuracy_centralized" not in item:
            accuracy_parts.append(f"acc_cen={csv_accuracy['centralized']:.4f}")
        if "federated" in csv_accuracy and "accuracy_federated" not in item:
            accuracy_parts.append(f"acc_fed={csv_accuracy['federated']:.4f}")
        if accuracy_parts:
            line = f"{line} | " + " ".join(accuracy_parts)
        lines.append(line)
    return lines

def _write_simple_pdf(path: str, lines: List[str]) -> None:
    content_lines = []
    content_lines.append("BT")
    content_lines.append("/F1 12 Tf")
    content_lines.append("72 720 Td")
    for idx, line in enumerate(lines):
        if idx > 0:
            content_lines.append("T*")
        content_lines.append(f"({_escape_pdf_text(line)}) Tj")
    content_lines.append("ET")
    content_stream = "\n".join(content_lines).encode("latin-1")

    objects = []
    objects.append(b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj")
    objects.append(b"2 0 obj << /Type /Pages /Count 1 /Kids [3 0 R] >> endobj")
    objects.append(
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj"
    )
    objects.append(b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj")
    objects.append(
        b"5 0 obj << /Length "
        + str(len(content_stream)).encode("ascii")
        + b" >> stream\n"
        + content_stream
        + b"\nendstream endobj"
    )

    xref_offsets = []
    pdf_parts = [b"%PDF-1.4\n"]
    for obj in objects:
        xref_offsets.append(sum(len(part) for part in pdf_parts))
        pdf_parts.append(obj + b"\n")

    xref_start = sum(len(part) for part in pdf_parts)
    xref_entries = [b"0000000000 65535 f \n"]
    for offset in xref_offsets:
        xref_entries.append(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf_parts.append(b"xref\n0 6\n" + b"".join(xref_entries))
    pdf_parts.append(b"trailer << /Size 6 /Root 1 0 R >>\n")
    pdf_parts.append(f"startxref\n{xref_start}\n%%EOF\n".encode("ascii"))

    with open(path, "wb") as pdf_file:
        pdf_file.write(b"".join(pdf_parts))

def generate_report_pdf(path: str = "crypto_report.pdf") -> str:
    global REPORT_GENERATED
    if REPORT_GENERATED:
        return path
    lines = _build_report_lines()
    generate_report_txt("crypto_report.txt")
    _write_simple_pdf(path, lines)
    REPORT_GENERATED = True
    return path

def generate_report_txt(path: str = "crypto_report.txt") -> str:
    """Generate a human-readable text report for crypto/timing results."""
    global REPORT_GENERATED
    if REPORT_GENERATED:
        return path
    lines = _build_report_lines()
    with open(path, "w", encoding="utf-8") as txt_file:
        txt_file.write("\n".join(lines))
    REPORT_GENERATED = True
    return path
