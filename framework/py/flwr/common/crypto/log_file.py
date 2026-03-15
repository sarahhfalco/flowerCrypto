import os
import ssl
from typing import List, Dict

from .config_cripto import ENCRYPTION_METHOD, ENCRYPTION_ENABLED, TLS, TLS_CIPHER_SUITES

CSV_PATH = None
CSV_INITIALIZED = False
TOTAL_CRYPTO_TIME = 0.0
TOTAL_ENCRYPT_TIME = 0.0
TOTAL_DECRYPT_TIME = 0.0
TOTAL_SERIAL_TIME = 0.0
TOTAL_AUTH_TIME = 0.0
TOTAL_AUTH_SIGN_TIME = 0.0
TOTAL_AUTH_VERIFY_TIME = 0.0
TOTAL_INTEGRITY_TIME = 0.0
TOTAL_OVERHEAD_BYTES = 0
TOTAL_PLAINTEXT_BYTES = 0
TOTAL_TRANSPORT_BASE_BYTES = 0
TOTAL_TRANSPORT_MSG_COUNT = 0
OVERHEAD_BY_METHOD: Dict[str, int] = {}
OVERHEAD_COUNT_BY_METHOD: Dict[str, int] = {}
OVERHEAD_BY_CATEGORY: Dict[str, int] = {}
OVERHEAD_COUNT_BY_CATEGORY: Dict[str, int] = {}


def reset_crypto_totals() -> None:
    """Reset accumulated crypto/serialization totals."""
    global TOTAL_CRYPTO_TIME, TOTAL_ENCRYPT_TIME, TOTAL_DECRYPT_TIME
    global TOTAL_SERIAL_TIME, TOTAL_AUTH_TIME
    global TOTAL_AUTH_SIGN_TIME, TOTAL_AUTH_VERIFY_TIME
    global TOTAL_INTEGRITY_TIME
    global TOTAL_OVERHEAD_BYTES, TOTAL_PLAINTEXT_BYTES
    global OVERHEAD_BY_METHOD, OVERHEAD_COUNT_BY_METHOD
    global OVERHEAD_BY_CATEGORY, OVERHEAD_COUNT_BY_CATEGORY
    TOTAL_CRYPTO_TIME = 0.0
    TOTAL_ENCRYPT_TIME = 0.0
    TOTAL_DECRYPT_TIME = 0.0
    TOTAL_SERIAL_TIME = 0.0
    TOTAL_AUTH_TIME = 0.0
    TOTAL_AUTH_SIGN_TIME = 0.0
    TOTAL_AUTH_VERIFY_TIME = 0.0
    TOTAL_INTEGRITY_TIME = 0.0
    TOTAL_OVERHEAD_BYTES = 0
    TOTAL_PLAINTEXT_BYTES = 0
    TOTAL_TRANSPORT_BASE_BYTES = 0
    TOTAL_TRANSPORT_MSG_COUNT = 0
    OVERHEAD_BY_METHOD = {}
    OVERHEAD_COUNT_BY_METHOD = {}
    OVERHEAD_BY_CATEGORY = {}
    OVERHEAD_COUNT_BY_CATEGORY = {}


def add_crypto_time(crypto_time: float, serial_time: float) -> None:
    """Accumulate crypto and serialization time for summary reporting."""
    global TOTAL_CRYPTO_TIME, TOTAL_SERIAL_TIME
    TOTAL_CRYPTO_TIME += crypto_time
    TOTAL_SERIAL_TIME += serial_time


def add_encrypt_decrypt_time(encrypt_time: float, decrypt_time: float) -> None:
    """Accumulate encryption/decryption time for summary reporting."""
    global TOTAL_ENCRYPT_TIME, TOTAL_DECRYPT_TIME
    TOTAL_ENCRYPT_TIME += encrypt_time
    TOTAL_DECRYPT_TIME += decrypt_time


def add_auth_time(auth_time: float) -> None:
    """Accumulate authentication time for summary reporting."""
    global TOTAL_AUTH_TIME
    TOTAL_AUTH_TIME += auth_time


def add_auth_sign_verify_time(sign_time: float, verify_time: float) -> None:
    """Accumulate authentication sign/verify times for summary reporting."""
    global TOTAL_AUTH_SIGN_TIME, TOTAL_AUTH_VERIFY_TIME
    TOTAL_AUTH_SIGN_TIME += sign_time
    TOTAL_AUTH_VERIFY_TIME += verify_time




def add_integrity_time(integrity_time: float) -> None:
    """Accumulate integrity time for summary reporting."""
    global TOTAL_INTEGRITY_TIME
    TOTAL_INTEGRITY_TIME += integrity_time

def get_crypto_totals() -> tuple[float, float]:
    """Return accumulated crypto and serialization totals."""
    return TOTAL_CRYPTO_TIME, TOTAL_SERIAL_TIME


def get_encrypt_decrypt_totals() -> tuple[float, float]:
    """Return accumulated encryption and decryption totals."""
    return TOTAL_ENCRYPT_TIME, TOTAL_DECRYPT_TIME




def get_integrity_totals() -> float:
    """Return accumulated integrity totals."""
    return TOTAL_INTEGRITY_TIME

def get_auth_totals() -> float:
    """Return accumulated authentication totals."""
    return TOTAL_AUTH_TIME


def get_auth_sign_verify_totals() -> tuple[float, float]:
    """Return accumulated authentication sign/verify totals."""
    return TOTAL_AUTH_SIGN_TIME, TOTAL_AUTH_VERIFY_TIME


def add_transport_message(base_bytes: int) -> None:
    """Accumulate transport-level message stats for TLS overhead estimation."""
    global TOTAL_TRANSPORT_BASE_BYTES, TOTAL_TRANSPORT_MSG_COUNT
    TOTAL_TRANSPORT_BASE_BYTES += max(base_bytes, 0)
    TOTAL_TRANSPORT_MSG_COUNT += 1


def _tls_record_overhead_bytes(cipher_suite: str) -> int:
    """Estimated per-record TLS overhead (header+auth tag/nonce), in bytes."""
    suite = cipher_suite.upper()
    # TLS 1.3 AEAD records: 5-byte header + 16-byte tag + 1-byte inner type
    if "TLS_AES_" in suite or "TLS_CHACHA20_" in suite:
        return 22
    # TLS 1.2 GCM: 5-byte header + 8-byte explicit nonce + 16-byte tag
    if "GCM" in suite:
        return 29
    # TLS 1.2 CBC/HMAC (approximate, depends on MAC/padding)
    return 45


def _get_tls_cipher_suites() -> list[str]:
    configured_env = os.getenv("GRPC_SSL_CIPHER_SUITES", "").strip()
    configured = configured_env or (TLS_CIPHER_SUITES or "").strip()
    if configured:
        return [item.strip() for item in configured.split(":") if item.strip()]
    return ["default(grpc-openssl)"]


def _get_default_openssl_cipher_candidates(limit: int = 10) -> list[str]:
    """Return a best-effort list of default OpenSSL cipher candidates."""
    try:
        context = ssl.create_default_context()
        ciphers = context.get_ciphers()
        names: list[str] = []
        for cipher in ciphers:
            name = cipher.get("name")
            if name and name not in names:
                names.append(name)
            if len(names) >= limit:
                break
        return names
    except Exception:
        return []


def build_tls_report() -> List[str]:
    """Build TLS/cipher-suite report and estimated TLS overhead."""
    if not TLS:
        return ["TLS overhead: TLS disabilitato (nessun overhead TLS stimato)."]

    suites = _get_tls_cipher_suites()
    suites_display = ", ".join(suites)
    reference_suite = suites[0]
    per_record = _tls_record_overhead_bytes(reference_suite)

    total_tls_overhead = TOTAL_TRANSPORT_MSG_COUNT * per_record
    impact = (
        (total_tls_overhead / TOTAL_TRANSPORT_BASE_BYTES * 100.0)
        if TOTAL_TRANSPORT_BASE_BYTES > 0
        else 0.0
    )

    lines = [
        f"TLS attivo: sì | Cipher suite(s): {suites_display}",
        (
            "Overhead TLS stimato: "
            f"{total_tls_overhead} B su {TOTAL_TRANSPORT_BASE_BYTES} B "
            f"({impact:.2f}%) | medio={per_record} B/msg "
            f"(stima per record da suite: {reference_suite})"
        ),
    ]

    if reference_suite == "default(grpc-openssl)":
        candidates = _get_default_openssl_cipher_candidates(limit=10)
        if candidates:
            lines.append(
                "Suite possibili con default OpenSSL (non necessariamente negoziata): "
                + ", ".join(candidates)
            )
        lines.append(
            "Nota: gRPC Python non espone facilmente la cipher suite realmente negoziata; "
            "per conoscerla con certezza imposta GRPC_SSL_CIPHER_SUITES esplicitamente."
        )

    lines.append(f"OpenSSL runtime: {ssl.OPENSSL_VERSION}")
    return lines


def add_overhead(
    method: str,
    category: str,
    added_bytes: int,
    base_bytes: int,
) -> None:
    """Accumulate overhead bytes per method and total payload size."""
    global TOTAL_OVERHEAD_BYTES, TOTAL_PLAINTEXT_BYTES
    global OVERHEAD_BY_METHOD, OVERHEAD_COUNT_BY_METHOD
    global OVERHEAD_BY_CATEGORY, OVERHEAD_COUNT_BY_CATEGORY
    TOTAL_OVERHEAD_BYTES += added_bytes
    TOTAL_PLAINTEXT_BYTES += base_bytes
    OVERHEAD_BY_METHOD[method] = OVERHEAD_BY_METHOD.get(method, 0) + added_bytes
    OVERHEAD_COUNT_BY_METHOD[method] = OVERHEAD_COUNT_BY_METHOD.get(method, 0) + 1
    OVERHEAD_BY_CATEGORY[category] = OVERHEAD_BY_CATEGORY.get(category, 0) + added_bytes
    OVERHEAD_COUNT_BY_CATEGORY[category] = (
        OVERHEAD_COUNT_BY_CATEGORY.get(category, 0) + 1
    )


def get_overhead_totals() -> tuple[int, int]:
    """Return total overhead and plaintext bytes."""
    return TOTAL_OVERHEAD_BYTES, TOTAL_PLAINTEXT_BYTES


def build_overhead_report() -> List[str]:
    lines = []
    if not OVERHEAD_BY_METHOD:
        lines.append("Nessun dato di overhead disponibile.")
        lines.extend(build_tls_report())
        return lines

    total_overhead, total_plaintext = get_overhead_totals()
    total_impact = (
        (total_overhead / total_plaintext * 100.0)
        if total_plaintext > 0
        else 0.0
    )
    lines.append(
        "Overhead totale: {overhead} B su {base} B ({impact:.2f}%)".format(
            overhead=total_overhead,
            base=total_plaintext,
            impact=total_impact,
        )
    )
    for method, added in sorted(OVERHEAD_BY_METHOD.items()):
        count = OVERHEAD_COUNT_BY_METHOD.get(method, 0)
        avg = (added / count) if count > 0 else 0.0
        impact = (added / total_plaintext * 100.0) if total_plaintext > 0 else 0.0
        lines.append(
            "Overhead {method}: {added} B ({impact:.2f}%) | medio={avg:.2f} B/msg".format(
                method=method,
                added=added,
                impact=impact,
                avg=avg,
            )
        )
    for category, added in sorted(OVERHEAD_BY_CATEGORY.items()):
        count = OVERHEAD_COUNT_BY_CATEGORY.get(category, 0)
        avg = (added / count) if count > 0 else 0.0
        lines.append(
            "Overhead medio {category}: {avg:.2f} B/msg".format(
                category=category,
                avg=avg,
            )
        )
    lines.extend(build_tls_report())
    return lines

ROUND_SUMMARIES: List[Dict[str, float]] = []


def init_csv():
    global CSV_PATH, CSV_INITIALIZED
    if CSV_INITIALIZED:
        return CSV_PATH

    base_name = (
        f"serialization_times_{ENCRYPTION_METHOD}.csv"
        if ENCRYPTION_ENABLED
        else "serialization_times_noCritto.csv"
    )
    CSV_PATH = base_name

    with open(CSV_PATH, mode="w", encoding="utf-8") as f:
        header_msg = (
            f"Encryption enabled: {ENCRYPTION_METHOD}"
            if ENCRYPTION_ENABLED
            else "Encryption disabled"
        )
        print(header_msg, flush=True)
        f.write(header_msg + "\n")

    CSV_INITIALIZED = True
    return CSV_PATH


def log_time(msg: str, *args) -> None:
    csv_path = init_csv()

    if args:
        try:
            output = msg % args
        except (TypeError, ValueError):
            try:
                output = msg.format(*args)
            except Exception:
                output = " ".join([msg, *[str(a) for a in args]])
    else:
        output = msg

    print(output, flush=True)

    try:
        with open(csv_path, mode="a", encoding="utf-8") as f:
            f.write(output + "\n")
    except Exception as e:
        print(f"[log_time ERROR] Scrittura CSV fallita: {e}", flush=True)


def get_round_summaries() -> List[Dict[str, float]]:
    return list(ROUND_SUMMARIES)


def build_round_time_report() -> List[str]:
    if not ROUND_SUMMARIES:
        return ["Nessun dato di round disponibile."]

    lines = []
    total_round_time = 0.0
    total_crypto_time = 0.0
    total_auth_time = 0.0
    total_integrity_time = 0.0
    total_auth_sign_time = 0.0
    total_auth_verify_time = 0.0
    total_crypto_cumulative = 0.0
    total_auth_cumulative = 0.0

    for summary in ROUND_SUMMARIES:
        round_time = summary["round_time"]
        crypto_time = summary["crypto_time"]
        encrypt_time = summary.get("encrypt_time", 0.0)
        decrypt_time = summary.get("decrypt_time", 0.0)
        without_crypto = summary["without_crypto"]
        auth_time = summary.get("auth_time", 0.0)
        integrity_time = summary.get("integrity_time", 0.0)
        auth_sign_time = summary.get("auth_sign_time", 0.0)
        auth_verify_time = summary.get("auth_verify_time", 0.0)
        crypto_cumulative = summary.get("crypto_cumulative", crypto_time)
        auth_cumulative = summary.get("auth_cumulative", auth_time)
        parallel_factor = summary.get("parallel_factor")
        parallel_fit = summary.get("parallel_fit")
        parallel_eval = summary.get("parallel_eval")

        impact = (crypto_time / round_time * 100.0) if round_time > 0 else 0.0
        auth_impact = (auth_time / round_time * 100.0) if round_time > 0 else 0.0

        parallel_note_parts = []
        if parallel_factor is not None:
            parallel_note_parts.append(f"parallel_factor={parallel_factor:.0f}")
        if parallel_fit is not None:
            parallel_note_parts.append(f"parallel_fit={parallel_fit:.0f}")
        if parallel_eval is not None:
            parallel_note_parts.append(f"parallel_eval={parallel_eval:.0f}")
        parallel_note = f" | {' | '.join(parallel_note_parts)}" if parallel_note_parts else ""

        lines.append(
            "Round {round_num}: totale={round_time:.2f}s | "
            "crypto={crypto_time:.2f}s ({impact:.2f}%) | "
            "encrypt={encrypt_time:.2f}s | decrypt={decrypt_time:.2f}s | integrity={integrity_time:.2f}s | "
            "auth={auth_time:.2f}s ({auth_impact:.2f}%) | "
            "firma={auth_sign_time:.2f}s | verifica={auth_verify_time:.2f}s | "
            "crypto_cum={crypto_cumulative:.2f}s | auth_cum={auth_cumulative:.2f}s | "
            "senza_critto={without_crypto:.2f}s{parallel_note}".format(
                round_num=int(summary["round"]),
                round_time=round_time,
                crypto_time=crypto_time,
                impact=impact,
                encrypt_time=encrypt_time,
                decrypt_time=decrypt_time,
                integrity_time=integrity_time,
                auth_time=auth_time,
                auth_impact=auth_impact,
                auth_sign_time=auth_sign_time,
                auth_verify_time=auth_verify_time,
                crypto_cumulative=crypto_cumulative,
                auth_cumulative=auth_cumulative,
                without_crypto=without_crypto,
                parallel_note=parallel_note,
            )
        )

        total_round_time += round_time
        total_crypto_time += crypto_time
        total_auth_time += auth_time
        total_integrity_time += integrity_time
        total_auth_sign_time += auth_sign_time
        total_auth_verify_time += auth_verify_time
        total_crypto_cumulative += crypto_cumulative
        total_auth_cumulative += auth_cumulative

    total_impact = (
        (total_crypto_time / total_round_time * 100.0)
        if total_round_time > 0
        else 0.0
    )
    total_auth_impact = (
        (total_auth_time / total_round_time * 100.0)
        if total_round_time > 0
        else 0.0
    )

    lines.append(
        "Totale critto (parallel): {total_crypto:.2f}s su {total_round:.2f}s ({impact:.2f}%)".format(
            total_crypto=total_crypto_time,
            total_round=total_round_time,
            impact=total_impact,
        )
    )
    lines.append(
        "Totale integrity (parallel): {total_integrity:.2f}s".format(
            total_integrity=total_integrity_time,
        )
    )
    lines.append(
        "Totale auth (parallel): {total_auth:.2f}s su {total_round:.2f}s ({impact:.2f}%)".format(
            total_auth=total_auth_time,
            total_round=total_round_time,
            impact=total_auth_impact,
        )
    )
    lines.append(
        "Totale firma (parallel): {total_sign:.2f}s | totale verifica (parallel): {total_verify:.2f}s".format(
            total_sign=total_auth_sign_time,
            total_verify=total_auth_verify_time,
        )
    )
    if total_crypto_cumulative != total_crypto_time:
        lines.append(
            "Totale critto cumulativo: {total_crypto:.2f}s".format(
                total_crypto=total_crypto_cumulative
            )
        )
    if total_auth_cumulative != total_auth_time:
        lines.append(
            "Totale auth cumulativo: {total_auth:.2f}s".format(
                total_auth=total_auth_cumulative
            )
        )

    return lines
