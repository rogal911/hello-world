# hello-world

#!/usr/bin/env python3
"""
trace_analyzer.py
==================

Analizuje logi tekstowe (jeden plik = jeden serwis) i dla kazdego TraceID,
ktory pojawil sie w logu experience-api, sledzi jego pelna sciezke przez
wszystkie pozostale serwisy oraz liczy czas wykonania (total + per-serwis).

UWAGA: Skrypt zawiera DOMYSLNE wzorce (regex) dopasowane do typowego
formatu Logback/Log4j. Bardzo prawdopodobnie trzeba je dostosowac do
realnego formatu logow - patrz sekcja KONFIGURACJA nizej.

Uzycie:
    python trace_analyzer.py --config config.json
    lub bez configu, edytujac SERVICE_FILES nizej w kodzie.

Wynik:
    - traces.csv          -> jedna linia = jeden TraceID (podsumowanie)
    - traces_detail.csv    -> jedna linia = jedno (TraceID, serwis) - per-serwis czasy
"""

import re
import csv
import sys
import argparse
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# ============================================================
# KONFIGURACJA - DOSTOSUJ DO SWOICH LOGOW
# ============================================================

# Mapowanie: nazwa_serwisu -> sciezka do pliku logu
# Nazwa "experience-api" MUSI byc taka, jak ustawiona w EXPERIENCE_API_NAME
SERVICE_FILES = {
    "experience-api": "/path/to/experience-api.log",
    "auth-service": "/path/to/auth-service.log",
    "user-service": "/path/to/user-service.log",
    # dodaj kolejne serwisy tutaj
}

EXPERIENCE_API_NAME = "experience-api"

# --- Wzorzec timestampu na poczatku linii ---
# Realny format SC: "2026-06-18T08:32:49.421Z DEBUG 135083 --- [eapi-ov-vault] ..."
TIMESTAMP_REGEX = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[.,]\d{3})Z"
)
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S.%f"  # uzyte po normalizacji separatorow

# --- Wzorce do wyciagania TraceID z linii ---
# Realny format SC: trzeci nawias kwadratowy = [traceId-spanId], traceId = 32 znaki hex
# np. [https-jsse-nio-9508-exec-2] [6a33ad3175af6bdd1096bc6daeb76d30-1096bc6daeb76d30]
# Dodatkowo czasem wystepuje jawny zapis "trace ID = XXXX" (bez spanId) - lapiemy to jako fallback.
TRACE_ID_PATTERNS = [
    # [32hex-32hex] albo [32hex-cokolwiek] - bierzemy tylko czesc przed myslnikiem
    re.compile(r"\[([a-fA-F0-9]{32})-[a-fA-F0-9]+\]"),
    # jawny zapis: trace ID = XXXX / traceId=XXXX / traceId: XXXX
    re.compile(r"[Tt]race[ _]?[Ii][Dd]\s*[=:]\s*([a-fA-F0-9]{32})"),
    # fallback: ogolny traceId=XXX / traceId: XXX (mniej rygorystyczna dlugosc)
    re.compile(r"traceId[=:]\s*([a-fA-F0-9\-]{8,})"),
    re.compile(r"trace_id[=:]\s*([a-fA-F0-9\-]{8,})"),
    re.compile(r"X-Trace-Id[=:]\s*([a-fA-F0-9\-]{8,})", re.IGNORECASE),
]

# Czy linie bez TraceID maja byc ignorowane (True) czy zglaszane jako blad (False)
IGNORE_LINES_WITHOUT_TRACE = True

# ============================================================
# KONIEC KONFIGURACJI
# ============================================================


def normalize_timestamp(ts: str) -> str:
    """Zamienia 'T' i ',' na spacje/punkt zgodnie z TIMESTAMP_FORMAT."""
    return ts.replace("T", " ").replace(",", ".")


def extract_trace_id(line: str):
    for pattern in TRACE_ID_PATTERNS:
        m = pattern.search(line)
        if m:
            return m.group(1)
    return None


def parse_log_file(service_name: str, filepath: str):
    """
    Parsuje jeden plik logu.
    Zwraca liste rekordow: dict(trace_id, service, timestamp: datetime, raw_line)
    """
    records = []
    path = Path(filepath)
    if not path.exists():
        print(f"[OSTRZEZENIE] Plik nie istnieje: {filepath} (serwis: {service_name})", file=sys.stderr)
        return records

    last_ts = None  # do obslugi linii kontynuacji (np. stack trace bez timestampu)

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, start=1):
            ts_match = TIMESTAMP_REGEX.match(line)
            if ts_match:
                ts_raw = normalize_timestamp(ts_match.group("ts"))
                try:
                    last_ts = datetime.strptime(ts_raw, TIMESTAMP_FORMAT)
                except ValueError:
                    # np. brak milisekund - fallback bez .%f
                    try:
                        last_ts = datetime.strptime(ts_raw.split(".")[0], "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        pass

            trace_id = extract_trace_id(line)
            if trace_id is None:
                if not IGNORE_LINES_WITHOUT_TRACE:
                    print(f"[INFO] Brak traceId w {filepath}:{lineno}", file=sys.stderr)
                continue

            if last_ts is None:
                # Linia z traceId ale bez timestampu w tej linii i bez wczesniejszego - pomijamy
                continue

            records.append({
                "trace_id": trace_id,
                "service": service_name,
                "timestamp": last_ts,
                "lineno": lineno,
                "raw_line": line.rstrip("\n"),
            })

    return records


def build_trace_map(all_records):
    """
    Grupuje rekordy po trace_id.
    Zwraca dict: trace_id -> list rekordow (sortowane chronologicznie)
    """
    trace_map = defaultdict(list)
    for rec in all_records:
        trace_map[rec["trace_id"]].append(rec)

    for trace_id in trace_map:
        trace_map[trace_id].sort(key=lambda r: r["timestamp"])

    return trace_map


def compute_service_durations(records_for_trace):
    """
    Dla listy rekordow jednego trace'a (sortowanej chronologicznie),
    oblicza:
      - per-service: pierwsze i ostatnie wystapienie, czas trwania w danym serwisie
      - kolejnosc odwiedzonych serwisow (sciezka, z deduplikacja kolejnych powtorzen)
      - total_duration = ostatni timestamp - pierwszy timestamp (w sekundach)
    """
    by_service = defaultdict(list)
    for rec in records_for_trace:
        by_service[rec["service"]].append(rec["timestamp"])

    service_stats = {}
    for service, timestamps in by_service.items():
        first_ts = min(timestamps)
        last_ts = max(timestamps)
        duration = (last_ts - first_ts).total_seconds()
        service_stats[service] = {
            "first_seen": first_ts,
            "last_seen": last_ts,
            "duration_sec": duration,
            "log_lines": len(timestamps),
        }

    # Sciezka = kolejnosc serwisow wg pierwszego wystapienia (chronologicznie)
    path_order = sorted(service_stats.items(), key=lambda kv: kv[1]["first_seen"])
    path_str = " -> ".join(s for s, _ in path_order)

    all_ts = [r["timestamp"] for r in records_for_trace]
    total_start = min(all_ts)
    total_end = max(all_ts)
    total_duration = (total_end - total_start).total_seconds()

    return {
        "path": path_str,
        "service_stats": service_stats,
        "total_start": total_start,
        "total_end": total_end,
        "total_duration_sec": total_duration,
    }


def main():
    parser = argparse.ArgumentParser(description="Analiza TraceID przez logi wielu serwisow")
    parser.add_argument("--config", help="Plik JSON z mapowaniem serwis -> plik logu (opcjonalnie)")
    parser.add_argument("--out-summary", default="traces.csv", help="Plik wynikowy - podsumowanie per TraceID")
    parser.add_argument("--out-detail", default="traces_detail.csv", help="Plik wynikowy - detale per (TraceID, serwis)")
    args = parser.parse_args()

    service_files = SERVICE_FILES
    if args.config:
        with open(args.config, "r", encoding="utf-8") as f:
            service_files = json.load(f)

    # 1. Parsowanie wszystkich plikow
    all_records = []
    for service_name, filepath in service_files.items():
        recs = parse_log_file(service_name, filepath)
        print(f"[INFO] {service_name}: znaleziono {len(recs)} linii z traceId w {filepath}")
        all_records.extend(recs)

    if not all_records:
        print("[BLAD] Nie znaleziono zadnych rekordow z traceId. Sprawdz konfiguracje regexow.", file=sys.stderr)
        sys.exit(1)

    # 2. Grupowanie po trace_id
    trace_map = build_trace_map(all_records)

    # 3. Filtrowanie: tylko trace_id, ktore wystapily w experience-api
    exp_api_trace_ids = {
        rec["trace_id"] for rec in all_records if rec["service"] == EXPERIENCE_API_NAME
    }
    print(f"[INFO] TraceID znalezionych w {EXPERIENCE_API_NAME}: {len(exp_api_trace_ids)}")

    relevant_trace_ids = [tid for tid in trace_map if tid in exp_api_trace_ids]

    # 4. Liczenie czasow i budowanie wynikow
    summary_rows = []
    detail_rows = []

    for trace_id in relevant_trace_ids:
        records_for_trace = trace_map[trace_id]
        stats = compute_service_durations(records_for_trace)

        only_experience_api = set(stats["service_stats"].keys()) == {EXPERIENCE_API_NAME}

        summary_rows.append({
            "trace_id": trace_id,
            "path": stats["path"],
            "num_services": len(stats["service_stats"]),
            "start_time": stats["total_start"].isoformat(sep=" ", timespec="milliseconds"),
            "end_time": stats["total_end"].isoformat(sep=" ", timespec="milliseconds"),
            "total_duration_sec": round(stats["total_duration_sec"], 3),
            "only_experience_api": only_experience_api,
        })

        for service, s in stats["service_stats"].items():
            detail_rows.append({
                "trace_id": trace_id,
                "service": service,
                "first_seen": s["first_seen"].isoformat(sep=" ", timespec="milliseconds"),
                "last_seen": s["last_seen"].isoformat(sep=" ", timespec="milliseconds"),
                "duration_sec": round(s["duration_sec"], 3),
                "log_lines": s["log_lines"],
            })

    # 5. Sortowanie wynikow - od najdluzszych total_duration
    summary_rows.sort(key=lambda r: r["total_duration_sec"], reverse=True)

    # 6. Zapis do CSV
    with open(args.out_summary, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "trace_id", "path", "num_services", "start_time", "end_time", "total_duration_sec", "only_experience_api"
        ])
        writer.writeheader()
        writer.writerows(summary_rows)

    with open(args.out_detail, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "trace_id", "service", "first_seen", "last_seen", "duration_sec", "log_lines"
        ])
        writer.writeheader()
        writer.writerows(detail_rows)

    print(f"\n[OK] Zapisano podsumowanie: {args.out_summary} ({len(summary_rows)} trace'ow)")
    print(f"[OK] Zapisano detale:        {args.out_detail} ({len(detail_rows)} wierszy)")

    # 7. Krotkie statystyki na konsoli
    if summary_rows:
        durations = [r["total_duration_sec"] for r in summary_rows]
        durations.sort()
        n = len(durations)
        print("\n--- Statystyki total_duration_sec ---")
        print(f"min:    {durations[0]:.3f}s")
        print(f"max:    {durations[-1]:.3f}s")
        print(f"median: {durations[n // 2]:.3f}s")
        print(f"avg:    {sum(durations)/n:.3f}s")


if __name__ == "__main__":
    main()

