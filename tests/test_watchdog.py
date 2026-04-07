from pathlib import Path

from watchdog import load_ips_from_csv


def test_load_ips_from_csv_reads_valid_ips(tmp_path: Path):
    csv_file = tmp_path / "input_data.csv"
    csv_file.write_text("ips\n8.8.8.8\n1.1.1.1\n", encoding="utf-8")

    ips = load_ips_from_csv(str(csv_file), column_name="ip_address")

    assert ips == ["8.8.8.8", "1.1.1.1"]


def test_load_ips_from_csv_skips_invalid_ips(tmp_path: Path):
    csv_file = tmp_path / "input_data.csv"
    csv_file.write_text("ips\n8.8.8.8\nnot_an_ip\n1.1.1.1\n", encoding="utf-8")

    ips = load_ips_from_csv(str(csv_file), column_name="ip_address")

    assert ips == ["8.8.8.8", "1.1.1.1"]


def test_load_ips_from_csv_returns_empty_for_missing_file():
    ips = load_ips_from_csv("does_not_exist.csv", column_name="ip_address")

    assert ips == []