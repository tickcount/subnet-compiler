#!/usr/bin/env python3
import argparse
import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

import yaml

IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$")
IPV6_RE = re.compile(r"^[0-9a-fA-F:]+(/\d{1,3})?$")


def classify(entry: str):
    if IPV4_RE.match(entry):
        return "cidr4"
    if ":" in entry and IPV6_RE.match(entry):
        return "cidr6"
    return "domain"


def fetch_url(url: str) -> list[str]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "subnet-compiler/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode().splitlines()
    except Exception as e:
        print(f"  warning: {url}: {e}", file=sys.stderr)
        return []


def read_file(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        print(f"  warning: file not found: {path}", file=sys.stderr)
        return []
    return p.read_text().splitlines()


def collect(sources: list) -> tuple[list, list, list]:
    seen: set[str] = set()
    cidrs4, cidrs6, domains = [], [], []

    for source in sources:
        if "url" in source:
            lines = fetch_url(source["url"])
        elif "file" in source:
            lines = read_file(source["file"])
        else:
            continue

        for raw in lines:
            entry = raw.strip()
            if not entry or entry.startswith("#"):
                continue
            if entry in seen:
                continue
            seen.add(entry)
            kind = classify(entry)
            if kind == "cidr4":
                cidrs4.append(entry)
            elif kind == "cidr6":
                cidrs6.append(entry)
            else:
                domains.append(entry)

    return cidrs4, cidrs6, domains


def write_json(path: Path, ruleset: dict):
    path.write_text(json.dumps(ruleset, indent=2))
    print(f"  wrote {path}")


def compile_srs(json_path: Path):
    srs_path = json_path.with_suffix(".srs")
    try:
        subprocess.run(
            ["sing-box", "rule-set", "compile", str(json_path), "-o", str(srs_path)],
            check=True,
        )
        print(f"  compiled -> {srs_path}")
    except FileNotFoundError:
        sys.exit("sing-box not found — install it or use --no-compile")
    except subprocess.CalledProcessError as e:
        sys.exit(f"sing-box failed on {json_path}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Compile sing-box rule sets from config.yml")
    parser.add_argument("--config", default="config.yml", help="Path to config file")
    parser.add_argument("--out", default="rules", help="Output directory")
    parser.add_argument("--no-compile", action="store_true", help="Skip sing-box compile step")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        sys.exit(f"config not found: {config_path}")

    with config_path.open() as f:
        config = yaml.safe_load(f)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    for name, category in config.get("categories", {}).items():
        print(f"==> {name}")
        sources = category.get("sources", [])
        cidrs4, cidrs6, domains = collect(sources)
        print(f"  {len(cidrs4)} CIDRv4, {len(cidrs6)} CIDRv6, {len(domains)} domains")

        if cidrs4:
            ipv4_json = out_dir / f"{name}-ipv4.json"
            write_json(ipv4_json, {"version": 3, "rules": [{"ip_cidr": cidrs4}]})
            if not args.no_compile:
                compile_srs(ipv4_json)

        if cidrs6:
            ipv6_json = out_dir / f"{name}-ipv6.json"
            write_json(ipv6_json, {"version": 3, "rules": [{"ip_cidr": cidrs6}]})
            if not args.no_compile:
                compile_srs(ipv6_json)

        if domains:
            domain_json = out_dir / f"{name}-domains.json"
            write_json(domain_json, {"version": 3, "rules": [{"domain_suffix": domains}]})
            if not args.no_compile:
                compile_srs(domain_json)


if __name__ == "__main__":
    main()
