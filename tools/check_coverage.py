#!/usr/bin/env python3
"""Merge kcov Cobertura line records and enforce a source-line coverage floor."""

import argparse
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def measure(directory):
    lines = {}
    reports = sorted(directory.rglob("cobertura.xml"))
    if not reports:
        raise ValueError("No Cobertura coverage report was produced")
    for path in reports:
        for cls in ET.parse(path).getroot().iter("class"):
            filename = cls.get("filename")
            if not filename:
                raise ValueError(f"Missing source filename in {path}")
            for line in cls.findall("./lines/line"):
                key = (filename, int(line.attrib["number"]))
                lines[key] = lines.get(key, False) or int(line.attrib["hits"]) > 0
    if not lines:
        raise ValueError("Coverage reports contain no measured source lines")
    covered = sum(lines.values())
    return {"covered": covered, "total": len(lines), "percent": 100 * covered / len(lines)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--minimum", type=float, default=70.0)
    args = parser.parse_args()
    if not 0 <= args.minimum <= 100:
        parser.error("--minimum must be between 0 and 100")
    try:
        result = measure(args.directory)
    except (ValueError, ET.ParseError, KeyError) as error:
        print(f"Coverage failure: {error}")
        return 1
    print(json.dumps(result, indent=2))
    return int(result["percent"] < args.minimum)


if __name__ == "__main__":
    raise SystemExit(main())
