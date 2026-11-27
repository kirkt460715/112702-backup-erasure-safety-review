"""读取独立的本地来源资料，并提供本地只读审计入口。"""
import argparse
import json
from pathlib import Path


def load_sources(directory):
    sources = {}
    for path in sorted(directory.glob("*.json")):
        rows = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError(f"{path.name} 需要对象数组")
        identifiers = [row.get("id") for row in rows]
        if any(not isinstance(key, str) or not key for key in identifiers):
            raise ValueError(f"{path.name} 缺少记录标识")
        if len(identifiers) != len(set(identifiers)):
            raise ValueError(f"{path.name} 的记录标识重复")
        sources[path.stem] = rows
    if not sources:
        raise ValueError("没有本地资料")
    return sources


def describe(sources):
    return [{"source": name, "count": len(rows), "ids": [row["id"] for row in rows]}
            for name, rows in sources.items()]


def read_page(sources, name, offset, limit):
    if offset < 0 or not 1 <= limit <= 50:
        raise ValueError("分页范围无效")
    if name not in sources:
        raise ValueError("来源不存在")
    rows = sources[name]
    end = offset + limit
    return {"source": name, "records": rows[offset:end],
            "next_offset": end if end < len(rows) else None}


def main(argv=None):
    import sys
    argv = list(sys.argv[1:] if argv is None else argv)
    # 审计入口：`records_view.py audit ...` 或 `records_view.py --audit ...`。
    if argv and argv[0] == "audit":
        from audit import main as audit_main
        return audit_main(argv[1:])
    if "--audit" in argv:
        argv.remove("--audit")
        from audit import main as audit_main
        return audit_main(argv)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=Path, default=Path(__file__).with_name("records"))
    parser.add_argument("--source")
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args(argv)
    try:
        sources = load_sources(args.records)
        result = (describe(sources) if args.source is None
                  else read_page(sources, args.source, args.offset, args.limit))
    except (ValueError, OSError) as error:
        parser.error(str(error))
    print(json.dumps(result, ensure_ascii=False))
    return 0


def __getattr__(name):
    """把审计 API 转发到 :mod:`audit`，兼容 ``from records_view import build_report`` 等用法。"""
    try:
        import audit as _audit
    except ImportError as error:  # pragma: no cover
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from error
    if hasattr(_audit, name):
        return getattr(_audit, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


if __name__ == "__main__":
    raise SystemExit(main())
