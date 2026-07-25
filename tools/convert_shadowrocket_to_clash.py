from __future__ import annotations

from collections import Counter
from pathlib import Path
from urllib.request import Request, urlopen


UPSTREAM = (
    "https://raw.githubusercontent.com/"
    "GMOogway/shadowrocket-rules/master"
)

SOURCES = {
    "direct": f"{UPSTREAM}/sr_direct_list.module",
    "proxy": f"{UPSTREAM}/sr_proxy_list.module",
    "reject": f"{UPSTREAM}/sr_reject_list.module",
}

# Mihomo 当前支持、并且适合放在 classical 规则集中的常见规则。
SUPPORTED_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-WILDCARD",
    "DOMAIN-REGEX",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-SUFFIX",
    "IP-ASN",
    "GEOIP",
    "SRC-GEOIP",
    "SRC-IP-ASN",
    "SRC-IP-CIDR",
    "SRC-IP-SUFFIX",
    "DST-PORT",
    "SRC-PORT",
    "IN-PORT",
    "IN-TYPE",
    "IN-USER",
    "IN-NAME",
    "PROCESS-PATH",
    "PROCESS-PATH-WILDCARD",
    "PROCESS-PATH-REGEX",
    "PROCESS-NAME",
    "PROCESS-NAME-WILDCARD",
    "PROCESS-NAME-REGEX",
    "NETWORK",
    "DSCP",
}

SHADOWROCKET_POLICIES = {
    "DIRECT",
    "PROXY",
    "REJECT",
    "REJECT-DROP",
    "REJECT-TINYGIF",
}


def download_text(url: str) -> str:
    request = Request(
        url,
        headers={
            "User-Agent": "shadowrocket-to-clash-converter/1.0",
        },
    )

    with urlopen(request, timeout=120) as response:
        return response.read().decode("utf-8-sig")


def remove_policy(line: str) -> str | None:
    """移除规则末尾的 DIRECT、PROXY、REJECT，同时保留 no-resolve。"""

    modifier = ""

    body, separator, last_field = line.rpartition(",")

    if separator and last_field.strip().lower() == "no-resolve":
        modifier = ",no-resolve"
        line = body

    body, separator, policy = line.rpartition(",")

    if not separator:
        return None

    if policy.strip().upper() not in SHADOWROCKET_POLICIES:
        return None

    return body.strip() + modifier


def convert(name: str, url: str, output: Path) -> None:
    source = download_text(url)

    converted: list[str] = []
    seen: set[str] = set()
    skipped_types: Counter[str] = Counter()

    for raw_line in source.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        # 删除 Shadowrocket 模块头部和注释。
        if line.startswith(("#", ";")):
            continue

        if line.lower() == "[rule]":
            continue

        rule_type = line.split(",", 1)[0].strip().upper()

        # 过滤 URL-REGEX、USER-AGENT 等 Mihomo 不支持的类型。
        if rule_type not in SUPPORTED_TYPES:
            skipped_types[rule_type] += 1
            continue

        rule = remove_policy(line)

        if not rule:
            continue

        if rule not in seen:
            seen.add(rule)
            converted.append(rule)

    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("w", encoding="utf-8", newline="\n") as file:
        file.write("\n".join(converted))
        file.write("\n")

    print(
        f"{name}: generated {len(converted)} rules; "
        f"skipped={dict(skipped_types)}"
    )


def main() -> None:
    output_dir = Path("clash")

    for name, url in SOURCES.items():
        convert(
            name=name,
            url=url,
            output=output_dir / f"{name}.txt",
        )


if __name__ == "__main__":
    main()
