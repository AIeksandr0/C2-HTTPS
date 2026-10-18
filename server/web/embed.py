
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "webui.h")

ASSETS = [
    ("kIndexHtml", "index.html"),
    ("kAppCss", "app.css"),
    ("kAppJs", "app.js" ),
]


def wrap_byte_lines(data, width=20):
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        lines.append("    " + ",".join(str(b) for b in chunk) + ",")
    return "\n".join(lines)


def main():
    parts = []
    parts.append("#pragma once")
    parts.append("#include <cstddef>")
    parts.append("")
    parts.append("namespace webui {")
    parts.append("")

    for name, filename in ASSETS:
        path = os.path.join(HERE, filename)
        with open(path, "rb") as f:
            data = f.read()
        parts.append("static const unsigned char %s[] = {" % name)
        parts.append(wrap_byte_lines(data))
        parts.append("   0")
        parts.append("};")
        parts.append("static const size_t %sLen = %d;" % (name, len(data)))
        parts.append("")

    parts.append("}")
    parts.append("")

    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(parts))

    total = sum(len(open(os.path.join(HERE, fn), "rb").read()) for _, fn in ASSETS)
    print("wrote %s (%d bytes embedded)" % (os.path.normpath(OUT), total))


if __name__ == "__main__":
    sys.exit(main())
