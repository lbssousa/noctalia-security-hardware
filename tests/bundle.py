#!/usr/bin/env python3
"""Bundles the plugin's panel and its modules into one Luau chunk after tests/panel_test.luau, so the
stock `luau` CLI can run the panel against a mock of the Noctalia API (its require() can't load
"./x.luau" paths, and required modules can't see the test's globals)."""

import json
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "security-hardware")
REQUIRE = re.compile(r'require\("(\.{1,2}/[^"]+\.luau)"\)')


def bundle(entry):
    modules = {}

    def visit(path):
        path = os.path.normpath(path)
        if path in modules:
            return
        with open(path, encoding="utf-8") as f:
            text = f.read()
        modules[path] = None
        here = os.path.dirname(path)

        def replace(match):
            target = os.path.normpath(os.path.join(here, match.group(1)))
            visit(target)
            return '__require("%s")' % os.path.relpath(target, ROOT)

        modules[path] = REQUIRE.sub(replace, text).replace("--!nonstrict", "")

    visit(os.path.join(ROOT, entry))
    out = ["local __modules, __cache = {}, {}",
           "function __require(name) if __cache[name] == nil then __cache[name] = __modules[name]() end "
           "return __cache[name] end"]
    for path, text in modules.items():
        name = os.path.relpath(path, ROOT)
        if name == entry:
            continue
        out.append('__modules["%s"] = function()\n%s\nend' % (name, text))
    out.append("-- entry: " + entry)
    out.append(modules[os.path.normpath(os.path.join(ROOT, entry))])
    return "\n".join(out)


def translations(lang):
    """The plugin's strings as a flat Luau table, for the mock noctalia.tr()."""
    with open(os.path.join(ROOT, "translations", lang + ".json"), encoding="utf-8") as f:
        tree = json.load(f)
    flat = {}

    def walk(node, prefix):
        for key, value in node.items():
            if isinstance(value, dict):
                walk(value, prefix + key + ".")
            else:
                flat[prefix + key] = value
    walk(tree, "")
    return "{\n" + "\n".join("  [%s] = %s," % (json.dumps(k, ensure_ascii=False), json.dumps(v, ensure_ascii=False)) for k, v in sorted(flat.items())) + "\n}"


if __name__ == "__main__":
    test = sys.argv[1]
    with open(test, encoding="utf-8") as f:
        harness = f.read()
    marker = "--@@PANEL@@"
    before, after = harness.split(marker, 1)
    lang = sys.argv[2] if len(sys.argv) > 2 else "en"
    before = before.replace("--@@TRANSLATIONS@@", "__LANG = %s\n__TRANSLATIONS = %s" % (json.dumps(lang), translations(lang)))
    sys.stdout.write(before + "\ndo\n" + bundle("panel.luau") + "\nend\n" + after)
