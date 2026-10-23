#!/usr/bin/env python3
"""Generate the dialect field reference from the normative schema.

Why this exists
---------------
`schema/llmproxy-v1.schema.json` is normative for the `--config` dialect
(AGENTS.md "Architecture Invariants", 5). A hand-kept field table drifts from
it; a generated one cannot. This script renders every object, field, type,
default, required flag, description and cross-field rule in the schema into
one docs-site page. Hand-written pages keep the explanations and link here.

Unknown schema constructs are an error, not an omission: a rule this script
cannot render would otherwise disappear from the reference silently.

Usage:  make config-reference         (write the page)
        make config-reference-check   (fail if the committed page is stale)
"""

import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "schema" / "llmproxy-v1.schema.json"
OUTPUT = ROOT / "docs" / "site" / "src" / "content" / "docs" / "configuration" / "reference.md"

# Keywords that annotate or constrain a value and are rendered (or are
# deliberately not shown, like `$schema`). Anything else fails generation.
KNOWN_KEYWORDS = {
    "$schema", "$id", "$ref", "$defs", "title", "description", "type", "properties",
    "required", "additionalProperties", "patternProperties", "items", "enum", "const",
    "default", "examples", "format", "pattern", "minimum", "maximum", "minLength",
    "minItems", "minProperties", "uniqueItems", "oneOf", "anyOf", "allOf", "not",
    "if", "then",
}


class SchemaError(Exception):
    pass


def check_keywords(node, where):
    unknown = set(node) - KNOWN_KEYWORDS
    if unknown:
        raise SchemaError(f"{where}: no rendering for keyword(s) {sorted(unknown)}")


def anchor(name):
    """The id Starlight gives a heading whose text is `name`: github-slugger
    lowercases, drops punctuation other than `-` and `_`, and turns spaces
    into `-`. Links target those ids, so the page carries no anchors of its
    own that could collide with them."""
    return re.sub(r"[^\w\- ]", "", name.lower()).replace(" ", "-")


def code(value):
    text = value if isinstance(value, str) else json.dumps(value)
    return f"`{text}`"


def cell(text):
    """One table cell: a single line with table pipes escaped."""
    return " ".join(text.split()).replace("|", "\\|")


class Renderer:
    def __init__(self, schema):
        self.schema = schema
        self.defs = schema.get("$defs", {})
        # Sections in output order: (title, node, path for errors).
        self.sections = []
        self.seen = set()
        self.scalar_defs = []
        # Definition name -> config paths that use it, for "Used at".
        self.used_at = {}

    # ----------------------------------------------------------- types --

    def ref_name(self, ref):
        prefix = "#/$defs/"
        if not ref.startswith(prefix) or ref[len(prefix):] not in self.defs:
            raise SchemaError(f"unsupported $ref {ref}")
        return ref[len(prefix):]

    def is_object_def(self, node):
        return node.get("type") == "object" and "properties" in node

    def queue_def(self, name):
        if name in self.seen:
            return
        self.seen.add(name)
        node = self.defs[name]
        if self.is_object_def(node) or (node.get("type") == "object" and "patternProperties" not in node):
            self.sections.append((name, node, f"#/$defs/{name}"))
        else:
            self.scalar_defs.append(name)

    def type_of(self, node, path, label):
        """A short type expression; queues the sections it links to."""
        check_keywords(node, path)
        if "$ref" in node:
            name = self.ref_name(node["$ref"])
            uses = self.used_at.setdefault(name, [])
            if label not in uses:
                uses.append(label)
            self.queue_def(name)
            return f"[{name}](#{anchor(name)})"
        for combinator, joiner in (("oneOf", " or "), ("anyOf", " or ")):
            if combinator in node and "type" not in node and "properties" not in node:
                return joiner.join(
                    self.with_constraints(b, f"{path}/{combinator}/{i}", label)
                    for i, b in enumerate(node[combinator])
                )
        if "const" in node:
            return f"constant {code(node['const'])}"
        if "enum" in node:
            return "one of " + ", ".join(code(v) for v in node["enum"])
        t = node.get("type")
        if isinstance(t, list):
            return " or ".join(t)
        if t == "array":
            items = node.get("items", {})
            text = "array of " + self.type_of(items, f"{path}/items", label + "[]")
            return text
        if t == "object":
            if "properties" in node:
                # An inline object gets its own section, named by its path.
                key = f"inline:{label}"
                if key not in self.seen:
                    self.seen.add(key)
                    self.sections.append((label, node, path))
                return f"[object](#{anchor(label)})"
            if "patternProperties" in node:
                (pattern, value), = node["patternProperties"].items()
                inner = self.type_of(value, f"{path}/patternProperties", label + ".<name>")
                return f"map of {inner}, keys match {code(pattern)}"
            extra = node.get("additionalProperties")
            if isinstance(extra, dict):
                inner = self.type_of(extra, f"{path}/additionalProperties", label + ".<name>")
                return f"map of {inner}"
            return "object"
        if t is None:
            raise SchemaError(f"{path}: no type, $ref, enum or const")
        if "format" in node:
            return f"{t} ({node['format']})"
        return t

    def with_constraints(self, node, path, label):
        """A combinator branch: its type plus its own constraints, which a
        reader needs to tell the branches apart (`TokenAmount`)."""
        text = self.type_of(node, path, label)
        extra = self.constraints(node)
        return f"{text} ({', '.join(extra)})" if extra and "$ref" not in node else text

    def constraints(self, node):
        parts = []
        for key, word in (("minimum", "minimum"), ("maximum", "maximum"),
                          ("minLength", "minimum length"), ("minItems", "minimum items"),
                          ("minProperties", "minimum entries")):
            if key in node:
                parts.append(f"{word} {node[key]}")
        if node.get("uniqueItems"):
            parts.append("items unique")
        if "pattern" in node:
            parts.append(f"pattern {code(node['pattern'])}")
        return parts

    # ----------------------------------------------------------- rules --

    def branch(self, node, path):
        """A plain-language condition for one rule branch."""
        parts = []
        for key in node:
            if key not in ("required", "properties", "not"):
                raise SchemaError(f"{path}: no rule rendering for {key!r}")
        for field in node.get("required", []):
            parts.append(f"{code(field)} is set")
        for field, sub in node.get("properties", {}).items():
            for key, one, many in (("minItems", "item", "items"),
                                   ("minProperties", "entry", "entries")):
                if key in sub:
                    word = one if sub[key] == 1 else many
                    parts.append(f"{code(field)} has at least {sub[key]} {word}")
            if set(sub) - {"minItems", "minProperties"}:
                raise SchemaError(f"{path}/properties/{field}: no rule rendering")
        if "not" in node:
            parts.append(self.negation(node["not"], f"{path}/not"))
        if not parts:
            raise SchemaError(f"{path}: empty rule branch")
        return " and ".join(parts)

    def negation(self, node, path):
        if set(node) == {"required"}:
            fields = node["required"]
            if len(fields) == 1:
                return f"{code(fields[0])} is not set"
            return " and ".join(code(f) for f in fields) + " are not both set"
        if set(node) == {"anyOf"}:
            groups = []
            for i, b in enumerate(node["anyOf"]):
                if set(b) != {"required"}:
                    raise SchemaError(f"{path}/anyOf/{i}: no rule rendering")
                groups.append(" with ".join(code(f) for f in b["required"]))
            return "none of " + ", ".join(groups) + " is set"
        raise SchemaError(f"{path}: no rendering for this `not`")

    @staticmethod
    def exclusive_fields(branches):
        """The fields of a `oneOf` whose every branch is "this one field is
        set, and none of the others", so it reads as "set exactly one of"."""
        if not branches:
            return None
        fields = []
        for b in branches:
            if set(b) - {"required", "not"} or len(b.get("required", [])) != 1:
                return None
            fields.append(b["required"][0])
        for b in branches:
            excluded = b.get("not", {"required": []})
            if set(excluded) != {"required"}:
                return None
            if not set(excluded["required"]) <= set(fields) - {b["required"][0]}:
                return None
        return fields

    def condition(self, node, path):
        """`if` blocks of the form `type == X`, its negation, or the
        negation of an `anyOf` of such tests on one field."""
        negated = False
        if set(node) == {"not"}:
            node, negated = node["not"], True
        if negated and set(node) == {"anyOf"}:
            fields, values = set(), []
            for i, branch in enumerate(node["anyOf"]):
                field, value = self.const_test(branch, f"{path}/not/anyOf/{i}")
                fields.add(field)
                values.append(code(value))
            if len(fields) != 1 or len(values) < 2:
                raise SchemaError(f"{path}: no rendering for this `if`")
            listed = ", ".join(values[:-1]) + " or " + values[-1]
            return f"When {code(fields.pop())} is not {listed}"
        props = node.get("properties", {})
        if set(node) != {"properties", "required"} or len(props) != 1:
            raise SchemaError(f"{path}: no rendering for this `if`")
        (field, sub), = props.items()
        if set(sub) != {"const"} or node["required"] != [field]:
            raise SchemaError(f"{path}: no rendering for this `if`")
        verb = "is not" if negated else "is"
        return f"When {code(field)} {verb} {code(sub['const'])}"

    def const_test(self, node, path):
        """The (field, value) of an `if` of the form `field == value`."""
        self.condition(node, path)
        (field, sub), = node["properties"].items()
        return field, sub["const"]

    def rules(self, node, path):
        out = []
        if "required" in node and "properties" not in node:
            out.append(", ".join(code(f) for f in node["required"]) + " must be set.")
        exclusive = self.exclusive_fields(node.get("oneOf"))
        if exclusive:
            out.append("Set exactly one of " + ", ".join(code(f) for f in exclusive) + ".")
            node = {k: v for k, v in node.items() if k != "oneOf"}
        for combinator, lead in (("oneOf", "Exactly one of these holds"),
                                 ("anyOf", "At least one of these holds")):
            if combinator in node:
                branches = [self.branch(b, f"{path}/{combinator}/{i}")
                            for i, b in enumerate(node[combinator])]
                out.append(f"{lead}: " + "; or ".join(branches) + ".")
        if "not" in node:
            text = self.negation(node["not"], f"{path}/not")
            out.append(text[0].upper() + text[1:] + ".")
        for i, sub in enumerate(node.get("allOf", [])):
            sub_path = f"{path}/allOf/{i}"
            if "if" in sub:
                if set(sub) != {"if", "then"}:
                    raise SchemaError(f"{sub_path}: `if` without exactly one `then`")
                lead = self.condition(sub["if"], f"{sub_path}/if")
                inner = self.rules(sub["then"], f"{sub_path}/then")
                out.append(f"{lead}: " + " ".join(inner))
            else:
                out.extend(self.rules(sub, sub_path))
        return out

    # --------------------------------------------------------- sections --

    def description(self, node, path):
        """A property's own description, else its definition's. A field
        with neither fails generation: the reference would show it bare."""
        if "description" in node:
            return node["description"]
        if "$ref" in node:
            target = self.defs[self.ref_name(node["$ref"])]
            if "description" in target:
                return target["description"]
        raise SchemaError(f"{path}: no description (add one to the schema)")

    def object_section(self, title, node, path):
        check_keywords(node, path)
        heading = title if title == "Top level" else code(title)
        lines = [f"## {heading}", ""]
        if title in self.used_at:
            lines += ["Used at: " + ", ".join(code(u) for u in self.used_at[title]) + ".", ""]
        if "description" in node:
            lines += [" ".join(node["description"].split()), ""]
        # Children are labelled by config path: a definition's first use, an
        # inline object's own path, nothing at the top level.
        prefix = None if title == "Top level" else self.used_at.get(title, [title])[0]
        props = node.get("properties", {})
        required = set(node.get("required", []))
        if props:
            lines += ["| Field | Type | Required | Default | Description |",
                      "|---|---|---|---|---|"]
            for name, sub in props.items():
                child_label = name if prefix is None else f"{prefix}.{name}"
                sub_path = f"{path}/properties/{name}"
                type_text = self.type_of(sub, sub_path, child_label)
                extra = self.constraints(sub)
                if extra:
                    type_text += "; " + ", ".join(extra)
                desc = self.description(sub, sub_path)
                if "examples" in sub:
                    desc += " Examples: " + ", ".join(code(e) for e in sub["examples"]) + "."
                default = code(sub["default"]) if "default" in sub else "none"
                lines.append(
                    f"| {code(name)} | {cell(type_text)} | {'yes' if name in required else 'no'} "
                    f"| {cell(default)} | {cell(desc)} |"
                )
            lines.append("")
        else:
            lines += ["This object takes no fields.", ""]
        if node.get("additionalProperties") is False:
            lines += ["Any other field is a load error.", ""]
        rule_list = self.rules({k: v for k, v in node.items()
                                if k in ("oneOf", "anyOf", "not", "allOf")}, path)
        if rule_list:
            lines += ["Rules:", ""] + [f"- {r}" for r in rule_list] + [""]
        return lines

    def scalar_section(self, name):
        node = self.defs[name]
        path = f"#/$defs/{name}"
        check_keywords(node, path)
        lines = [f"### {name}", ""]
        type_text = self.type_of({k: v for k, v in node.items()
                                  if k not in ("description", "examples")}, path, name)
        extra = self.constraints(node)
        lines.append(f"Type: {type_text}" + (f"; {', '.join(extra)}" if extra else "") + ".")
        lines.append("")
        if "description" in node:
            lines += [" ".join(node["description"].split()), ""]
        if name in self.used_at:
            lines += ["Used at: " + ", ".join(code(u) for u in self.used_at[name]) + ".", ""]
        if "examples" in node:
            lines += ["Examples: " + ", ".join(code(e) for e in node["examples"]) + ".", ""]
        return lines

    def render(self):
        self.sections.append(("Top level", self.schema, "#"))
        body = []
        i = 0
        # Sections are discovered while rendering earlier ones, so walk the
        # list as it grows: each object follows the first object linking it.
        while i < len(self.sections):
            body += self.object_section(*self.sections[i])
            i += 1
        # A definition nothing links to is still part of the schema.
        for name in self.defs:
            if name not in self.seen:
                self.queue_def(name)
                while i < len(self.sections):
                    body += self.object_section(*self.sections[i])
                    i += 1
        if self.scalar_defs:
            body += ["## Value types", ""]
            for name in self.scalar_defs:
                body += self.scalar_section(name)
        return body


HEADER = """---
title: Configuration field reference
description: Every field of the llm-proxy configuration file (--config), generated from schema/llmproxy-v1.schema.json.
---

<!-- GENERATED by scripts/gen-config-reference.py from schema/llmproxy-v1.schema.json.
     Do not edit. Run `make config-reference` after a schema change. -->

This page is generated from `schema/llmproxy-v1.schema.json`, the normative
schema for the file passed with `--config`. It lists every field, its type,
its default and whether it is required. For explanations and examples, see
[Configuration file](../configuration-file/).

Parsing is strict: an unknown field is a load error that names its full path.
Every string field accepts `${VAR_NAME}` environment-variable interpolation,
applied before parsing.
"""


def generate():
    schema = json.loads(SCHEMA.read_text())
    body = Renderer(schema).render()
    return HEADER + "\n" + "\n".join(body).rstrip() + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="fail if the committed page differs from the schema")
    args = parser.parse_args()
    try:
        text = generate()
    except SchemaError as e:
        print(f"gen-config-reference: {e}", file=sys.stderr)
        return 1
    rel = OUTPUT.relative_to(ROOT)
    if args.check:
        current = OUTPUT.read_text() if OUTPUT.exists() else ""
        if current != text:
            print(f"{rel} is stale; run `make config-reference` and commit it", file=sys.stderr)
            return 1
        print(f"{rel} is up to date")
        return 0
    OUTPUT.write_text(text)
    print(f"wrote {rel}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
