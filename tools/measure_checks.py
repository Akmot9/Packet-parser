#!/usr/bin/env python3
"""Mesure la triplication parse/checks/errors par protocole (issue #222).

Pour chaque fichier de `src/checks/` qui definit des fonctions (un fichier
par protocole, plus les `mod.rs` qui en portent : Ethernet dans
`data_link/mod.rs`, les octets des protocoles texte dans
`application/mod.rs`), le script compte :

- les fonctions libres `pub` ou `pub(crate)` du fichier ;
- celles qui n'ont qu'un site d'appel dans le code de `src/` hors tests
  (`#[cfg(test)]`), et celles qui n'en ont aucun (appelees par les tests
  seuls, ou mortes) ;
- celles qui servent hors de leur protocole : un autre module de `src/`
  (hors tests), ou `tests/`, `fuzz/` (oracles et cibles), `benches/` ;
- celles qu'un test appelle directement (module de test du fichier de
  checks ou d'un autre fichier de `src/`, ou `tests/`, `fuzz/`, `benches/`) ;
- les gardes : un corps d'une ou deux instructions de premier niveau, sans
  boucle ni `match` (`if <condition> { return Err(..) } Ok(..)`, ou une
  expression seule). Le compte est logique, pas physique : rustfmt deploie
  un `return Err(Erreur { .. })` sur cinq lignes, une garde en occupe
  souvent sept ;
- les lignes de code des fichiers checks, errors et parse du protocole, hors
  commentaires, lignes vides et blocs `#[cfg(test)]`, et le rapport
  (checks + errors) / parse.

Usage (depuis n'importe ou, les chemins partent de la racine du depot) :
    python3 tools/measure_checks.py              # table Markdown
    python3 tools/measure_checks.py --detail ntp # une ligne par fonction
    python3 tools/measure_checks.py --tsv        # toutes les fonctions, TSV
    python3 tools/measure_checks.py --unresolved # occurrences non attribuees
    python3 tools/measure_checks.py --lines src/parse/application/protocols/foo.rs
        # lignes de code d'un fichier, hors commentaires et tests : le critere
        # du petit decodeur de METHODE_AJOUT_PROTOCOLE.md

Methode et limites. La recherche des appels est textuelle, sur le source
debarrasse des commentaires et du contenu des chaines : elle ne compile rien.
- Un site d'appel est une occurrence de l'identifiant qui n'est pas sa
  definition : appel, passage en pointeur de fonction (`.map(extract_x)`).
  Les declarations `use` ne comptent pas. Chaque site compte une fois, meme
  dans une boucle.
- Les homonymes sont departages par les imports : une occurrence nue n'est
  attribuee a une fonction de checks que dans son propre fichier, ou dans un
  fichier qui l'importe (`use`, alias `as` compris, ou import glob `*`). Une
  occurrence prefixee (`crate::checks::...::f`, `super::f`, `dnp3::f` apres
  `use ...::dnp3`) est attribuee par son chemin. Un import local a une
  fonction vaut pour tout le fichier.
- Un appel par un chemin que le script ne sait pas resoudre (module
  re-exporte sous un autre nom, `use` en chaine `use a::b; use b::c`) est
  perdu ; il est compte parmi les occurrences textuelles non resolues.
- Les macros ne sont pas developpees : un appel ecrit dans le corps d'un
  `macro_rules!` compterait une fois, quel que soit le nombre d'expansions
  (src/ n'en definit aucune a la date de la mesure).
- Les methodes (`impl` des curseurs QUIC et PostgreSQL) sont exclues : un
  `.take(` ou un `.remaining(` ne se distingue pas d'une methode homonyme
  sans les types. Elles sont comptees a part.
- `src/checks` est `pub(crate)` depuis la 11.0.0 : `tests/`, `fuzz/` et
  `benches/` ne peuvent pas l'appeler, sauf a l'inclure par `#[path]`, ce
  que le script detecte. Les occurrences textuelles qu'on y trouve sont des
  homonymes ; elles sont comptees et signalees, pas attribuees.
"""
import argparse
import os
import re
import statistics
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXTERNAL_DIRS = ("tests", "fuzz", "benches")
GUARD_MAX_STATEMENTS = 2
# Seuil du petit decodeur (METHODE_AJOUT_PROTOCOLE.md, section Organisation
# des fichiers, #222) : parseur et checks ensemble, en lignes de code.
SMALL_DECODER_MAX_LINES = 300

# Fichiers de checks qui ne suivent pas la correspondance par nom :
# etiquette, fichiers de parse, fichiers d'erreurs.
SPECIAL_UNITS = {
    "src/checks/data_link/mod.rs": (
        "ethernet",
        [
            "src/parse/data_link/mod.rs",
            "src/parse/data_link/vlan_tag.rs",
            "src/parse/data_link/mac_addres/mod.rs",
        ],
        ["src/errors/data_link/mod.rs", "src/errors/data_link/mac_addres/mod.rs"],
    ),
    "src/checks/application/mod.rs": ("texte (commun)", [], []),
}

IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
SPECIAL = re.compile(r"//|/\*|(?<![A-Za-z0-9_])(?:b|c)?r(#*)\"|\"|'")
CFG_TEST = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")
USE_RE = re.compile(r"(?<![A-Za-z0-9_:])(?:pub\s*(?:\([^)]*\))?\s+)?use\s+")
USE_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|::|[{},*]")
FN_DEF = re.compile(
    r"(?<![A-Za-z0-9_])pub\s*(\(\s*crate\s*\))?\s+(?:const\s+)?(?:async\s+)?"
    r"(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)"
)
IMPL_RE = re.compile(r"(?<![A-Za-z0-9_])impl(?![A-Za-z0-9_])")
BRANCHING_RE = re.compile(r"(?<![A-Za-z0-9_])(?:for|while|loop|match)(?![A-Za-z0-9_])")
PATH_INCLUDE = re.compile(r"#\s*\[\s*path\s*=\s*\"[^\"]*src/checks")


def blank(chunk, fill=" "):
    """Remplace tout sauf les fins de ligne."""
    return "".join(c if c == "\n" else fill for c in chunk)


def sanitize(text):
    """Commentaires en espaces, contenu des chaines et caracteres en `~`.

    Les positions et les fins de ligne sont conservees : un offset du texte
    nettoye designe le meme octet du source.
    """
    out = []
    i = 0
    n = len(text)
    while i < n:
        m = SPECIAL.search(text, i)
        if not m:
            out.append(text[i:])
            break
        out.append(text[i : m.start()])
        i = m.start()
        tok = m.group(0)
        if tok == "//":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(blank(text[i:j]))
            i = j
        elif tok == "/*":
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            out.append(blank(text[i:j]))
            i = j
        elif tok.endswith('"') and "r" in tok:
            end = '"' + m.group(1)
            j = text.find(end, m.end())
            j = n if j < 0 else j
            out.append(tok + blank(text[m.end() : j], "~") + text[j : j + len(end)])
            i = j + len(end)
        elif tok == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append('"' + blank(text[i + 1 : j], "~") + '"')
            i = j + 1
        else:  # apostrophe : caractere ou lifetime
            if i + 1 < n and text[i + 1] == "\\":
                j = i + 3
                while j < n and text[j] != "'":
                    j += 1
                out.append("'" + blank(text[i + 1 : j], "~") + "'")
                i = j + 1
            elif i + 2 < n and text[i + 2] == "'":
                out.append("'~'")
                i += 3
            else:
                out.append("'")
                i += 1
    return "".join(out)


def match_close(code, pos, opening, closing):
    """Offset de la fermante qui equilibre `code[pos]`."""
    depth = 0
    for j in range(pos, len(code)):
        ch = code[j]
        if ch == opening:
            depth += 1
        elif ch == closing:
            depth -= 1
            if depth == 0:
                return j
    return len(code) - 1


def item_end(code, pos):
    """Fin de l'item qui commence a `pos` (attributs sautes)."""
    n = len(code)
    while True:
        while pos < n and code[pos].isspace():
            pos += 1
        if code.startswith("#", pos):
            pos = match_close(code, code.find("[", pos), "[", "]") + 1
            continue
        break
    depth = 0
    while pos < n:
        ch = code[pos]
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == ";" and depth == 0:
            return pos + 1
        elif ch == "{" and depth == 0:
            return match_close(code, pos, "{", "}") + 1
        pos += 1
    return n


def module_of(rel):
    """Chemin de module d'un fichier de src/ (`src/a/b.rs` -> crate::a::b)."""
    if not rel.startswith("src/"):
        return None
    parts = rel[len("src/") : -len(".rs")].split("/")
    if parts[-1] in ("mod", "lib"):
        parts = parts[:-1]
    return ["crate"] + parts


class Source:
    """Un fichier Rust nettoye, avec ses blocs de test et ses imports."""

    def __init__(self, rel):
        self.rel = rel
        with open(os.path.join(ROOT, rel), encoding="utf-8") as handle:
            self.text = handle.read()
        self.code = sanitize(self.text)
        self.module = module_of(rel)
        self.external = self.module is None
        self.tests = []
        for m in CFG_TEST.finditer(self.code):
            if self.tests and m.start() < self.tests[-1][1]:
                continue
            self.tests.append((m.start(), item_end(self.code, m.end())))
        self.uses = []  # (debut, fin, [(chemin absolu ou None, nom local)])
        self.imports = {}
        self.globs = []
        for m in USE_RE.finditer(self.code):
            end = self.code.find(";", m.end())
            end = len(self.code) if end < 0 else end + 1
            nested = self.in_test(m.start())
            entries = []
            for segs, local in parse_use_tree(USE_TOKEN.findall(self.code[m.end() : end])):
                path = self.absolutize(segs, nested)
                entries.append((path, local))
                if path is None:
                    continue
                if local == "*":
                    self.globs.append(path)
                else:
                    self.imports.setdefault(local, []).append(path)
            self.uses.append((m.start(), end, entries))
        chars = list(self.code)
        for start, end, _ in self.uses:
            chars[start:end] = blank(self.code[start:end])
        self.search = "".join(chars)

    def in_test(self, pos):
        return any(start <= pos < end for start, end in self.tests)

    def absolutize(self, segs, nested):
        if not segs:
            return None
        first = segs[0]
        if first == "packet_parser":
            return ["crate"] + segs[1:]
        if self.external:
            return None
        if first == "crate":
            return list(segs)
        if first in ("super", "self"):
            base = self.module + (["<test>"] if nested else [])
            i = 0
            while i < len(segs) and segs[i] in ("super", "self"):
                if segs[i] == "super":
                    base = base[:-1]
                i += 1
            return base + segs[i:]
        return None

    def code_lines(self, skip_tests=True):
        chars = list(self.code)
        if skip_tests:
            for start, end in self.tests:
                chars[start:end] = blank(self.code[start:end])
        return sum(1 for line in "".join(chars).split("\n") if line.strip())

    def use_lines_from(self, roots):
        """Lignes des `use` hors tests qui importent depuis `roots`."""
        lines = 0
        for start, end, entries in self.uses:
            if self.in_test(start):
                continue
            if any(p and len(p) > 1 and p[1] in roots for p, _ in entries):
                lines += self.code.count("\n", start, end) + 1
        return lines


def parse_use_tree(tokens):
    """Arbre d'un `use` -> [(segments, nom local ou '*')]."""
    results = []
    pos = 0

    def tree(prefix):
        nonlocal pos
        segs = list(prefix)
        while pos < len(tokens):
            tok = tokens[pos]
            if tok == "{":
                pos += 1
                while pos < len(tokens) and tokens[pos] != "}":
                    if tokens[pos] == ",":
                        pos += 1
                        continue
                    tree(segs)
                pos += 1
                return
            if tok == "*":
                pos += 1
                results.append((segs, "*"))
                return
            if tok == "::":
                pos += 1
                continue
            if tok in (",", "}"):
                return
            segs.append(tok)
            pos += 1
            if pos < len(tokens) and tokens[pos] == "::":
                continue
            alias = None
            if pos + 1 < len(tokens) and tokens[pos] == "as":
                alias = tokens[pos + 1]
                pos += 2
            if segs[-1] == "self":
                segs = segs[:-1]
            if segs:
                results.append((segs, alias or segs[-1]))
            return

    while pos < len(tokens):
        before = pos
        tree([])
        if pos == before:
            pos += 1
    return results


def body_stats(code, def_end):
    """(instructions de premier niveau, lignes, boucle ou match ?) d'un corps."""
    depth, pos = 0, def_end
    while pos < len(code):
        ch = code[pos]
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == ";" and depth == 0:
            return 0, 0, False
        elif ch == "{" and depth == 0:
            break
        pos += 1
    close = match_close(code, pos, "{", "}")
    body = code[pos + 1 : close]
    statements, current, depth, after_block = 0, False, 0, False
    i = 0
    while i < len(body):
        ch = body[i]
        if ch.isspace():
            i += 1
            continue
        if after_block and depth == 0:
            after_block = False
            word = IDENT.match(body, i)
            if ch not in ";.?)],+-*/%&|^<>=!" and not (word and word.group(0) in ("else", "as")):
                statements += 1
                current = False
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if ch == "}" and depth == 0:
                after_block = True
        elif ch == ";" and depth == 0:
            if current:
                statements += 1
            current = False
            i += 1
            continue
        current = True
        i += 1
    if current:
        statements += 1
    lines = sum(1 for line in body.split("\n") if line.strip())
    return statements, lines, bool(BRANCHING_RE.search(body))


class Function:
    def __init__(self, unit, name, visibility, statements, lines, branching):
        self.unit = unit
        self.name = name
        self.visibility = visibility
        self.statements = statements
        self.lines = lines
        self.guard = 1 <= statements <= GUARD_MAX_STATEMENTS and not branching
        self.sites = {}  # categorie -> nombre
        self.other_files = set()

    def count(self, category):
        return self.sites.get(category, 0)

    @property
    def prod(self):
        return self.count("prod_same") + self.count("prod_parser") + self.count("prod_other")

    @property
    def external(self):
        return sum(self.count(d) for d in EXTERNAL_DIRS)

    @property
    def tested(self):
        return self.count("test_same") + self.count("test_other") + self.external > 0


class Unit:
    """Un fichier de checks et les fichiers parse et errors de son protocole."""

    def __init__(self, rel, label, parse_files, error_files):
        self.rel = rel
        self.label = label
        self.layer = rel.split("/")[2]
        self.parse_files = parse_files
        self.error_files = error_files
        self.module = module_of(rel)
        self.functions = {}
        self.methods = 0


def rust_files(top):
    found = []
    base = os.path.join(ROOT, top)
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if d != "target")
        for name in sorted(filenames):
            if name.endswith(".rs"):
                found.append(os.path.relpath(os.path.join(dirpath, name), ROOT))
    return found


def resolve_files(candidates):
    for cand in candidates:
        path = os.path.join(ROOT, cand)
        if cand.endswith(".rs") and os.path.isfile(path):
            return [cand]
        if not cand.endswith(".rs") and os.path.isdir(path):
            return rust_files(cand)
    return []


def build_units(sources):
    units = []
    for rel in sorted(r for r in sources if r.startswith("src/checks/")):
        src = sources[rel]
        defs = [m for m in FN_DEF.finditer(src.code) if not src.in_test(m.start())]
        parts = rel.split("/")
        if rel in SPECIAL_UNITS:
            label, parse_files, error_files = SPECIAL_UNITS[rel]
        elif parts[-1] == "mod.rs" and len(parts) <= 4:
            if defs:
                sys.exit(f"{rel} definit des fonctions : l'ajouter a SPECIAL_UNITS")
            continue
        else:
            layer = parts[2]
            name = parts[3][: -len(".rs")] if len(parts) == 4 else parts[3]
            label = name
            parse_files = resolve_files(
                [
                    f"src/parse/{layer}/protocols/{name}.rs",
                    f"src/parse/{layer}/protocols/{name}",
                    f"src/parse/{layer}/{name}.rs",
                    f"src/parse/{layer}/{name}",
                ]
            )
            error_files = resolve_files(
                [f"src/errors/{layer}/{name}.rs", f"src/errors/{layer}/{name}"]
            )
            if not parse_files or not error_files:
                sys.exit(f"{rel} : parseur ou erreurs introuvables")
        unit = Unit(rel, label, parse_files, error_files)
        impls = []
        for m in IMPL_RE.finditer(src.code):
            before = src.code[: m.start()].rstrip()
            if before and before[-1] not in "{};]":
                continue  # `impl Trait` en position de type
            if src.in_test(m.start()):
                continue
            impls.append((m.start(), item_end(src.code, m.start())))
        for m in defs:
            if any(start <= m.start() < end for start, end in impls):
                unit.methods += 1
                continue
            name = m.group(2)
            vis = "pub(crate)" if m.group(1) else "pub"
            unit.functions[name] = Function(unit, name, vis, *body_stats(src.code, m.end()))
        units.append(unit)
    return units


def scan(sources, units):
    """Attribue chaque occurrence d'un nom de fonction de checks."""
    by_module = {tuple(u.module): u for u in units}
    names = set()
    for u in units:
        names.update(u.functions)
    parse_owner = {}
    for u in units:
        for f in u.parse_files:
            parse_owner.setdefault(f, set()).add(u.rel)
    unresolved = {}

    def lookup(path, name):
        unit = by_module.get(tuple(path)) if path else None
        if unit and name in unit.functions:
            return unit.functions[name]
        return None

    for rel, src in sources.items():
        own = by_module.get(tuple(src.module)) if src.module else None
        aliases = {local: paths for local, paths in src.imports.items() if local not in names}
        wanted = names | {
            local for local, paths in aliases.items()
            if any(p[-1] in names for p in paths)
        }
        code = src.search
        for m in IDENT.finditer(code):
            word = m.group(0)
            if word not in wanted:
                continue
            start = m.start()
            head = code[max(0, start - 300) : start]
            stripped = head.rstrip()
            if re.search(r"(?<![A-Za-z0-9_])fn$", stripped):
                continue  # definition
            tail = code[m.end() : m.end() + 3].lstrip()
            if stripped.endswith("."):
                continue  # champ ou methode
            if tail.startswith(":") and not tail.startswith("::"):
                continue  # champ d'une structure
            target = None
            prefix = re.search(r"((?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)+)$", head)
            nested = src.in_test(start)
            if prefix:
                segs = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", prefix.group(1))
                path = src.absolutize(segs, nested)
                if path is None and segs[0] in src.imports:
                    path = src.imports[segs[0]][0] + segs[1:]
                target = lookup(path, word)
            else:
                if own and word in own.functions:
                    target = own.functions[word]
                for path in src.imports.get(word, []):
                    target = target or lookup(path[:-1], path[-1])
                for path in src.globs:
                    target = target or lookup(path, word)
            if target is None:
                where = rel.split("/")[0] if src.external else "src"
                line = src.code.count("\n", 0, start) + 1
                unresolved.setdefault(where, []).append(f"{rel}:{line}: {word}")
                continue
            if src.external:
                category = rel.split("/")[0]
            elif rel == target.unit.rel:
                category = "test_same" if nested else "prod_same"
            elif nested:
                category = "test_other"
            elif target.unit.rel in parse_owner.get(rel, ()):
                category = "prod_parser"
            else:
                category = "prod_other"
                target.other_files.add(rel)
            target.sites[category] = target.sites.get(category, 0) + 1
    return unresolved


def pct(part, whole):
    return f"{part} ({round(100 * part / whole)} %)" if whole else "0"


def ratio(num, den):
    return f"{num / den:.2f}" if den else "-"


def summarize(units, sources):
    rows = []
    for u in units:
        fns = list(u.functions.values())
        checks = sources[u.rel].code_lines()
        errors = sum(sources[f].code_lines() for f in u.error_files)
        parse = sum(sources[f].code_lines() for f in u.parse_files)
        imports = sum(sources[f].use_lines_from({"checks", "errors"}) for f in u.parse_files)
        rows.append(
            {
                "unit": u,
                "fns": len(fns),
                "single": sum(1 for f in fns if f.prod == 1),
                "zero": sum(1 for f in fns if f.prod == 0),
                "other": sum(1 for f in fns if f.count("prod_other")),
                "external": sum(1 for f in fns if f.external),
                "tested": sum(1 for f in fns if f.tested),
                "guards": sum(1 for f in fns if f.guard),
                "guards_single": sum(1 for f in fns if f.guard and f.prod == 1),
                "checks": checks,
                "errors": errors,
                "parse": parse,
                "imports": imports,
            }
        )
    return rows


COLUMNS = [
    ("fns", "Fonctions"),
    ("single", "1 appel"),
    ("zero", "0 appel"),
    ("other", "Autres modules"),
    ("external", "tests/ fuzz/ benches/"),
    ("tested", "Testees en direct"),
    ("guards", "Gardes"),
    ("guards_single", "Gardes a 1 appel"),
    ("checks", "Lignes checks"),
    ("errors", "Lignes errors"),
    ("parse", "Lignes parse"),
    ("imports", "Lignes `use` checks/errors du parseur"),
]


def git_head():
    try:
        out = subprocess.run(
            ["git", "-C", ROOT, "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, check=True,
        )
        return out.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "inconnu"


def print_table(rows, units, sources, unresolved):
    protocols = [r for r in rows if r["unit"].parse_files]
    total = {key: sum(r[key] for r in rows) for key, _ in COLUMNS}
    fns = total["fns"]
    print(f"## Triplication parse/checks/errors (#222, commit {git_head()})\n")
    header = ["Couche", "Protocole"] + [title for _, title in COLUMNS] + ["(checks+errors)/parse"]
    print("| " + " | ".join(header) + " |")
    print("|" + "---|" * 2 + "---:|" * (len(COLUMNS) + 1))
    for r in rows:
        u = r["unit"]
        cells = [u.layer, u.label] + [str(r[key]) for key, _ in COLUMNS]
        cells.append(ratio(r["checks"] + r["errors"], r["parse"]))
        print("| " + " | ".join(cells) + " |")
    cells = ["**Total**", f"{len(rows)} fichiers"]
    for key, _ in COLUMNS:
        if key in ("fns", "checks", "errors", "parse", "imports"):
            cells.append(f"**{total[key]}**")
        else:
            cells.append(f"**{pct(total[key], fns)}**")
    cells.append(f"**{ratio(total['checks'] + total['errors'], total['parse'])}**")
    print("| " + " | ".join(cells) + " |")
    cells = ["**Mediane**", f"{len(protocols)} protocoles"]
    for key, _ in COLUMNS:
        cells.append(f"{statistics.median(r[key] for r in protocols):g}")
    ratios = [(r["checks"] + r["errors"]) / r["parse"] for r in protocols]
    cells.append(f"{statistics.median(ratios):.2f}")
    print("| " + " | ".join(cells) + " |")

    print("\nColonnes : fonctions libres `pub`/`pub(crate)` ; sites d'appel hors tests")
    print("dans src/ (1 appel, 0 appel = tests seuls ou code mort) ; fonctions appelees")
    print("par un module de src/ hors du protocole (autres modules) ou depuis tests/,")
    print("fuzz/, benches/ ; appelees par un test (testees en direct) ; gardes = corps")
    print(f"de 1 a {GUARD_MAX_STATEMENTS} instructions de premier niveau, sans boucle ni `match`.")
    print("Lignes : code hors commentaires, lignes vides et blocs `#[cfg(test)]`.")

    print("\n### Extremes\n")

    def ranking(key_fn, reverse=True, count=3, fmt=str):
        ordered = sorted(protocols, key=key_fn, reverse=reverse)[:count]
        return ", ".join(f"{r['unit'].label} ({fmt(key_fn(r))})" for r in ordered)

    def share(key):
        return lambda r: r[key] / r["fns"] if r["fns"] else 0

    percent = lambda value: f"{round(100 * value)} %"
    two = lambda value: f"{value:.2f}"
    rel_ratio = lambda r: (r["checks"] + r["errors"]) / r["parse"]
    print(f"- (checks+errors)/parse le plus haut : {ranking(rel_ratio, fmt=two)}")
    print(f"- le plus bas : {ranking(rel_ratio, reverse=False, fmt=two)}")
    print(f"- le plus de fonctions : {ranking(lambda r: r['fns'])}")
    print(f"- le moins de fonctions : {ranking(lambda r: r['fns'], reverse=False)}")
    print(f"- part d'appel unique la plus haute : {ranking(share('single'), fmt=percent)}")
    print(f"- la plus basse : {ranking(share('single'), reverse=False, fmt=percent)}")
    print(f"- part de gardes la plus haute : {ranking(share('guards'), fmt=percent)}")
    print(f"- le plus de lignes de parse : {ranking(lambda r: r['parse'])}")
    print(f"- le moins de lignes de parse : {ranking(lambda r: r['parse'], reverse=False)}")

    other_users = {}
    for u in units:
        for f in u.functions.values():
            for rel in f.other_files:
                other_users.setdefault(f"{u.label} -> {rel}", []).append(f.name)
    print("\n### Appels hors du protocole (src/, hors tests)\n")
    for key in sorted(other_users):
        print(f"- {key} : {', '.join(sorted(other_users[key]))}")

    own_file_only = sum(
        1 for u in units for f in u.functions.values()
        if f.count("prod_same") and not f.count("prod_parser") and not f.count("prod_other")
    )
    combined = [r["parse"] + r["checks"] for r in protocols]
    local = [r for r in protocols if not r["other"] and not r["external"]]
    small = [r for r in local if r["parse"] + r["checks"] <= SMALL_DECODER_MAX_LINES]
    methods = sum(u.methods for u in units)
    path_includes = [
        rel for rel, src in sources.items()
        if src.external and PATH_INCLUDE.search(src.text)
    ]
    lib = sources.get("src/lib.rs")
    private = bool(lib and re.search(r"pub\s*\(\s*crate\s*\)\s+mod\s+checks\b", lib.code))
    print("\n### Notes de mesure\n")
    print(f"- Fichiers : {count_files('src/checks')} checks, {count_files('src/errors')} errors, "
          f"{count_files('src/parse')} parse (mod.rs compris).")
    print(f"- `checks` est {'pub(crate)' if private else 'public'} dans src/lib.rs ; "
          f"inclusions `#[path]` de src/checks depuis tests/, fuzz/, benches/ : "
          f"{len(path_includes)}.")
    print("- Occurrences textuelles de noms de checks non attribuees (homonymes, "
          "fonctions locales, chemins non resolus) : "
          + ", ".join(f"{k} {len(v)}" for k, v in sorted(unresolved.items()))
          + " (liste : --unresolved).")
    print(f"- Methodes `pub` des curseurs exclues du compte : {methods}.")
    print(f"- Fonctions `pub` appelees seulement depuis leur propre fichier de checks : "
          f"{pct(own_file_only, fns)}.")
    print(f"- Lignes parse + checks par protocole : mediane {statistics.median(combined):g}, "
          f"de {min(combined)} a {max(combined)}.")
    print(f"- Protocoles dont aucune fonction de checks ne sert hors du protocole : "
          f"{len(local)} sur {len(protocols)}.")
    print(f"- Decodeurs existants qui rempliraient les deux conditions du petit decodeur "
          f"(aucun appelant exterieur, parse + checks <= {SMALL_DECODER_MAX_LINES} lignes) : "
          f"{len(small)} sur {len(protocols)} ({', '.join(r['unit'].label for r in small)}).")


def count_files(top):
    return len(rust_files(top))


def print_detail(units, label):
    matches = [u for u in units if u.label == label or u.rel == label]
    if not matches:
        sys.exit(f"protocole inconnu : {label}")
    for u in matches:
        print(f"# {u.label} ({u.rel})")
        print(f"parse : {', '.join(u.parse_files) or '-'}")
        print(f"errors : {', '.join(u.error_files) or '-'}")
        print("fonction\tvis\tprod_same\tprod_parser\tprod_other\ttest_same\ttest_other\t"
              "externe\tinstr\tlignes\tgarde\tautres fichiers")
        for f in u.functions.values():
            print("\t".join(str(x) for x in (
                f.name, f.visibility, f.count("prod_same"), f.count("prod_parser"),
                f.count("prod_other"), f.count("test_same"), f.count("test_other"),
                f.external, f.statements, f.lines, "oui" if f.guard else "non",
                ",".join(sorted(f.other_files)),
            )))


def print_tsv(units):
    print("protocole\tfonction\tprod\tprod_other\ttest\texterne\tinstr\tlignes\tgarde")
    for u in units:
        for f in u.functions.values():
            tests = f.count("test_same") + f.count("test_other")
            print("\t".join(str(x) for x in (
                u.label, f.name, f.prod, f.count("prod_other"), tests, f.external,
                f.statements, f.lines, int(f.guard),
            )))


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--detail", metavar="PROTOCOLE", help="une ligne par fonction")
    parser.add_argument("--tsv", action="store_true", help="toutes les fonctions en TSV")
    parser.add_argument(
        "--unresolved", action="store_true",
        help="occurrences de noms de checks que le script n'attribue a aucune fonction",
    )
    parser.add_argument(
        "--lines", nargs="+", metavar="FICHIER",
        help="lignes de code de ces fichiers, hors commentaires et tests",
    )
    args = parser.parse_args()
    if args.lines:
        total = 0
        for path in args.lines:
            rel = os.path.relpath(os.path.abspath(path), ROOT)
            count = Source(rel).code_lines()
            total += count
            print(f"{count}\t{rel}")
        if len(args.lines) > 1:
            print(f"{total}\ttotal")
        verdict = "<=" if total <= SMALL_DECODER_MAX_LINES else ">"
        print(f"seuil du petit decodeur : {total} {verdict} {SMALL_DECODER_MAX_LINES}")
        return

    rels = rust_files("src")
    for top in EXTERNAL_DIRS:
        if os.path.isdir(os.path.join(ROOT, top)):
            rels += rust_files(top)
    sources = {rel: Source(rel) for rel in rels}
    units = build_units(sources)
    unresolved = scan(sources, units)
    if args.detail:
        print_detail(units, args.detail)
    elif args.tsv:
        print_tsv(units)
    elif args.unresolved:
        for where in sorted(unresolved):
            print("\n".join(unresolved[where]))
    else:
        print_table(summarize(units, sources), units, sources, unresolved)


if __name__ == "__main__":
    main()
