#!/usr/bin/env python3
"""
Copyright (c) 2026 quatric
Copyright (c) 2009 megazig

ezitext.py - tools for the Wii Software Keyboard's Zi predictive-text dictionaries.

The Wii's "eZiText" keyboard engine (Zi Corporation, internally "Zi8") loads
two kinds of dictionary file:

  .zsd  Static dictionary
        A table of contents of binary records. Record 0 holds the word list,
        compressed into a DAWG (directed acyclic word graph). Record 4 holds
        a profanity blocklist (words the predictor must not suggest). Format
        reverse engineered from the Zi8*/ZiDAWG* functions in the title's
        00000001.app (Ghidra, PowerPC).

  .znd  Auxiliary ("OEM") dictionary
        A flat array of length-implicit UTF-16BE strings, used for extra
        vocabulary such as Nintendo-supplied proper nouns. Format and the
        original Python 2 reader/writer: megazig (2009); ported to Python 3
        and folded into this tool below.

Japanese titles use JustSystems' ATOK engine instead of Zi, with three
parallel dictionaries:

  .atd  ATOK dictionary
        AtokNintendo.atd (custom game terms), AtokApot.atd (prediction) and
        AtokSystem.atd (main, compressed). Shift-JIS surfaces keyed by
        half-width-katakana readings. Reverse engineered from the ATOK engine
        in 00000001.app. Extract only; System's decompressor is not yet done.

Usage:
    ezitext.py zsd extract        <in.zsd> <out.txt>
    ezitext.py zsd build          <in.zsd> <words.txt> <out.zsd> [--blocklist FILE] [--no-minify]
    ezitext.py zsd dump-blocklist <in.zsd> <out.txt>
    ezitext.py zsd set-blocklist  <in.zsd> <blocklist.txt> <out.zsd>
    ezitext.py znd extract        <in.znd> <out.txt>
    ezitext.py znd build          <in.txt> <out.znd>
    ezitext.py atd extract        <in.atd> <out.tsv> [--surfaces-only]
"""

from __future__ import annotations

import argparse
import re
import struct
import sys
from pathlib import Path

# =============================================================================
# .zsd - static dictionary
# =============================================================================

TOC_ENTRY_SIZE = 6
DICTIONARY_RECORD = 0
BLOCKLIST_RECORD = 4

# The Zi build watermark embedded as a real word in the DAWG and as the final
# entry of the blocklist, e.g. "zicorp20051208000112128".
WATERMARK_PATTERN = re.compile(r"^zicorp\d")


def _read_be24(data: bytes, offset: int) -> int:
    return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]


def _pack_be24(value: int) -> bytes:
    return bytes([(value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])


class Toc:
    """The .zsd table of contents: a run of 6-byte (size, offset) records
    starting at file offset 4, both fields 3-byte big-endian. Record 0's
    offset also marks the end of the TOC, since record 0 always follows
    directly after it.
    """

    def __init__(self, records: dict[int, tuple[int, int]]):
        self.records = records  # index -> (offset, size)

    @classmethod
    def parse(cls, data: bytes) -> "Toc":
        base = _read_be24(data, 7)
        records: dict[int, tuple[int, int]] = {}
        index = 0
        while index * TOC_ENTRY_SIZE + 10 <= base:
            size = _read_be24(data, index * TOC_ENTRY_SIZE + 4)
            offset = _read_be24(data, index * TOC_ENTRY_SIZE + 7)
            if size or offset:
                records[index] = (offset, size)
            index += 1
        return cls(records)

    def patched(
        self,
        data: bytes,
        edits: list[tuple[int, int, bytes]],
        size_overrides: dict[int, int],
    ) -> bytes:
        """Apply a set of (start, end, new_bytes) byte-range replacements to
        `data`, then rewrite every TOC entry to point at its data's new
        location. Byte ranges outside `edits` -- including data that falls
        between records and isn't covered by any TOC entry -- are carried
        over unchanged.
        """
        edits = sorted(edits)
        out = bytearray()
        cursor = 0
        for start, end, new_bytes in edits:
            out += data[cursor:start]
            out += new_bytes
            cursor = end
        out += data[cursor:]

        def shifted(offset: int) -> int:
            shift = 0
            for start, end, new_bytes in edits:
                if offset >= end:
                    shift += len(new_bytes) - (end - start)
                elif offset >= start:
                    return start + shift
            return offset + shift

        for index, (offset, size) in self.records.items():
            new_size = size_overrides.get(index, size)
            pos = index * TOC_ENTRY_SIZE
            out[pos + 4 : pos + 7] = _pack_be24(new_size)
            out[pos + 7 : pos + 10] = _pack_be24(shifted(offset))
        return bytes(out)


class Charset:
    """The character table at the start of record 0: a frequency-ordered
    list of Unicode code points. Each also has a 1-byte fold/key value used
    by the engine's key-prediction tables, which this tool doesn't need to
    interpret, so the whole header is kept verbatim for rebuilding.
    """

    HEADER_SIZE = 4  # u16 (unused) + u16BE region size, before the value table

    def __init__(self, values: list[int], header_bytes: bytes):
        self.values = values
        self.index_of = {value: index for index, value in enumerate(values)}
        self._header_bytes = header_bytes

    @classmethod
    def parse(cls, data: bytes, record_offset: int) -> tuple["Charset", int]:
        region_size = struct.unpack_from(">H", data, record_offset + 2)[0]
        count = region_size // 3
        values = [
            struct.unpack_from(">H", data, record_offset + 4 + i * 2)[0]
            for i in range(count)
        ]
        graph_offset = record_offset + cls.HEADER_SIZE + region_size
        header_bytes = data[record_offset:graph_offset]
        return cls(values, header_bytes), graph_offset

    def to_bytes(self) -> bytes:
        return self._header_bytes


# --- DAWG node encoding -----------------------------------------------------
#
# A node's first byte's high nibble selects a "flag class" from a 16-entry
# table (found at 0x80211128 in 00000001.app); the low nibble is a character
# index (0xF means "extended": the real index is in the next byte, plus 15).
# The flag class says which of {child, sibling, terminal} the node has, and
# whether the child/sibling links are explicit pointers or implicit (i.e.
# the linked node sits immediately after this one's encoded bytes).

_FLAG_HAS_CHILD = 0x01
_FLAG_CHILD_EXPLICIT = 0x02
_FLAG_HAS_SIBLING = 0x04
_FLAG_SIBLING_EXPLICIT = 0x08
_FLAG_TERMINAL = 0x10

_NODE_FLAGS = [
    0x10, 0x01, 0x03, 0x14, 0x05, 0x07, 0x1C, 0x0D,
    0x0F, 0x11, 0x13, 0x15, 0x17, 0x1D, 0x1F, 0x35,
]

# Reverse map: (child_state, sibling_state, terminal) -> flag-class high
# nibble, where each state is "none", "implicit" (0 bytes, the linked cell
# is physically adjacent) or "explicit" (a pointer is written). A cell with
# no child is always terminal -- a dead end that isn't some word's end
# would serve no purpose -- so that's the only shape missing a "none, none,
# False" and "none, X, False" entry.
_FLAG_CLASS_FOR_SHAPE = {
    ("none", "none", True): 0x0,
    ("implicit", "none", False): 0x1,
    ("explicit", "none", False): 0x2,
    ("none", "implicit", True): 0x3,
    ("implicit", "implicit", False): 0x4,
    ("explicit", "implicit", False): 0x5,
    ("none", "explicit", True): 0x6,
    ("implicit", "explicit", False): 0x7,
    ("explicit", "explicit", False): 0x8,
    ("implicit", "none", True): 0x9,
    ("explicit", "none", True): 0xA,
    ("implicit", "implicit", True): 0xB,
    ("explicit", "implicit", True): 0xC,
    ("implicit", "explicit", True): 0xD,
    ("explicit", "explicit", True): 0xE,
    # idx15 (0x35) is a rarely-used alias of ("implicit", "implicit", True)
    # with one extra bit our decoder never inspects; we never emit it.
}


def _encode_pointer(distance: int) -> bytes:
    """A forward, node-relative pointer: 2 bytes if it fits under 0x8000,
    otherwise a 3-byte form with the top bit set and a +0x8000 bias.
    """
    if distance < 0x8000:
        return struct.pack(">H", distance)
    biased = distance - 0x8000
    return bytes([0x80 | (biased >> 16), (biased >> 8) & 0xFF, biased & 0xFF])


def _pointer_width(distance: int) -> int:
    return 2 if distance < 0x8000 else 3


class DawgReader:
    """Walks an on-disk DAWG using the engine's own node format (ported from
    the Zi8DAWG*/zz_800bf5d8_ family of functions) to recover every word.
    """

    def __init__(self, data: bytes, charset: Charset, graph_offset: int):
        self.data = data
        self.charset = charset
        self.graph_offset = graph_offset

    def words(self) -> list[str]:
        result: list[str] = []
        self._walk(self.graph_offset, "", result)
        return result

    def _flags(self, node_offset: int) -> int:
        return _NODE_FLAGS[self.data[node_offset] >> 4]

    def _char_index(self, node_offset: int) -> int:
        data = self.data
        if (data[node_offset] & 0xF) == 0xF:
            return data[node_offset + 1] + 15
        return data[node_offset] & 0xF

    def _is_terminal(self, node_offset: int) -> bool:
        return bool(self._flags(node_offset) & _FLAG_TERMINAL)

    def _read_pointer(self, offset: int) -> int:
        data = self.data
        if (data[offset] & 0x80) == 0:
            return (data[offset] << 8) | data[offset + 1]
        return (
            ((data[offset] & 0x7F) << 16)
            + (data[offset + 1] << 8)
            + 0x8000
            + data[offset + 2]
        )

    def _first_child(self, node_offset: int):
        data = self.data
        flags = self._flags(node_offset)
        if not (flags & _FLAG_HAS_CHILD):
            return None
        char_width = 2 if (data[node_offset] & 0xF) == 0xF else 1
        pointer_offset = node_offset + char_width
        if flags & _FLAG_CHILD_EXPLICIT:
            return node_offset + self._read_pointer(pointer_offset)
        distance = char_width
        if flags & _FLAG_SIBLING_EXPLICIT:
            # The sibling pointer occupies the slot before the (implicit)
            # child, so skip over it first.
            distance += 3 if (data[pointer_offset] & 0x80) else 2
        return node_offset + distance

    def _next_sibling(self, node_offset: int):
        data = self.data
        flags = self._flags(node_offset)
        if not (flags & _FLAG_HAS_SIBLING):
            return None
        if flags & _FLAG_SIBLING_EXPLICIT:
            char_width = 2 if (data[node_offset] & 0xF) == 0xF else 1
            pointer_offset = node_offset + char_width
            if flags & _FLAG_CHILD_EXPLICIT:
                pointer_offset += 3 if (data[pointer_offset] & 0x80) else 2
            return node_offset + self._read_pointer(pointer_offset)
        # Implicit sibling: it sits right after this node's own subtree, so
        # walk forward counting nested implicit children/siblings until we
        # return to this node's depth.
        depth = 0
        cursor = node_offset
        advance = 0
        while True:
            cursor_flags = self._flags(cursor)
            if (data[cursor] & 0xF) == 0xF:
                cursor += 2
                advance += 2
            else:
                cursor += 1
                advance += 1
            if cursor_flags & _FLAG_HAS_CHILD:
                if cursor_flags & _FLAG_CHILD_EXPLICIT:
                    step = 3 if (data[cursor] & 0x80) else 2
                    cursor += step
                    advance += step
                else:
                    depth += 1
            if not (cursor_flags & _FLAG_HAS_SIBLING):
                depth -= 1
            elif cursor_flags & _FLAG_SIBLING_EXPLICIT:
                step = 3 if (data[cursor] & 0x80) else 2
                cursor += step
                advance += step
                depth -= 1
            if depth <= 0:
                break
        return node_offset + advance

    def _walk(self, node_offset, prefix: str, result: list[str]) -> None:
        while node_offset is not None:
            char_index = self._char_index(node_offset)
            if char_index >= len(self.charset.values):
                break
            word = prefix + chr(self.charset.values[char_index])
            if self._is_terminal(node_offset):
                result.append(word)
            child = self._first_child(node_offset)
            if child is not None:
                self._walk(child, word, result)
            node_offset = self._next_sibling(node_offset)


class _TrieNode:
    __slots__ = ("char_index", "terminal", "children")

    def __init__(self, char_index: int):
        self.char_index = char_index
        self.terminal = False
        self.children: dict[int, "_TrieNode"] = {}


class _DawgCell:
    """One physical node of the encoded graph: a character, a terminal
    flag, and links to its first child and next sibling. Distinct trie
    nodes collapse onto the same cell once minification finds their
    child/sibling subtrees to be identical (suffix sharing) -- that's what
    turns a plain trie into a true DAWG.
    """

    __slots__ = ("char_index", "terminal", "child", "sibling", "offset", "size")

    def __init__(self, char_index: int, terminal: bool, child, sibling):
        self.char_index = char_index
        self.terminal = terminal
        self.child = child
        self.sibling = sibling
        self.offset = 0
        self.size = 0


class Dawg:
    """Builds a Zi-compatible word graph from a flat list of words."""

    def __init__(self, root_cell, cell_count: int):
        self.root_cell = root_cell
        self.cell_count = cell_count

    @classmethod
    def build(
        cls, words: list[str], charset: Charset, minify: bool = True
    ) -> tuple["Dawg", list[str]]:
        trie, skipped = cls._build_trie(words, charset)
        root_cell = cls._trie_to_cells(trie)
        if minify:
            root_cell = cls._minify(root_cell)
        order, _, _ = cls._plan_layout(root_cell)
        return cls(root_cell, len(order)), skipped

    @staticmethod
    def _build_trie(
        words: list[str], charset: Charset
    ) -> tuple[_TrieNode, list[str]]:
        root = _TrieNode(-1)
        skipped: list[str] = []
        for word in words:
            try:
                indices = [charset.index_of[ord(c)] for c in word]
            except KeyError:
                skipped.append(word)
                continue
            node = root
            for index in indices:
                node = node.children.setdefault(index, _TrieNode(index))
            node.terminal = True
        return root, skipped

    @staticmethod
    def _trie_to_cells(trie_node: _TrieNode):
        def chain(children: dict[int, _TrieNode]):
            head = previous = None
            for child in children.values():
                cell = _DawgCell(
                    child.char_index, child.terminal, chain(child.children), None
                )
                if previous is None:
                    head = cell
                else:
                    previous.sibling = cell
                previous = cell
            return head

        return chain(trie_node.children)

    @staticmethod
    def _minify(entry):
        """Merge cells with identical (char, terminal, child, sibling), i.e.
        identical sub-DAWGs, so shared suffixes are stored once. Cells are
        processed children/siblings-first so their links are already
        canonical by the time each cell itself is considered.
        """
        if entry is None:
            return None
        post_order = []
        visited = set()
        stack = [entry]
        while stack:
            cell = stack.pop()
            if cell is None or id(cell) in visited:
                continue
            visited.add(id(cell))
            post_order.append(cell)
            stack.append(cell.child)
            stack.append(cell.sibling)

        canonical: dict[tuple, _DawgCell] = {}
        replacement: dict[int, _DawgCell] = {}
        for cell in reversed(post_order):
            cell.child = replacement.get(id(cell.child), cell.child)
            cell.sibling = replacement.get(id(cell.sibling), cell.sibling)
            key = (
                cell.char_index,
                cell.terminal,
                id(cell.child) if cell.child else 0,
                id(cell.sibling) if cell.sibling else 0,
            )
            replacement[id(cell)] = canonical.setdefault(key, cell)
        return replacement[id(entry)]

    @staticmethod
    def _plan_layout(entry):
        """Decide an emission order, plus which child/sibling edges become
        implicit (0 bytes, physically adjacent) versus explicit (a written
        pointer).

        The format only encodes forward, unsigned distances, so a cell may
        only be placed once every one of its referrers has already been
        emitted -- and only ONE of a (possibly shared) cell's referrers can
        claim the "immediately adjacent" implicit slot; every other
        referrer must use an explicit pointer.

        This runs a variant of Kahn's algorithm: a cell becomes "ready"
        once all its incoming child/sibling edges have been accounted for.
        Whenever advancing through a ready cell frees up its child and/or
        sibling, the child is preferred as the implicit continuation
        (mirroring how Zi's own dictionaries favour implicit child links
        over implicit sibling links); anything not claimed as implicit is
        queued for later placement via an explicit pointer.
        """
        implicit_child: set[int] = set()
        implicit_sibling: set[int] = set()
        if entry is None:
            return [], implicit_child, implicit_sibling

        pending: dict[int, int] = {id(entry): 0}
        stack = [entry]
        seen = {id(entry)}
        while stack:
            cell = stack.pop()
            for target in (cell.child, cell.sibling):
                if target is None:
                    continue
                pending[id(target)] = pending.get(id(target), 0) + 1
                if id(target) not in seen:
                    seen.add(id(target))
                    stack.append(target)

        order: list[_DawgCell] = []
        placed: set[int] = set()
        ready_stack = [entry]

        def resolve(target) -> bool:
            pending[id(target)] -= 1
            return pending[id(target)] == 0

        while ready_stack:
            cell = ready_stack.pop()
            while cell is not None and id(cell) not in placed:
                placed.add(id(cell))
                order.append(cell)

                next_cell = None
                if cell.child is not None:
                    if resolve(cell.child) and id(cell.child) not in placed:
                        implicit_child.add(id(cell))
                        next_cell = cell.child
                if cell.sibling is not None:
                    if resolve(cell.sibling) and id(cell.sibling) not in placed:
                        if next_cell is None:
                            implicit_sibling.add(id(cell))
                            next_cell = cell.sibling
                        else:
                            ready_stack.append(cell.sibling)
                cell = next_cell

        return order, implicit_child, implicit_sibling

    def to_bytes(self) -> bytes:
        if self.root_cell is None:
            return b""
        order, implicit_child, implicit_sibling = self._plan_layout(self.root_cell)

        def link_state(cell: _DawgCell, target, implicit_ids: set[int]) -> str:
            if target is None:
                return "none"
            return "implicit" if id(cell) in implicit_ids else "explicit"

        def char_field_width(cell: _DawgCell) -> int:
            return 1 if cell.char_index < 15 else 2

        for cell in order:
            cell.size = char_field_width(cell)
            if link_state(cell, cell.child, implicit_child) == "explicit":
                cell.size += 2
            if link_state(cell, cell.sibling, implicit_sibling) == "explicit":
                cell.size += 2

        # Explicit pointer width depends on inter-cell distance, which
        # depends on cell size -- iterate to a fixed point. Implicit links
        # need no such loop: by construction (see _plan_layout) their
        # target is always the very next cell in `order`, so their offsets
        # already agree once cumulative offsets are assigned below.
        changed = True
        while changed:
            offset = 0
            for cell in order:
                cell.offset = offset
                offset += cell.size
            changed = False
            for cell in order:
                size = char_field_width(cell)
                if link_state(cell, cell.child, implicit_child) == "explicit":
                    size += _pointer_width(cell.child.offset - cell.offset)
                if link_state(cell, cell.sibling, implicit_sibling) == "explicit":
                    size += _pointer_width(cell.sibling.offset - cell.offset)
                if size != cell.size:
                    cell.size = size
                    changed = True

        out = bytearray()
        for cell in order:
            child_state = link_state(cell, cell.child, implicit_child)
            sibling_state = link_state(cell, cell.sibling, implicit_sibling)
            flag_class = _FLAG_CLASS_FOR_SHAPE[(child_state, sibling_state, cell.terminal)]
            if cell.char_index < 15:
                out.append((flag_class << 4) | cell.char_index)
            else:
                out.append((flag_class << 4) | 0xF)
                out.append(cell.char_index - 15)
            if child_state == "explicit":
                out += _encode_pointer(cell.child.offset - cell.offset)
            if sibling_state == "explicit":
                out += _encode_pointer(cell.sibling.offset - cell.offset)
        return bytes(out)


class ZsdDictionary:
    """A Wii eZiText static dictionary (.zsd): a word list compressed into a
    DAWG, a profanity blocklist, and a handful of unrelated tables
    (component/property data, a build-stamp footer) that travel along for
    the ride unmodified.
    """

    def __init__(self, data: bytes):
        self.data = data
        self.toc = Toc.parse(data)
        self._record_offset, self._record_size = self.toc.records[DICTIONARY_RECORD]
        self.charset, self.graph_offset = Charset.parse(data, self._record_offset)

    @classmethod
    def load(cls, path) -> "ZsdDictionary":
        return cls(Path(path).read_bytes())

    def extract_words(self) -> list[str]:
        reader = DawgReader(self.data, self.charset, self.graph_offset)
        return [w for w in reader.words() if not WATERMARK_PATTERN.match(w)]

    def read_blocklist(self) -> list[str]:
        """Record 4's TOC size field is an entry COUNT, not a byte size,
        followed by that many length-prefixed Latin-1 strings. The final
        entry is always the Zi build watermark.
        """
        offset, count = self.toc.records[BLOCKLIST_RECORD]
        entries = []
        cursor = offset
        for _ in range(count):
            length = self.data[cursor]
            entries.append(self.data[cursor + 1 : cursor + 1 + length].decode("latin-1"))
            cursor += 1 + length
        return entries

    def _blocklist_byte_range(self) -> tuple[int, int]:
        offset, count = self.toc.records[BLOCKLIST_RECORD]
        cursor = offset
        for _ in range(count):
            cursor += 1 + self.data[cursor]
        return offset, cursor

    @staticmethod
    def _encode_blocklist(entries: list[str]) -> bytes:
        out = bytearray()
        for entry in entries:
            encoded = entry.encode("latin-1")
            if len(encoded) > 255:
                raise ValueError(f"blocklist entry too long: {entry!r}")
            out.append(len(encoded))
            out += encoded
        return bytes(out)

    def with_blocklist(self, entries: list[str]) -> bytes:
        """Return a new .zsd with only the blocklist (record 4) replaced;
        every other byte, including the word DAWG, is untouched.
        """
        start, end = self._blocklist_byte_range()
        new_bytes = self._encode_blocklist(entries)
        edits = [(start, end, new_bytes)]
        size_overrides = {BLOCKLIST_RECORD: len(entries)}
        return self.toc.patched(self.data, edits, size_overrides)

    def rebuild(
        self,
        words: list[str],
        blocklist: list[str] | None = None,
        minify: bool = True,
    ) -> tuple[bytes, int, list[str]]:
        """Return a new .zsd with record 0 (and optionally record 4)
        replaced; every other table is preserved byte-for-byte.
        """
        dawg, skipped = Dawg.build(words, self.charset, minify=minify)
        new_record0 = self.charset.to_bytes() + dawg.to_bytes()

        edits = [
            (self._record_offset, self._record_offset + self._record_size, new_record0)
        ]
        size_overrides = {DICTIONARY_RECORD: len(new_record0)}

        if blocklist is not None:
            start, end = self._blocklist_byte_range()
            edits.append((start, end, self._encode_blocklist(blocklist)))
            size_overrides[BLOCKLIST_RECORD] = len(blocklist)

        new_data = self.toc.patched(self.data, edits, size_overrides)
        return new_data, dawg.cell_count, skipped


# =============================================================================
# .znd - auxiliary ("OEM") dictionary
#
# Format and original Python 2 reader/writer: megazig (2009). Ported to
# Python 3 below; the on-disk layout is unchanged.
# =============================================================================


class ZndDictionary:
    """A flat array of UTF-16BE strings.

    Layout (all integers big-endian):
        u32 count
        count * u32 offset      -- byte offset of each string from file start
        for each entry: UTF-16 code units, terminated by U+0000
        the file is then padded with U+0000 to a 0x20-byte boundary
    """

    def __init__(self, words: list[str]):
        self.words = words

    @classmethod
    def load(cls, path) -> "ZndDictionary":
        return cls.from_bytes(Path(path).read_bytes())

    @classmethod
    def from_bytes(cls, data: bytes) -> "ZndDictionary":
        (count,) = struct.unpack_from(">I", data, 0)
        offsets = struct.unpack_from(f">{count}I", data, 4)
        words = []
        for offset in offsets:
            terminator = data.find(b"\x00\x00", offset)
            end = terminator if terminator != -1 else len(data)
            words.append(data[offset:end].decode("utf-16-be"))
        return cls(words)

    def to_bytes(self) -> bytes:
        out = bytearray()
        count = len(self.words)
        out += struct.pack(">I", count)

        position = 4 + count * 4
        offsets = []
        for word in self.words:
            offsets.append(position)
            position += len(word) * 2 + 2
        for offset in offsets:
            out += struct.pack(">I", offset)

        for word in self.words:
            out += word.encode("utf-16-be")
            out += b"\x00\x00"

        while len(out) % 0x20:
            out += b"\x00\x00"
        return bytes(out)

    def save(self, path) -> None:
        Path(path).write_bytes(self.to_bytes())

    @classmethod
    def load_text(cls, path) -> "ZndDictionary":
        with open(path, encoding="utf-8") as f:
            return cls([line.rstrip("\n") for line in f])

    def save_text(self, path) -> None:
        with open(path, "w", encoding="utf-8") as f:
            for word in self.words:
                f.write(word + "\n")


# =============================================================================
# .atd - ATOK Japanese dictionary
# =============================================================================
#
# Japanese titles swap the Zi engine for JustSystems' ATOK ("ATOK Engine
# Ver00.12"). It loads three .atd files (parallel to the Latin .zsd/.znd):
#
#   AtokNintendo.atd  magic b"ATAD"      Nintendo custom game-term dictionary.
#   AtokApot.atd      magic 0x800D0002   prediction dictionary (JP-only).
#   AtokSystem.atd    magic 0xE00A0001   main system dictionary (character trie).
#
# All three store Shift-JIS text keyed by half-width-katakana readings. Format
# reverse engineered from the ATOK engine in the title's 00000001.app (Ghidra,
# PowerPC) plus direct analysis of the files. Entries are (reading, surface) pairs.
#
# AtokSystem is NOT compressed: it is a character-indexed trie whose nodes the
# engine reads by byte offset (no inflate step). Its runtime node format is fully
# reversed (see atok_system_notes.py) - node = [u16 type][u16 child_count]
# [(u16 edge, u16 child)...], plus a [char][3-byte] child table; readings are
# front-coded half-width katakana decoded to hiragana via KANA_TO_HIRAGANA below.
# What remains for a full System extractor is the on-disk -> in-RAM structure
# build (the `data` base the engine walks is assembled at load, not a raw file
# slice), so `atd extract` on System raises for now. The reading decoder is
# exposed here and verified.

# Shift-JIS byte classes.
def _sj_kana(b: int) -> bool:   # half-width katakana (single byte)
    return 0xA1 <= b <= 0xDF


def _sj_lead(b: int) -> bool:   # double-byte lead
    return 0x81 <= b <= 0x9F or 0xE0 <= b <= 0xEF


def _sj_trail(b: int) -> bool:  # double-byte trail
    return 0x40 <= b <= 0x7E or 0x80 <= b <= 0xFC


_HAS_JP = re.compile(r"[一-鿿぀-ヿ]").search


def _jp_start(ch: str) -> bool:  # kanji, hiragana or katakana
    return ("一" <= ch <= "鿿") or ("぀" <= ch <= "ヿ") or ("ｦ" <= ch <= "ﾝ")


# Half-width katakana byte -> full-width hiragana SJIS code, used by AtokSystem's
# reading decoder. Extracted & verified from the engine table at 0x80255BF8
# (index = (byte - 0xA6) * 2). See atok_system_notes.py for the full trie format.
KANA_TO_HIRAGANA = {
    0xa6: 0x82f0, 0xa7: 0x829f, 0xa8: 0x82a1, 0xa9: 0x82a3, 0xaa: 0x82a5,
    0xab: 0x82a7, 0xac: 0x82e1, 0xad: 0x82e3, 0xae: 0x82e5, 0xaf: 0x82c1,
    0xb0: 0x815b, 0xb1: 0x82a0, 0xb2: 0x82a2, 0xb3: 0x82a4, 0xb4: 0x82a6,
    0xb5: 0x82a8, 0xb6: 0x82a9, 0xb7: 0x82ab, 0xb8: 0x82ad, 0xb9: 0x82af,
    0xba: 0x82b1, 0xbb: 0x82b3, 0xbc: 0x82b5, 0xbd: 0x82b7, 0xbe: 0x82b9,
    0xbf: 0x82bb, 0xc0: 0x82bd, 0xc1: 0x82bf, 0xc2: 0x82c2, 0xc3: 0x82c4,
    0xc4: 0x82c6, 0xc5: 0x82c8, 0xc6: 0x82c9, 0xc7: 0x82ca, 0xc8: 0x82cb,
    0xc9: 0x82cc, 0xca: 0x82cd, 0xcb: 0x82d0, 0xcc: 0x82d3, 0xcd: 0x82d6,
    0xce: 0x82d9, 0xcf: 0x82dc, 0xd0: 0x82dd, 0xd1: 0x82de, 0xd2: 0x82df,
    0xd3: 0x82e0, 0xd4: 0x82e2, 0xd5: 0x82e4, 0xd6: 0x82e6, 0xd7: 0x82e7,
    0xd8: 0x82e8, 0xd9: 0x82e9, 0xda: 0x82ea, 0xdb: 0x82eb, 0xdc: 0x82ed,
    0xdd: 0x82f1, 0xde: 0x814a, 0xdf: 0x814b,
}


def kana_reading_to_hiragana(kana: bytes) -> str:
    """Half-width-katakana reading (with 0xDE/0xDF combiners) -> hiragana.

    Reimplements the reading half of the ATOK record decoder zz_800ee440_.
    """
    out = bytearray()
    i = 0
    while i < len(kana):
        code = KANA_TO_HIRAGANA.get(kana[i])
        if code is None:
            i += 1
            continue
        hi, lo = code >> 8, code & 0xFF
        nxt = kana[i + 1] if i + 1 < len(kana) else 0
        if nxt == 0xDE:                       # dakuten
            if kana[i] == 0xB3:               # う + ゛ -> ヴ (the one katakana case)
                hi, lo = 0x83, 0x94
            else:
                lo += 1
            i += 1
        elif nxt == 0xDF:                     # handakuten
            lo += 2
            i += 1
        out += bytes([hi, lo])
        i += 1
    return out.decode("shift_jis", "replace")


class AtdDictionary:
    """An ATOK .atd dictionary; variant auto-detected from the magic."""

    NINTENDO, APOT, SYSTEM = "nintendo", "apot", "system"

    def __init__(self, data: bytes):
        self.data = data
        if data[:4] == b"ATAD":
            self.variant = self.NINTENDO
        elif data[:2] == b"\x80\x0d":
            self.variant = self.APOT
        elif data[:2] == b"\xe0\x0a":
            self.variant = self.SYSTEM
        else:
            raise ValueError(f"unknown .atd magic: {data[:4]!r}")

    @classmethod
    def load(cls, path) -> "AtdDictionary":
        return cls(Path(path).read_bytes())

    def extract(self) -> list[tuple[str, str]]:
        """Return (reading, surface) pairs."""
        if self.variant == self.NINTENDO:
            return self._extract_nintendo()
        if self.variant == self.APOT:
            return self._extract_apot()
        raise NotImplementedError(
            "AtokSystem.atd is a character-indexed trie (not compressed). Its "
            "runtime node format is reversed (see atok_system_notes.py) and the "
            "reading decoder kana_reading_to_hiragana() is available, but the "
            "on-disk->RAM structure build is not yet reimplemented, so full "
            "extraction is not wired up."
        )

    # -- AtokNintendo.atd -----------------------------------------------------
    # Records from 0x2DA: [reading-len:1][reading HW-kana][surface SJIS][POS/freq
    # trailer 1-2 B], sorted by reading. Anchored on the length prefix.
    def _extract_nintendo(self) -> list[tuple[str, str]]:
        d = self.data
        out: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        i, n = 0x2DA, len(d)
        while i < n - 1:
            L = d[i]
            if 1 <= L <= 24 and i + 1 + L <= n and all(_sj_kana(b) for b in d[i + 1:i + 1 + L]):
                reading = d[i + 1:i + 1 + L]
                j = i + 1 + L
                sb = bytearray()
                while j < n - 1:
                    b = d[j]
                    if _sj_lead(b) and _sj_trail(d[j + 1]):
                        sb += d[j:j + 2]; j += 2
                    elif 0x30 <= b <= 0x7A and not _sj_kana(b):
                        sb.append(b); j += 1
                    else:
                        break
                pair = (reading.decode("shift_jis", "replace"),
                        sb.decode("shift_jis", "replace"))
                if pair not in seen:
                    seen.add(pair); out.append(pair)
                i = max(j, i + 1)
            else:
                i += 1
        return out

    # -- AtokApot.atd ---------------------------------------------------------
    # (1) recursive trie: kana jump-table @0x37D38 -> nodes; node = [u32 count]
    #     [count x 8-byte entry], entry = [4B reading-key][4B pointer]; pointer
    #     -> child node or surface record [flag][kana-suffix][SJIS surface].
    #     Yields exact readings (path kana + record suffix).
    # (2) flat candidate pool (0xE3000..end): [reading-suffix kana][surface]
    #     runs; full surface coverage with an approximate (suffix) reading.
    def _extract_apot(self) -> list[tuple[str, str]]:
        d = self.data
        u32 = lambda o: struct.unpack(">I", d[o:o + 4])[0]
        TRIE_LO, TRIE_HI, FILE_HI = 0x37D00, 0xEC900, len(d)

        jt: list[tuple[int, int]] = []
        o = 0x37D38
        while o + 4 <= 0x37E00:
            c = d[o]
            ptr = (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3]
            if not (0xA0 <= c <= 0xDF and 0x38000 < ptr < 0xEC000):
                break
            jt.append((c, ptr)); o += 4

        def looks_node(off: int) -> bool:
            if off < TRIE_LO or off >= TRIE_HI:
                return False
            cnt = u32(off)
            return 1 <= cnt <= 4000 and off + 4 + cnt * 8 <= FILE_HI

        def surf_at(sp: int) -> tuple[bytes, bytes]:
            end = sp + 24
            q = sp + 1
            suf = bytearray()
            while q < end and _sj_kana(d[q]):
                suf.append(d[q]); q += 1
            surf = bytearray()
            while q < end - 1:
                if _sj_lead(d[q]) and _sj_trail(d[q + 1]):
                    surf += d[q:q + 2]; q += 2
                elif _sj_kana(d[q]):
                    surf.append(d[q]); q += 1
                else:
                    break
            return bytes(suf), bytes(surf)

        exact: dict[str, str] = {}
        sys.setrecursionlimit(100000)

        def walk(off: int, prefix: bytes, depth: int) -> None:
            if depth > 12 or not looks_node(off):
                return
            cnt = u32(off)
            p = off + 4
            for _ in range(cnt):
                if p + 8 > FILE_HI:
                    break
                key = d[p:p + 4]
                sptr = u32(p + 4) & 0xFFFFFF
                p += 8
                rk = prefix + bytes(b for b in key[1:] if _sj_kana(b))
                if looks_node(sptr):
                    walk(sptr, rk, depth + 1)
                else:
                    suf, surf = surf_at(sptr)
                    if surf:
                        try:
                            exact[surf.decode("shift_jis")] = (rk + suf).decode("shift_jis")
                        except UnicodeDecodeError:
                            pass

        for c, off in jt:
            walk(off, bytes([c]), 0)

        flatw: dict[str, str] = {}
        i, cur = 0xE3000, bytearray()
        while i < FILE_HI - 1:
            b = d[i]
            if _sj_lead(b) and _sj_trail(d[i + 1]):
                cur += d[i:i + 2]; i += 2
            elif _sj_kana(b):
                cur.append(b); i += 1
            else:
                if len(cur) >= 2:
                    try:
                        s = cur.decode("shift_jis")
                        k = 0
                        while k < len(s) and "｡" <= s[k] <= "ﾟ":
                            k += 1
                        # surface must start with a kanji/kana; a leading
                        # punctuation char means we caught binary noise.
                        if s[k:] and _jp_start(s[k]):
                            flatw.setdefault(s[k:], s[:k])
                    except UnicodeDecodeError:
                        pass
                cur = bytearray(); i += 1

        return [(exact.get(s) or flatw.get(s, ""), s)
                for s in sorted(set(flatw) | set(exact))
                if _jp_start(s[0])]


# =============================================================================
# CLI
# =============================================================================


def _write_words(words: list[str], path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for word in words:
            f.write(word + "\n")


def _read_words(path) -> list[str]:
    with open(path, encoding="utf-8") as f:
        return [line.rstrip("\n") for line in f if line.strip("\n")]


def cmd_zsd_extract(args: argparse.Namespace) -> None:
    zsd = ZsdDictionary.load(args.input)
    words = zsd.extract_words()
    _write_words(words, args.output)
    print(f"{args.input}: extracted {len(words)} words -> {args.output}")


def cmd_zsd_build(args: argparse.Namespace) -> None:
    zsd = ZsdDictionary.load(args.input)
    words = _read_words(args.words)
    blocklist = _read_words(args.blocklist) if args.blocklist else None
    data, cell_count, skipped = zsd.rebuild(
        words, blocklist=blocklist, minify=not args.no_minify
    )
    Path(args.output).write_bytes(data)
    print(
        f"{args.input}: {len(words)} words -> {cell_count} DAWG cells "
        f"(minify={not args.no_minify})"
    )
    print(f"{len(zsd.data)} bytes -> {len(data)} bytes -> {args.output}")
    if blocklist is not None:
        print(f"blocklist replaced: {len(blocklist)} entries")
    if skipped:
        print(f"skipped {len(skipped)} word(s) using characters outside the "
              f"charset: {skipped[:20]}")


def cmd_zsd_dump_blocklist(args: argparse.Namespace) -> None:
    zsd = ZsdDictionary.load(args.input)
    entries = zsd.read_blocklist()
    _write_words(entries, args.output)
    print(f"{args.input}: {len(entries)} blocklist entries -> {args.output}")
    print(f"final entry (build watermark): {entries[-1]!r}")


def cmd_zsd_set_blocklist(args: argparse.Namespace) -> None:
    zsd = ZsdDictionary.load(args.input)
    entries = _read_words(args.blocklist)
    data = zsd.with_blocklist(entries)
    Path(args.output).write_bytes(data)
    print(f"{args.input}: blocklist set to {len(entries)} entries -> {args.output}")


def cmd_znd_extract(args: argparse.Namespace) -> None:
    znd = ZndDictionary.load(args.input)
    znd.save_text(args.output)
    print(f"{args.input}: extracted {len(znd.words)} words -> {args.output}")


def cmd_znd_build(args: argparse.Namespace) -> None:
    znd = ZndDictionary.load_text(args.input)
    znd.save(args.output)
    print(f"{args.input}: {len(znd.words)} words -> {args.output}")


def cmd_atd_extract(args: argparse.Namespace) -> None:
    atd = AtdDictionary.load(args.input)
    pairs = atd.extract()
    if args.surfaces_only:
        _write_words([s for _, s in pairs], args.output)
    else:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write("reading\tsurface\n")
            for reading, surface in pairs:
                f.write(f"{reading}\t{surface}\n")
    exact = sum(1 for r, _ in pairs if r)
    print(f"{args.input}: extracted {len(pairs)} {atd.variant} entries "
          f"({exact} with readings) -> {args.output}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ezitext.py", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    formats = parser.add_subparsers(dest="format", required=True)

    zsd = formats.add_parser("zsd", help="static dictionary (.zsd)")
    zsd_actions = zsd.add_subparsers(dest="action", required=True)

    p = zsd_actions.add_parser("extract", help="dump every word to a text file")
    p.add_argument("input"); p.add_argument("output")
    p.set_defaults(func=cmd_zsd_extract)

    p = zsd_actions.add_parser("build", help="rebuild record 0 (and optionally the blocklist) from a word list")
    p.add_argument("input"); p.add_argument("words"); p.add_argument("output")
    p.add_argument("--blocklist", metavar="FILE", help="replace the profanity blocklist too")
    p.add_argument("--no-minify", action="store_true", help="emit a raw trie instead of a minified DAWG")
    p.set_defaults(func=cmd_zsd_build)

    p = zsd_actions.add_parser("dump-blocklist", help="export the profanity blocklist to a text file")
    p.add_argument("input"); p.add_argument("output")
    p.set_defaults(func=cmd_zsd_dump_blocklist)

    p = zsd_actions.add_parser("set-blocklist", help="replace only the profanity blocklist")
    p.add_argument("input"); p.add_argument("blocklist"); p.add_argument("output")
    p.set_defaults(func=cmd_zsd_set_blocklist)

    znd = formats.add_parser("znd", help="auxiliary dictionary (.znd)")
    znd_actions = znd.add_subparsers(dest="action", required=True)

    p = znd_actions.add_parser("extract", help="dump every word to a text file")
    p.add_argument("input"); p.add_argument("output")
    p.set_defaults(func=cmd_znd_extract)

    p = znd_actions.add_parser("build", help="build a .znd from a word list")
    p.add_argument("input"); p.add_argument("output")
    p.set_defaults(func=cmd_znd_build)

    atd = formats.add_parser("atd", help="ATOK Japanese dictionary (.atd)")
    atd_actions = atd.add_subparsers(dest="action", required=True)

    p = atd_actions.add_parser("extract", help="dump reading/surface pairs to a TSV (variant auto-detected)")
    p.add_argument("input"); p.add_argument("output")
    p.add_argument("--surfaces-only", action="store_true", help="write one surface per line instead of reading<TAB>surface")
    p.set_defaults(func=cmd_atd_extract)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except FileNotFoundError as exc:
        print(f"error: {exc.filename}: not found", file=sys.stderr)
        return 1
    except (NotImplementedError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
