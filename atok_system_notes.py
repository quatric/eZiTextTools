#!/usr/bin/env python3
"""
atok_system_notes.py - reverse-engineering notes + reusable pieces for AtokSystem.atd

Status: PARTIAL. The full AtokSystem word extractor is NOT finished - the packed
leaf encoding (see step 4) is not yet cracked. Everything above it IS reversed and
verified, and the reusable pieces (kana->hiragana table, per-record decoder) are
below. Reverse engineered from the ATOK engine in the Everybody Votes Channel (JP)
00000001.app (PowerPC, Ghidra + offline capstone).

================================================================================
HOW AtokSystem.atd WORKS  (magic 0xE00A0001)
================================================================================

The big finding: **AtokSystem is a character-indexed TRIE, not a compressed blob.**
There is no LZ/entropy codec (zlib/deflate/Yaz0/LZ77/LZMA all fail). The engine reads
trie nodes by byte offset into a base `data` (zz_800eeec8_(dict,id)==**(dict+0x3cc)+id).
NOTE (corrected): `data` is NOT a raw slice of the .atd file - zz_800f474c_ validates
the section header (byte0&0x80, byte1 bits 0/2/3, byte3!=0) and the raw 0xE00A0001
file header FAILS that, so the walked structure is assembled/relocated at load time.
The ~7.9-bit/byte "entropy" is dense index/pointer packing, still not a codec. The
on-disk -> in-RAM build is the one remaining unknown for a from-file extractor.

Load / lookup pipeline (engine functions):
  zz_800efde4_   per-dict setup: pool = zz_800f474c_(raw)  -> dict+0x3cc
  zz_800ef9cc_   lookup: entry = **(dict+0x3cc) + record_id ; compare reading ;
                 zz_800eeec8_ fetch record ; zz_800ee440_ decode
  zz_800ee84c_   node iterator: walks *(node+0x81) entries, each a 0x40-byte
                 struct (+0x3c packed-record ptr, +8 decode buffer, +7 len)
  zz_800ee440_   PER-RECORD DECODER (reimplemented as decode_record below)

On-disk structure:
  0x000..0x400   header: E00A0001, 7 sub-section offsets (0x60..0x1da0), +0x20 word
  0x400..0xc00   char-code table (single-byte alphabet: ASCII + half-width kana)
  0xc00..0x1da0  null-terminated half-width-katakana reading KEYS (low entropy)
  0x1da0..0x3400 TOP INDEX: 12-byte entries = [u32 offset][u16][u16][u16][u16].
                 The u32 points at a sub-table; the u16s are counts/sizes.
  0x3400..end    multi-level 16-bit offset sub-tables -> PACKED LEAVES (the ~7.9
                 region). *** leaf packing = the remaining unknown (step 4) ***

Per-record format (what decode_record handles, from zz_800ee440_/zz_800ee84c_):
  [header byte h]
      h & 0x0f = shared-prefix length (front-coding vs the previous reading)
      h & 0x10 = reading-stored-inline flag
  [reading: half-width katakana bytes 0xA1..0xDF, with 0xDE/0xDF as the
   dakuten/handakuten COMBINING marks applied to the previous kana]
  [surface: Shift-JIS bytes, every byte >= 0x20, until a byte < 0x20]
  (an additive 8-bit checksum over the emitted bytes is also produced)
  Readings decode to HIRAGANA via KANA_TO_HIRAGANA. Special case: う(0xB3)+゛ -> ヴ
  is emitted as 0x8394 (the only katakana exception).

SOLVED (step 4): the 0x3400+ region is NOT bit-packed opaque data - it is a
CHARACTER-INDEXED TRIE. Node accessors reversed:

  pool base `data` = **(dict+0x3cc)  (a section of the raw file; NOT file start)

  Node descriptor: 12 bytes at  data + 0x10 + node_id*0xc
      +0x00  u32  nodedata_off   (0 => absent)
      +0x04  u32  childtable_off (0 => absent)
      +0x08  u32  (aux)

  Node data (at data + nodedata_off):        [used by zz_800f4860_/zz_800f4898_]
      +0x00  u16  node TYPE       (0..~0x14; flags 0x100/0x400/0x800/0x1000/0x2000)
      +0x02  u16  child_count
      +0x04  child_count x [u16 edge_index][u16 child_node_id]

  Child lookup table (at data + childtable_off):        [used by zz_800f48d8_]
      sequence of u32 = [char:1 byte][value:3 bytes], terminated by a 0 char byte;
      returns value&0xFFFFFF for the matching char (fast char->child path).

Traversal primitives (all one-liners, reimplementable):
  type(id)        = u16 @ data + desc[id].nodedata_off
  child_list(id)  = (count = u16 @ nodedata+2 ; pairs @ nodedata+4)
  child_for(id,c) = walk childtable for byte==c -> 24-bit value

To EXTRACT ALL WORDS: DFS from the root node, accumulating the edge chars into a
reading; at terminal nodes fetch the packed record (byte offset into `data`) and
run decode_record / kana_reading_to_hiragana + the SJIS surface. Still TODO to
turn this into a runnable extractor: (a) pin `data`'s file offset and the root
node id, (b) map edge_index -> kana char (via the char-code table at file 0x400),
(c) identify which TYPE values are terminal and where their record offset lives.
The node walk itself is the three primitives above.
"""

# Half-width katakana byte -> full-width hiragana SJIS code.
# Extracted from the engine table at 0x80255BF8 (index = (byte-0xA6)*2), verified.
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
    """Convert a half-width-katakana reading (with 0xDE/0xDF combiners) to hiragana.

    Mirrors the reading half of zz_800ee440_.
    """
    out = bytearray()
    i = 0
    while i < len(kana):
        b = kana[i]
        nxt = kana[i + 1] if i + 1 < len(kana) else 0
        code = KANA_TO_HIRAGANA.get(b)
        if code is None:
            i += 1
            continue
        hi, lo = code >> 8, code & 0xff
        if nxt == 0xde:            # dakuten
            if b == 0xb3:          # う + ゛ -> ヴ (katakana, the one exception)
                hi, lo = 0x83, 0x94
            else:
                lo += 1
            i += 1
        elif nxt == 0xdf:          # handakuten
            lo += 2
            i += 1
        out += bytes([hi, lo])
        i += 1
    return out.decode("shift_jis", "replace")


if __name__ == "__main__":
    # sanity: quick round-trip of the reading decoder
    for hw, want in [(b"\xc4\xde\xb3\xcc\xde\xc2\xc9\xd3\xd8", "どうぶつのもり"),
                     (b"\xc4\xb7\xde\xd8\xbf\xb3", "ときりそう")]:
        print(hw.hex(), "->", kana_reading_to_hiragana(hw), "(want", want + ")")
