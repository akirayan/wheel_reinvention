# Wheel_reinvention

**Reinventing the wheel, on purpose.**

This repository is a personal learning project written in C,  
aimed at *understanding fundamental disk, filesystem, and forensic file formats*  
by decoding them from raw binary structures.

This project does **not** aim to replace existing mature tools or libraries.  
The goal is to **take the wheel apart**, understand every spoke,  
and reassemble it by hand.

---

## Philosophy

Modern forensic and low-level tools hide enormous complexity behind stable APIs.
That is useful — but it also obscures *why things work*.

This repository exists to answer questions such as:

- Why is the MBR exactly 512 bytes?
- How does GPT really use GUIDs and CRCs?
- Why does NTFS store metadata the way it does?
- What is an EVTX template, *really*?
- Why is the Windows Registry a filesystem in disguise?

To understand these, the wheel must be reinvented.

---

## Scope

Each decoder is intentionally:

- Written in **plain C**
- Minimal and readable
- Focused on **structure understanding**, not performance
- Backed by hex dumps and offsets, not abstractions

---

## Project Structure

```text
Wheel_reinverted/
├── common/              # Shared helpers (hexdump, endian, utils)
│
├── mbr_decode/          # Master Boot Record
├── gpt_decode/          # GUID Partition Table
│
├── vbr_decode/         # NTFS internals  Volume Boot Record
├── mft_decode/         # NTFS internals  Master File Table
│
├── evtx_decode/         # Windows Event Log (.evtx)
│
├── registry_decode/     # Windows Registry hive files
│
└── docs/                # Format notes and diagrams

```


## Current Targets


## Non-Goals

This repository intentionally does not aim to:
- Be a drop-in replacement for existing tools
- Fully support corrupted or malicious inputs
- Provide high-performance parsing
- Cover every edge case

If you need production-grade tooling, use existing libraries.

If you want to understand why they work, read this code.

## References

Specifications and implementations consulted during this work include:
- Microsoft Open Specifications
- libfsntfs / libevtx / libregf
- Public reverse-engineering notes
- Hex dumps and personal experiments

All mistakes and misunderstandings are my own.

## Licebse

MIT License.

Educational purpose only.


