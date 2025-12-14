# bromascan

bromascan helps update Broma bindings for new Geometry Dash builds without
having to manually look for everything from scratch.

It comes with a shared core and two small tools:

- **genpat** – makes pattern files from a known binary plus its bindings.
- **scanpat** – runs those patterns on another build to recover the new offsets.

## Project Layout

- `shared/` – common helpers (data types, serialization, threading).
- `genpat/` – pattern generator CLI (`genpat/main.cpp`).
- `scanpat/` – bulk pattern scanner (`scanpat/main.cpp`).

## Requirements

- CMake ≥ 3.21
- A C++23 compiler (GCC/Clang/MSVC)
- Git for CPM dependency fetching

## Build

```bash
cmake -S . -B build
cmake --build build
```

## Usage

Generate patterns:

```bash
genpat GeometryDash.22074.mac CodegenData-22074.json Patterns.imac.22074.json -p imac
```

> Note: only `imac` requires manual `-p imac` platform specification; others can
> be auto-detected, so `-p` is optional

Scan a fresh binary with those patterns:

```bash
scanpat GeometryDash.22074.exe Patterns.Win.22074.json Output.Win.22074.json
```

Add `--verbose` for extra logging. Use `--platform m1|imac|win|ios` (or `-p`) on `genpat` to override auto-detection.

You need bindings from https://github.com/geode-sdk/bindings (`.bro` definitions)
and the matching CodegenData JSON from https://prevter.github.io/bindings-meta;
both are required to merge bindings into a blank `.bro` for a newer game build.

You will also need the corresponding Geometry Dash binaries for every platform
you plan to scan.

## License

MIT License. See `LICENSE` for details.
