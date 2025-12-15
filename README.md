# bromascan

bromascan helps move Broma bindings to new Geometry Dash builds without redoing
every offset search by hand. The repo bundles a shared core plus three small CLIs:

- **genpat** – turn a known binary and its bindings into pattern files.
- **scanpat** – run those patterns on another build to recover the updated addresses.
- **broutil** – clean, format, and merge `.bro` files with scan results.

## Project Layout

- `shared/` – common helpers (data types, serialization, threading).
- `genpat/` – pattern generator CLI (`genpat/main.cpp`).
- `scanpat/` – bulk pattern scanner (`scanpat/main.cpp`).
- `broutil/` – `.bro` helper CLI (`broutil/main.cpp`).

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

> `-p imac` is only needed for that platform; other binaries auto-detect the
> platform unless you override it with `-p/--platform`.

Scan another binary with those patterns:

```bash
scanpat GeometryDash.22074.exe Patterns.Win.22074.json Output.Win.22074.json
```

broutil helpers (pick one flag):

```bash
broutil --clear input.bro cleaned.bro
broutil --append base.bro Output.Win.22074.json merged.bro
broutil --format messy.bro pretty.bro
```

Add `--verbose` to `genpat`/`scanpat` when you want extra logging.

## Data Prep

You need two matching resources for each game build:

- https://github.com/geode-sdk/bindings for the `.bro` binding definitions.
- https://prevter.github.io/bindings-meta for the `CodegenData-*.json` generated
  from those definitions.

Both files plus the target Geometry Dash binaries (one per platform you plan to
scan) let you merge newer bindings back into a clean `.bro` with `broutil`.

## License

MIT License. See `LICENSE` for details.
