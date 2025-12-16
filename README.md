# SynoXtract CLI and GUI

Synology .pat/.spk file decryption and extraction utility.

## Dependencies

- `libsodium`
- `msgpack-cxx`

## GUI  Usage

1. Run synoxtract-gui.exe.
2. File -> Open or Drag a file into the window.
3. Select files and click Select Extract, or click All Extract.
4. Check the Status Bar for progress.

## CLI Usage

```bash
# List files in archive
./synoxtract -i DSM.pat -l

# Extract all files to directory
./synoxtract -i DSM.pat -d output_dir

# Extract specific files
./synoxtract -i DSM.pat -d output_dir -f INFO
```

Inspired by:
- [patology](https://github.com/sud0woodo/patology)
- [Synology_Archive_Extractor](https://github.com/K4L0dev/Synology_Archive_Extractor)
