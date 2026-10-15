# Filesystem Inspector

A read-only desktop viewer for ext2 filesystem images. Open an image to inspect structures, decoded fields, and their source bytes in HEX/ASCII.

Requires Python 3.10–3.15. On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e .
.\.venv\Scripts\python -m fs_inspector
```

On Linux or macOS, use `.venv/bin/python` instead of `.\.venv\Scripts\python`.

Choose **File → Open image** and select `fixtures/ext2_demo.img`. Expand the superblock, block group 0, root inode, `docs`, and `large.bin` to inspect its data blocks. `fixtures/ext2_features.img` also contains hard links and sparse data. Selecting a field highlights its bytes in the HEX view.

The supported ext2 profile uses 1 KiB blocks, 128-byte inodes, linear directories, and direct or single-indirect file blocks. Other filesystem formats and ext2 features are not implemented. Images are never modified.
