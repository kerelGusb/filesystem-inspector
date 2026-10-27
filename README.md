# Filesystem Inspector

A read-only desktop viewer for ext2 and FAT32 filesystem images. Open an image to inspect structures, decoded fields, and their source bytes in HEX/ASCII.

Requires Python 3.10–3.15. On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e .
.\.venv\Scripts\python -m fs_inspector
```

On Linux or macOS, use `.venv/bin/python` instead of `.\.venv\Scripts\python`.

Choose **File → Open image** and select `fixtures/ext2_demo.img`. Expand the superblock, block group 0, root inode, `docs`, and `large.bin` to inspect its data blocks. `fixtures/ext2_features.img` also contains hard links and sparse data. Selecting a field highlights its bytes in the HEX view.

For FAT32, open `fixtures/fat32_demo.img` and expand **FAT32 boot sector → Root directory**. The example contains nested directories, long names (including Cyrillic), empty and fragmented files, and `many_entries` for pagination. Expand a file entry to inspect its data clusters. Boot fields, FSInfo, the backup boot sector, both FAT copies, and raw directory records are also available.

The ext2 profile uses 1 KiB blocks, 128-byte inodes, linear directories, and direct or single-indirect file blocks. FAT32 supports volume images starting at offset 0, 512-byte sectors, clusters from 512 bytes to 32 KiB, and one or two FAT copies. Short names use CP437; long names use UTF-16. Partition tables, other FAT formats, and deleted-file recovery are not implemented. Chain inspection is limited to 65,536 clusters and directory inspection to 1,048,576 records. Images are never modified.

After updating the project, run `python -m pip install -e .` again to refresh plugin registration.
