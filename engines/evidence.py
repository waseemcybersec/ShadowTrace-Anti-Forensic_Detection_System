import os
from datetime import datetime, timezone
from math import log2
from pathlib import Path
from typing import Iterable, Iterator, List, Optional

import pytsk3

try:
    import pyewf
except ImportError:  # pragma: no cover - optional dependency
    pyewf = None

SUPPORTED_FORENSIC_EXTENSIONS = (
    ".dd",
    ".raw",
    ".img",
    ".001",
    ".iso",
    ".bin",
) + ((".e01", ".ex01") if pyewf is not None else tuple())


class RawImageInfo(pytsk3.Img_Info):
    def __init__(self, file_obj):
        self._file_obj = file_obj
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        try:
            self._file_obj.close()
        finally:
            super().close()

    def read(self, offset, size):
        self._file_obj.seek(offset)
        return self._file_obj.read(size)

    def get_size(self):
        current = self._file_obj.tell()
        self._file_obj.seek(0, os.SEEK_END)
        size = self._file_obj.tell()
        self._file_obj.seek(current)
        return size


class EwfImageInfo(pytsk3.Img_Info):
    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        try:
            self._ewf_handle.close()
        finally:
            super().close()

    def read(self, offset, size):
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)

    def get_size(self):
        return self._ewf_handle.get_media_size()


class ForensicImageSource:
    def __init__(self, image_path):
        self.image_path = Path(image_path)
        self._image_info = None
        self._opened_resources = []

    @property
    def exists(self):
        return self.image_path.exists()

    @property
    def extension(self):
        return self.image_path.suffix.lower()

    @property
    def supported(self):
        return self.extension in SUPPORTED_FORENSIC_EXTENSIONS

    def open(self):
        if not self.exists:
            raise FileNotFoundError(f"Evidence file not found: {self.image_path}")

        if self.extension == ".e01" or self.extension == ".ex01":
            if pyewf is None:
                raise RuntimeError("EWF evidence is not supported in this environment.")
            filenames = pyewf.glob(str(self.image_path))
            ewf_handle = pyewf.handle()
            ewf_handle.open(filenames)
            self._opened_resources.append(ewf_handle)
            self._image_info = EwfImageInfo(ewf_handle)
            return self._image_info

        raw_file = open(self.image_path, "rb")
        self._opened_resources.append(raw_file)
        self._image_info = RawImageInfo(raw_file)
        return self._image_info

    def close(self):
        for resource in reversed(self._opened_resources):
            try:
                resource.close()
            except Exception:
                pass
        self._opened_resources.clear()
        self._image_info = None

    def _open_filesystem(self, image_info, offset=0):
        return pytsk3.FS_Info(image_info, offset=offset)

    def _convert_timestamp(self, value):
        if not value:
            return None
        try:
            epoch = int(value)
            utc_dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
            return {
                "epoch": epoch,
                "utc": utc_dt.strftime("%Y-%m-%d %I:%M:%S %p UTC"),
            }
        except (OverflowError, OSError, ValueError, TypeError):
            return None

    def _iter_directory(self, fs, directory, base_path="/"):
        for entry in directory:
            if not entry or not getattr(entry, "info", None):
                continue
            name_info = entry.info.name
            meta = entry.info.meta
            if not name_info:
                continue
            try:
                name = name_info.name.decode("utf-8", errors="ignore")
            except AttributeError:
                name = str(name_info.name)

            if name in (".", ".."):
                continue

            path = base_path.rstrip("/") + "/" + name if base_path != "/" else "/" + name
            yield entry, path

            if meta and meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                try:
                    child_dir = entry.as_directory()
                    yield from self._iter_directory(fs, child_dir, path)
                except Exception:
                    continue

    def _shannon_entropy(self, data):
        if not data:
            return None

        counts = {}
        for byte in data:
            counts[byte] = counts.get(byte, 0) + 1

        length = len(data)
        entropy = 0.0
        for count in counts.values():
            probability = count / length
            entropy -= probability * log2(probability)
        return entropy

    def _sample_characteristics(self, data):
        if not data:
            return {"printable_ratio": None, "null_ratio": None}

        length = len(data)
        printable_count = 0
        null_count = 0

        for byte in data:
            if byte == 0:
                null_count += 1
            if byte in (9, 10, 13) or 32 <= byte <= 126:
                printable_count += 1

        return {
            "printable_ratio": printable_count / length,
            "null_ratio": null_count / length,
        }

    def _extract_ntfs_encryption_markers(self, entry, meta):
        attr_encrypted = False
        run_encrypted = False
        efs_stream_present = False
        stream_names = []

        attr_enc_flag = int(getattr(pytsk3, "TSK_FS_ATTR_ENC", 0) or 0)
        run_enc_flag = int(getattr(pytsk3, "TSK_FS_ATTR_RUN_FLAG_ENCRYPTED", 0) or 0)

        try:
            for attr in entry:
                attr_info = getattr(attr, "info", None)
                if attr_info is None:
                    continue

                try:
                    flags = int(getattr(attr_info, "flags", 0) or 0)
                except (TypeError, ValueError):
                    flags = 0

                if attr_enc_flag and (flags & attr_enc_flag):
                    attr_encrypted = True

                raw_name = getattr(attr_info, "name", None)
                if raw_name:
                    if isinstance(raw_name, bytes):
                        name_text = raw_name.decode("utf-8", errors="ignore")
                    else:
                        name_text = str(raw_name)
                    if name_text:
                        stream_names.append(name_text)
                        if "$efs" in name_text.lower():
                            efs_stream_present = True

                for run in getattr(attr, "runs", []) or []:
                    try:
                        run_flags = int(getattr(run, "flags", 0) or 0)
                    except (TypeError, ValueError):
                        run_flags = 0
                    if run_enc_flag and (run_flags & run_enc_flag):
                        run_encrypted = True
        except Exception:
            pass

        return {
            "ntfs_attr_encrypted": attr_encrypted,
            "ntfs_run_encrypted": run_encrypted,
            "efs_stream_present": efs_stream_present,
            "stream_names": stream_names,
        }

    def _collect_partitions(self, image_info):
        try:
            volume_info = pytsk3.Volume_Info(image_info)
            partitions = [part for part in volume_info if getattr(part, "len", 0) > 0]
        except Exception:
            partitions = []
        return partitions

    def iter_partitions(self):
        image_info = self._image_info or self.open()
        partitions = self._collect_partitions(image_info)

        if not partitions:
            size_bytes = int(image_info.get_size())
            yield {
                "index": 0,
                "description": "Single volume (no partition table detected)",
                "start_sector": 0,
                "length_sectors": size_bytes // 512,
                "end_sector": (size_bytes // 512) - 1,
                "flags": 0,
                "is_allocated": True,
                "is_unallocated": False,
                "is_metadata": False,
                "has_filesystem": False,
                "filesystem_offset": 0,
                "filesystem_error": "No partition table detected",
            }
            return

        alloc_flag = int(getattr(pytsk3, "TSK_VS_PART_FLAG_ALLOC", 0) or 0)
        unalloc_flag = int(getattr(pytsk3, "TSK_VS_PART_FLAG_UNALLOC", 0) or 0)
        meta_flag = int(getattr(pytsk3, "TSK_VS_PART_FLAG_META", 0) or 0)

        for index, part in enumerate(partitions):
            try:
                flags = int(getattr(part, "flags", 0) or 0)
            except (TypeError, ValueError):
                flags = 0

            raw_desc = getattr(part, "desc", "")
            if isinstance(raw_desc, bytes):
                description = raw_desc.decode("utf-8", errors="ignore").strip()
            else:
                description = str(raw_desc).strip()

            try:
                start_sector = int(getattr(part, "start", 0) or 0)
            except (TypeError, ValueError):
                start_sector = 0

            try:
                length_sectors = int(getattr(part, "len", 0) or 0)
            except (TypeError, ValueError):
                length_sectors = 0

            end_sector = start_sector + max(length_sectors - 1, 0)
            offset = start_sector * 512
            # Avoid direct FS mount probing here. Some malformed/edge partitions can
            # trigger native crashes in pytsk3 FS_Info on Windows.
            has_filesystem = None
            fs_error = "Filesystem probing skipped for stability"

            yield {
                "index": index,
                "description": description,
                "start_sector": start_sector,
                "length_sectors": length_sectors,
                "end_sector": end_sector,
                "flags": flags,
                "is_allocated": bool(alloc_flag and (flags & alloc_flag)),
                "is_unallocated": bool(unalloc_flag and (flags & unalloc_flag)),
                "is_metadata": bool(meta_flag and (flags & meta_flag)),
                "has_filesystem": has_filesystem,
                "filesystem_offset": offset,
                "filesystem_error": fs_error,
            }

    def iter_files(self):
        image_info = self._image_info or self.open()
        partitions = [part for part in self._collect_partitions(image_info) if "Unallocated" not in str(getattr(part, "desc", ""))]

        if not partitions:
            partitions = [None]

        for partition_index, partition in enumerate(partitions):
            offset = 0 if partition is None else partition.start * 512
            try:
                fs = self._open_filesystem(image_info, offset=offset)
            except Exception:
                continue

            try:
                root_dir = fs.open_dir(path="/")
            except Exception:
                continue

            for entry, path in self._iter_directory(fs, root_dir):
                meta = getattr(entry.info, "meta", None)
                if not meta or meta.type != pytsk3.TSK_FS_META_TYPE_REG:
                    continue

                timestamps = {
                    "created": self._convert_timestamp(getattr(meta, "crtime", None)),
                    "modified": self._convert_timestamp(getattr(meta, "mtime", None)),
                    "accessed": self._convert_timestamp(getattr(meta, "atime", None)),
                    "changed": self._convert_timestamp(getattr(meta, "ctime", None)),
                }

                try:
                    size = int(getattr(meta, "size", 0) or 0)
                except (TypeError, ValueError):
                    size = 0

                sample_entropy = None
                printable_ratio = None
                null_ratio = None
                file_header = None
                if size > 0:
                    try:
                        sample_size = min(size, 65536)
                        sample = entry.read_random(0, sample_size)
                        sample_entropy = self._shannon_entropy(sample)
                        characteristics = self._sample_characteristics(sample)
                        printable_ratio = characteristics["printable_ratio"]
                        null_ratio = characteristics["null_ratio"]
                        file_header = bytes(sample[:512])
                    except Exception:
                        sample_entropy = None
                        printable_ratio = None
                        null_ratio = None
                        file_header = None

                extension = os.path.splitext(path)[1].lower()
                ntfs_markers = self._extract_ntfs_encryption_markers(entry, meta)

                name_info = getattr(entry.info, "name", None)

                try:
                    name_flags = int(getattr(name_info, "flags", 0) or 0)
                except (TypeError, ValueError):
                    name_flags = 0

                raw_entry_name = getattr(name_info, "name", None)
                if isinstance(raw_entry_name, bytes):
                    filename = raw_entry_name.decode("utf-8", errors="ignore")
                elif raw_entry_name is not None:
                    filename = str(raw_entry_name)
                else:
                    filename = path.rsplit("/", 1)[-1]

                try:
                    meta_flags = int(getattr(meta, "flags", 0) or 0)
                except (TypeError, ValueError):
                    meta_flags = 0

                yield {
                    "partition_index": partition_index,
                    "path": path,
                    "name": path.rsplit("/", 1)[-1],
                    "filename": filename,
                    "name_flags": name_flags,
                    "meta_flags": meta_flags,
                    "extension": extension,
                    "size": size,
                    "sample_entropy": sample_entropy,
                    "printable_ratio": printable_ratio,
                    "null_ratio": null_ratio,
                    "file_header": file_header,
                    "ntfs_attr_encrypted": ntfs_markers["ntfs_attr_encrypted"],
                    "ntfs_run_encrypted": ntfs_markers["ntfs_run_encrypted"],
                    "efs_stream_present": ntfs_markers["efs_stream_present"],
                    "stream_names": ntfs_markers["stream_names"],
                    "timestamps": timestamps,
                }
