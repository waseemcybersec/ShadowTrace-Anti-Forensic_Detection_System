"""
Secure Deletion Detection Engine
=================================
Detects traces of secure (anti-forensic) file deletion within a forensic disk
image.  The engine operates on two complementary layers:

Layer 1 – Deleted-file metadata analysis  (via iter_files / iter_deleted_files)
    Examines files whose TSK metadata flags indicate they have been deleted
    (TSK_FS_META_FLAG_UNALLOC).  For each such file the engine runs a battery
    of heuristic rules against the residual metadata and any remaining data
    content to determine whether the deletion was performed by a secure-wipe
    tool rather than a normal OS delete.

Layer 2 – Unallocated cluster analysis  (via iter_unallocated_runs)
    Reads raw runs of unallocated disk space and checks for byte-fill patterns
    (all-zero, all-0xFF, repeating single-byte) or near-perfect randomness,
    both of which are hallmarks of multi-pass wiping algorithms (DoD 5220.22-M,
    Gutmann, etc.).

Together these layers detect:
    •  Wiping-tool artifacts  (SDelete, Eraser, BleachBit, CCleaner, cipher /w)
    •  Overwrite patterns     (zero-fill, 0xFF-fill, single-byte patterns,
                                pseudo-random overwrites)
    •  Metadata anomalies    (size > 0 but data all zeroed/randomised,
                                truncated-then-deleted sequences, timestamp
                                anomalies around deletion)
    •  Cluster-level evidence (large contiguous regions of fill patterns in
                                unallocated space)
"""

import os
import struct
from collections import Counter

from .base import AnalysisEngine
from .evidence import ForensicImageSource
from .models import AnalysisFinding, AnalysisReport

try:
    import pytsk3
except ImportError:
    pytsk3 = None


class SecureDeletionEngine(AnalysisEngine):
    module_id = "secure_deletion"
    module_name = "Secure Deletion Detection"
    MAX_REPORTED_FINDINGS = 2500

    # --------------- thresholds ---------------
    HIGH_ENTROPY_THRESHOLD = 7.92          # near-perfect randomness (8.0 = max)
    ELEVATED_ENTROPY_THRESHOLD = 7.75
    ZERO_RATIO_WIPE_THRESHOLD = 0.97       # ≥ 97 % null bytes → zero-fill wipe
    SINGLE_BYTE_RATIO_THRESHOLD = 0.97     # ≥ 97 % same byte  → pattern wipe
    MIN_SAMPLE_SIZE = 4096                  # ignore tiny remnants
    UNALLOC_BLOCK_SIZE = 1024 * 1024        # 1 MiB chunks for unallocated scan
    UNALLOC_SCAN_LIMIT = 64 * 1024 * 1024   # scan up to 64 MiB of unalloc space

    # --------------- tool signatures (found in filenames / paths) ---------------
    WIPE_TOOL_KEYWORDS = {
        "sdelete", "sdelete64", "eraser", "bleachbit", "ccleaner",
        "privazer", "dban", "nwipe", "shred", "srm", "wipe",
        "cipher", "fileshredder", "wipefile", "securedelete",
        "hdshredder", "kcleaner", "freeraser", "permadelete",
    }

    # Filenames that wipe tools leave behind as place-holders (SDelete pattern)
    SDELETE_STUB_PREFIXES = (
        "AAAAAAAAAAAAAAAAAAA",   # SDelete zero-fill stubs
        "ZZZZZZZZZZZZZZZZZZZ",  # SDelete renamed stubs
    )

    # Known wipe-tool log / config file names
    WIPE_TOOL_ARTIFACTS = {
        "eraser.log", "eraserlog.txt", "bleachbit.ini", "bleachbit.log",
        "ccleaner.ini", "ccleaner64.ini", "privazer.ini",
        "sdelete.exe", "sdelete64.exe", "cipher.log",
    }

    # --------------- helpers ---------------

    def _shannon_entropy(self, data):
        """Calculate Shannon entropy of a byte buffer (0.0 – 8.0)."""
        if not data:
            return None
        length = len(data)
        counts = Counter(data)
        entropy = 0.0
        from math import log2
        for count in counts.values():
            p = count / length
            entropy -= p * log2(p)
        return entropy

    def _byte_distribution_analysis(self, data):
        """Return a dict with detailed byte-distribution metrics."""
        if not data:
            return {
                "null_ratio": None,
                "dominant_byte": None,
                "dominant_ratio": None,
                "unique_bytes": 0,
                "is_zero_filled": False,
                "is_single_byte_filled": False,
                "is_pseudo_random": False,
            }

        length = len(data)
        counts = Counter(data)
        null_count = counts.get(0, 0)
        null_ratio = null_count / length

        dominant_byte, dominant_count = counts.most_common(1)[0]
        dominant_ratio = dominant_count / length
        unique_bytes = len(counts)

        is_zero_filled = null_ratio >= self.ZERO_RATIO_WIPE_THRESHOLD
        is_single_byte_filled = (
            dominant_ratio >= self.SINGLE_BYTE_RATIO_THRESHOLD
            and not is_zero_filled
        )

        entropy = self._shannon_entropy(data)
        is_pseudo_random = (
            entropy is not None
            and entropy >= self.HIGH_ENTROPY_THRESHOLD
            and unique_bytes >= 240            # almost every byte value present
            and dominant_ratio < 0.02          # no dominant byte
        )

        return {
            "null_ratio": null_ratio,
            "dominant_byte": dominant_byte,
            "dominant_ratio": dominant_ratio,
            "unique_bytes": unique_bytes,
            "is_zero_filled": is_zero_filled,
            "is_single_byte_filled": is_single_byte_filled,
            "is_pseudo_random": is_pseudo_random,
            "entropy": entropy,
        }

    def _detect_repeating_pattern(self, data, max_pattern_len=16):
        """Check if data consists of a repeating short pattern (e.g. 0xAA 0x55)."""
        if not data or len(data) < max_pattern_len * 2:
            return None, 0.0
        for plen in range(1, max_pattern_len + 1):
            pattern = data[:plen]
            mismatch = 0
            check_len = min(len(data), 8192)  # check first 8 KiB for speed
            for i in range(plen, check_len):
                if data[i] != pattern[i % plen]:
                    mismatch += 1
            match_ratio = 1.0 - (mismatch / (check_len - plen))
            if match_ratio >= 0.98:
                return bytes(pattern), match_ratio
        return None, 0.0

    def _check_wipe_tool_filename(self, filename, path):
        """Return list of matched wipe-tool keyword rules."""
        rules = []
        lower_name = filename.lower()
        lower_path = path.lower()

        for keyword in self.WIPE_TOOL_KEYWORDS:
            if keyword in lower_name:
                rules.append(f"wipe_tool_keyword:{keyword}")
                break

        if lower_name in self.WIPE_TOOL_ARTIFACTS:
            rules.append("wipe_tool_artifact_file")

        for prefix in self.SDELETE_STUB_PREFIXES:
            if filename.startswith(prefix):
                rules.append("sdelete_stub_filename")
                break

        # Check for cipher /w artefact naming (e.g., EFSTMPWP in path)
        if "efstmpwp" in lower_path:
            rules.append("cipher_w_temp_directory")

        return rules

    def _is_deleted_meta(self, meta_flags):
        """Check TSK meta flags for the UNALLOC (deleted) flag."""
        if pytsk3 is None:
            return False
        unalloc_flag = int(getattr(pytsk3, "TSK_FS_META_FLAG_UNALLOC", 0) or 0)
        if not unalloc_flag:
            return False
        return bool(meta_flags & unalloc_flag)

    def _is_deleted_name(self, name_flags):
        """Check TSK name flags for the UNALLOC (deleted) flag."""
        if pytsk3 is None:
            return False
        unalloc_flag = int(getattr(pytsk3, "TSK_FS_NAME_FLAG_UNALLOC", 0) or 0)
        if not unalloc_flag:
            return False
        return bool(name_flags & unalloc_flag)

    def _score_severity(self, strong_flags, weak_flags):
        if strong_flags >= 3 or (strong_flags >= 2 and weak_flags >= 2):
            return "High"
        if strong_flags >= 2 or (strong_flags >= 1 and weak_flags >= 2):
            return "Medium"
        return "Low"

    # --------------- main analysis ---------------

    def analyze(self, evidence_path, case_name, examiner):
        source = ForensicImageSource(evidence_path)
        findings = []
        total_files = 0
        suspicious_files = 0
        deleted_files_found = 0

        try:
            # ========== LAYER 1: Deleted file metadata + content analysis ==========
            for record in source.iter_files():
                total_files += 1

                path = record.get("path", "")
                name = record.get("name", "")
                filename = record.get("filename", name)
                ext = (record.get("extension") or "").lower()
                size = record.get("size", 0)
                meta_flags = record.get("meta_flags", 0)
                name_flags = record.get("name_flags", 0)
                entropy = record.get("sample_entropy")
                printable_ratio = record.get("printable_ratio")
                null_ratio = record.get("null_ratio")
                timestamps = record.get("timestamps", {})

                rules = []
                strong_flags = 0
                weak_flags = 0
                wipe_pattern = None
                byte_analysis = {}

                is_deleted = self._is_deleted_meta(meta_flags) or self._is_deleted_name(name_flags)

                # Rule 1: Wipe-tool artifact file present (deleted or not)
                tool_rules = self._check_wipe_tool_filename(filename, path)
                if tool_rules:
                    for r in tool_rules:
                        rules.append(r)
                    strong_flags += len(tool_rules)

                # The remaining rules apply mainly to deleted files
                if is_deleted:
                    deleted_files_found += 1
                    rules.append("file_metadata_marked_deleted")
                    weak_flags += 1

                    # Rule 2: Deleted file whose data area is zero-filled
                    if null_ratio is not None and null_ratio >= self.ZERO_RATIO_WIPE_THRESHOLD and size >= self.MIN_SAMPLE_SIZE:
                        rules.append("data_area_zero_filled")
                        wipe_pattern = "Zero-fill (0x00)"
                        strong_flags += 2

                    # Rule 3: Deleted file with near-perfect random data (crypto wipe)
                    elif (
                        entropy is not None
                        and entropy >= self.HIGH_ENTROPY_THRESHOLD
                        and size >= self.MIN_SAMPLE_SIZE
                        and printable_ratio is not None
                        and printable_ratio <= 0.20
                    ):
                        rules.append("data_area_pseudo_random")
                        wipe_pattern = "Pseudo-random (crypto wipe)"
                        strong_flags += 2

                    # Rule 4: Elevated entropy on deleted file (weaker signal)
                    elif (
                        entropy is not None
                        and entropy >= self.ELEVATED_ENTROPY_THRESHOLD
                        and size >= self.MIN_SAMPLE_SIZE
                        and printable_ratio is not None
                        and printable_ratio <= 0.35
                    ):
                        rules.append("data_area_elevated_entropy")
                        wipe_pattern = "Elevated entropy"
                        weak_flags += 1

                    # Rule 5: Size recorded but content wiped (size vs content mismatch)
                    if size > 0 and null_ratio is not None and null_ratio >= 0.99:
                        rules.append("size_content_mismatch")
                        strong_flags += 1

                    # Rule 6: File truncated to zero before deletion
                    if size == 0:
                        rules.append("truncated_before_deletion")
                        weak_flags += 1

                    # Rule 7: SDelete-style stub filename on deleted entry
                    for prefix in self.SDELETE_STUB_PREFIXES:
                        if filename.startswith(prefix):
                            if "sdelete_stub_filename" not in rules:
                                rules.append("sdelete_stub_filename")
                                strong_flags += 2
                            break

                    # Rule 8: Timestamp anomaly – all timestamps identical on deleted file
                    # (wipe tools often reset timestamps before unlinking)
                    ts_epochs = set()
                    for key in ("created", "modified", "accessed", "changed"):
                        ts_val = timestamps.get(key)
                        if isinstance(ts_val, dict):
                            epoch = ts_val.get("epoch")
                            if epoch is not None:
                                ts_epochs.add(epoch)
                    if len(ts_epochs) == 1 and size > 0:
                        rules.append("all_timestamps_identical_on_deleted")
                        weak_flags += 1

                    # Rule 9: Epoch-zero timestamps (1970-01-01) – strong wipe indicator
                    if 0 in ts_epochs:
                        rules.append("epoch_zero_timestamp")
                        strong_flags += 1

                # Skip if no rules triggered
                if not rules:
                    continue

                # Require at least one strong signal to reduce false positives
                if strong_flags == 0:
                    continue

                suspicious_files += 1
                severity = self._score_severity(strong_flags, weak_flags)
                confidence = min(97, 40 + (strong_flags * 16) + (weak_flags * 5))

                details = {
                    "size": size,
                    "extension": ext or "(none)",
                    "is_deleted": is_deleted,
                    "wipe_pattern": wipe_pattern,
                    "sample_entropy": round(entropy, 4) if entropy is not None else None,
                    "printable_ratio": round(printable_ratio, 4) if printable_ratio is not None else None,
                    "null_ratio": round(null_ratio, 4) if null_ratio is not None else None,
                    "partition_index": record.get("partition_index"),
                    "timestamps": timestamps,
                    "deletion_indicators": rules.copy(),
                }

                if len(findings) < self.MAX_REPORTED_FINDINGS:
                    findings.append(
                        AnalysisFinding(
                            module=self.module_name,
                            artifact=path,
                            severity=severity,
                            status="Suspicious",
                            confidence=confidence,
                            rules=rules,
                            details=details,
                        )
                    )

            # ========== LAYER 2: Unallocated cluster analysis ==========
            unalloc_findings = self._analyze_unallocated_space(source)
            for uf in unalloc_findings:
                if len(findings) < self.MAX_REPORTED_FINDINGS:
                    findings.append(uf)
                    suspicious_files += 1

        finally:
            source.close()

        summary = {
            "imageLoaded": True,
            "selectedModules": 1,
            "reportStatus": "Pending generation" if findings else "No anomalies detected",
            "totalFilesScanned": total_files,
            "suspiciousFiles": suspicious_files,
            "deletedFilesFound": deleted_files_found,
        }

        return AnalysisReport(
            case_name=case_name,
            examiner=examiner,
            image_path=str(evidence_path),
            module=self.module_name,
            findings=findings,
            summary=summary,
        )

    # --------------- Layer 2: unallocated space scanner ---------------

    def _analyze_unallocated_space(self, source):
        """Scan unallocated disk regions for wipe patterns."""
        findings = []
        image_info = source._image_info
        if image_info is None:
            return findings

        # Gather unallocated partitions / regions
        unalloc_regions = []
        try:
            partitions = source._collect_partitions(image_info)
            if not partitions:
                # No partition table – skip unallocated scan
                return findings

            if pytsk3 is None:
                return findings

            alloc_flag = int(getattr(pytsk3, "TSK_VS_PART_FLAG_ALLOC", 0) or 0)
            unalloc_flag = int(getattr(pytsk3, "TSK_VS_PART_FLAG_UNALLOC", 0) or 0)

            for idx, part in enumerate(partitions):
                try:
                    flags = int(getattr(part, "flags", 0) or 0)
                except (TypeError, ValueError):
                    flags = 0

                is_unalloc = bool(unalloc_flag and (flags & unalloc_flag))
                if not is_unalloc:
                    continue

                start = int(getattr(part, "start", 0) or 0)
                length = int(getattr(part, "len", 0) or 0)
                if length <= 0:
                    continue

                unalloc_regions.append({
                    "index": idx,
                    "offset": start * 512,
                    "size": length * 512,
                })
        except Exception:
            return findings

        # Scan each unallocated region
        for region in unalloc_regions:
            region_findings = self._scan_unallocated_region(
                image_info, region["index"], region["offset"], region["size"],
            )
            findings.extend(region_findings)

        return findings

    def _scan_unallocated_region(self, image_info, part_index, offset, size):
        """Read through an unallocated region in chunks and look for wipe patterns."""
        findings = []
        scan_size = min(size, self.UNALLOC_SCAN_LIMIT)
        block_size = self.UNALLOC_BLOCK_SIZE

        zero_filled_blocks = 0
        pattern_filled_blocks = 0
        random_filled_blocks = 0
        total_blocks = 0
        detected_patterns = set()

        pos = 0
        while pos < scan_size:
            chunk_size = min(block_size, scan_size - pos)
            try:
                data = image_info.read(offset + pos, chunk_size)
            except Exception:
                pos += block_size
                continue

            if not data or len(data) < 512:
                pos += block_size
                continue

            total_blocks += 1
            analysis = self._byte_distribution_analysis(data)

            if analysis["is_zero_filled"]:
                zero_filled_blocks += 1
                detected_patterns.add("Zero-fill (0x00)")
            elif analysis["is_single_byte_filled"]:
                pattern_filled_blocks += 1
                byte_val = analysis["dominant_byte"]
                detected_patterns.add(f"Byte-fill (0x{byte_val:02X})")
            elif analysis["is_pseudo_random"]:
                random_filled_blocks += 1
                detected_patterns.add("Pseudo-random overwrite")
            else:
                # Check for short repeating pattern (e.g. DoD pattern 0xAA/0x55)
                pattern, ratio = self._detect_repeating_pattern(data)
                if pattern is not None and len(pattern) <= 4:
                    pattern_filled_blocks += 1
                    hex_pat = pattern.hex().upper()
                    detected_patterns.add(f"Repeating pattern (0x{hex_pat})")

            pos += block_size

        if total_blocks == 0:
            return findings

        wiped_blocks = zero_filled_blocks + pattern_filled_blocks + random_filled_blocks
        wipe_ratio = wiped_blocks / total_blocks

        # Only report if significant portion shows wipe patterns
        if wipe_ratio >= 0.30 and wiped_blocks >= 2:
            strong_flags = 0
            weak_flags = 0
            rules = ["unallocated_region_wipe_pattern"]

            if zero_filled_blocks > 0:
                rules.append("unalloc_zero_fill_detected")
                strong_flags += 1
            if pattern_filled_blocks > 0:
                rules.append("unalloc_pattern_fill_detected")
                strong_flags += 1
            if random_filled_blocks > 0:
                rules.append("unalloc_random_fill_detected")
                strong_flags += 2

            if wipe_ratio >= 0.80:
                rules.append("high_wipe_coverage")
                strong_flags += 1

            severity = self._score_severity(strong_flags, weak_flags)
            confidence = min(95, 45 + int(wipe_ratio * 40) + (strong_flags * 8))

            region_size_mb = round(size / (1024 * 1024), 2)
            scanned_mb = round(scan_size / (1024 * 1024), 2)

            details = {
                "partition_index": part_index,
                "region_offset": offset,
                "region_size_bytes": size,
                "region_size_mb": region_size_mb,
                "scanned_mb": scanned_mb,
                "total_blocks_scanned": total_blocks,
                "zero_filled_blocks": zero_filled_blocks,
                "pattern_filled_blocks": pattern_filled_blocks,
                "random_filled_blocks": random_filled_blocks,
                "wipe_ratio": round(wipe_ratio, 4),
                "detected_patterns": sorted(detected_patterns),
                "wipe_pattern": ", ".join(sorted(detected_patterns)),
                "is_deleted": False,
                "timestamps": {},
            }

            findings.append(
                AnalysisFinding(
                    module=self.module_name,
                    artifact=f"Unallocated Region (Partition {part_index}, offset {offset})",
                    severity=severity,
                    status="Suspicious",
                    confidence=confidence,
                    rules=rules,
                    details=details,
                )
            )

        return findings
