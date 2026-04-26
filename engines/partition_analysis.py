from .base import AnalysisEngine
from .evidence import ForensicImageSource
from .models import AnalysisFinding, AnalysisReport


class PartitionAnalysisEngine(AnalysisEngine):
    module_id = "partition_analysis"
    module_name = "Partition Analysis"

    MIN_SUSPICIOUS_PARTITION_SECTORS = 20480  # 1) MB at 512-byte sectors
    LARGE_GAP_THRESHOLD_SECTORS = 2_097_152  # ~1 GB at 512-byte sectors
    HUGE_UNALLOCATED_PARTITION_SECTORS = 2_097_152  # ~2 GB at 512-byte sectors

    def _score_severity(self, strong_flags, weak_flags):
        if strong_flags >= 3 or (strong_flags >= 2 and weak_flags >= 1):
            return "High"
        if strong_flags >= 2 or (strong_flags >= 1 and weak_flags >= 2):
            return "Medium"
        return "Low"

    def _partition_artifact(self, part):
        desc = part.get("description") or "Unknown"
        return f"Partition {part.get('index', 0)} | {desc} | Start {part.get('start_sector')}"

    def analyze(self, evidence_path, case_name, examiner):
        source = ForensicImageSource(evidence_path)
        findings = []

        try:
            partitions = list(source.iter_partitions())
            total_partitions = len(partitions)
            suspicious_partitions = 0

            # Work on likely data partitions for overlap/gap topology checks.
            data_parts = [
                p
                for p in partitions
                if not p.get("is_metadata") and p.get("length_sectors", 0) > 0
            ]
            data_parts.sort(key=lambda p: p.get("start_sector", 0))

            for idx, part in enumerate(data_parts):
                rules = []
                strong_flags = 0
                weak_flags = 0

                description = (part.get("description") or "").lower()
                has_fs_raw = part.get("has_filesystem")
                has_fs = bool(has_fs_raw) if has_fs_raw is not None else None
                is_alloc = bool(part.get("is_allocated"))
                is_unalloc = bool(part.get("is_unallocated"))
                start = int(part.get("start_sector", 0) or 0)
                end = int(part.get("end_sector", 0) or 0)
                length = int(part.get("length_sectors", 0) or 0)

                # If probing is available, treat filesystem in unallocated space as strong.
                if is_unalloc and has_fs is True:
                    rules.append("filesystem_present_in_unallocated_partition")
                    strong_flags += 2

                if (not is_alloc) and has_fs is True:
                    rules.append("mountable_partition_not_marked_allocated")
                    strong_flags += 2

                if length < self.MIN_SUSPICIOUS_PARTITION_SECTORS and is_alloc and not part.get("is_metadata"):
                    rules.append("very_small_allocated_partition")
                    strong_flags += 1

                if "reserved" in description and is_alloc and length >= self.MIN_SUSPICIOUS_PARTITION_SECTORS:
                    rules.append("reserved_partition_sized_like_data")
                    strong_flags += 1

                if is_unalloc and length >= self.HUGE_UNALLOCATED_PARTITION_SECTORS:
                    rules.append("very_large_unallocated_partition_segment")
                    strong_flags += 1

                # Overlap check with previous and next data partitions.
                if idx > 0:
                    prev = data_parts[idx - 1]
                    prev_end = int(prev.get("end_sector", 0) or 0)
                    if start <= prev_end:
                        rules.append("overlapping_partition_ranges")
                        strong_flags += 2
                    else:
                        gap = start - prev_end - 1
                        if gap >= self.LARGE_GAP_THRESHOLD_SECTORS:
                            rules.append("large_unmapped_gap_between_partitions")
                            weak_flags += 1

                if idx < len(data_parts) - 1:
                    nxt = data_parts[idx + 1]
                    next_start = int(nxt.get("start_sector", 0) or 0)
                    if end >= next_start:
                        if "overlapping_partition_ranges" not in rules:
                            rules.append("overlapping_partition_ranges")
                            strong_flags += 2

                # Be conservative: require at least one strong indicator.
                if strong_flags == 0:
                    continue

                suspicious_partitions += 1
                severity = self._score_severity(strong_flags, weak_flags)
                confidence = min(97, 50 + (strong_flags * 15) + (weak_flags * 6))

                details = {
                    "partition_index": part.get("index"),
                    "partition_description": part.get("description"),
                    "start_sector": start,
                    "end_sector": end,
                    "length_sectors": length,
                    "is_allocated": is_alloc,
                    "is_unallocated": is_unalloc,
                    "is_metadata": bool(part.get("is_metadata")),
                    "has_filesystem": has_fs,
                    "filesystem_offset": part.get("filesystem_offset"),
                    "filesystem_error": part.get("filesystem_error"),
                }

                findings.append(
                    AnalysisFinding(
                        module=self.module_name,
                        artifact=self._partition_artifact(part),
                        severity=severity,
                        status="Suspicious",
                        confidence=confidence,
                        rules=rules,
                        details=details,
                    )
                )

            # Global table-level condition as a finding when structure is noisy.
            if total_partitions > 32:
                findings.append(
                    AnalysisFinding(
                        module=self.module_name,
                        artifact="Partition Table",
                        severity="Medium",
                        status="Suspicious",
                        confidence=70,
                        rules=["unusually_high_partition_count"],
                        details={
                            "total_partitions": total_partitions,
                        },
                    )
                )
                suspicious_partitions += 1

            summary = {
                "imageLoaded": True,
                "selectedModules": 1,
                "reportStatus": "Pending generation" if findings else "No anomalies detected",
                "totalFilesScanned": total_partitions,
                "suspiciousFiles": suspicious_partitions,
            }

            return AnalysisReport(
                case_name=case_name,
                examiner=examiner,
                image_path=str(evidence_path),
                module=self.module_name,
                findings=findings,
                summary=summary,
            )
        finally:
            source.close()
