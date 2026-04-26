from .base import AnalysisEngine
from .evidence import ForensicImageSource
from .models import AnalysisFinding, AnalysisReport


class EncryptionDetectionEngine(AnalysisEngine):
    module_id = "encryption_detection"
    module_name = "Encryption Detection"
    MAX_REPORTED_FINDINGS = 2500

    HIGH_ENTROPY_THRESHOLD = 7.92
    ELEVATED_ENTROPY_THRESHOLD = 7.75
    MIN_BINARY_SAMPLE_SIZE = 16 * 1024
    MIN_ELEVATED_SAMPLE_SIZE = 64 * 1024

    ENCRYPTED_CONTAINER_EXTENSIONS = {
        ".tc",
        ".hc",
        ".kdbx",
        ".pgp",
        ".gpg",
        ".aes",
        ".enc",
        ".crypt",
        ".p7m",
        ".p7e",
        ".axx",
        ".vault",
    }

    POSSIBLE_PROTECTED_ARCHIVES = {".zip", ".7z", ".rar"}

    LIKELY_CLEAR_TEXT_EXTENSIONS = {
        ".txt",
        ".log",
        ".csv",
        ".tsv",
        ".json",
        ".xml",
        ".html",
        ".htm",
        ".md",
        ".ini",
        ".cfg",
        ".yaml",
        ".yml",
        ".sql",
        ".py",
        ".js",
        ".ts",
        ".java",
        ".c",
        ".cpp",
        ".h",
        ".hpp",
        ".ps1",
        ".bat",
        ".sh",
    }

    ENCRYPTION_KEYWORDS = {
        "encrypt",
        "encrypted",
        "encryption",
        "locker",
        "vault",
        "cipher",
        "secret",
        "bitlocker",
        "veracrypt",
        "truecrypt",
        "private",
        "secure",
    }

    def _score_severity(self, strong_flags, weak_flags):
        if strong_flags >= 3 or (strong_flags >= 2 and weak_flags >= 1):
            return "High"
        if strong_flags >= 2 or (strong_flags >= 1 and weak_flags >= 2):
            return "Medium"
        return "Low"

    def _is_likely_readable_content(self, ext, entropy, printable_ratio):
        if ext not in self.LIKELY_CLEAR_TEXT_EXTENSIONS:
            return False
        if entropy is None or printable_ratio is None:
            return False
        return printable_ratio >= 0.86 and entropy <= 7.2

    def analyze(self, evidence_path, case_name, examiner):
        source = ForensicImageSource(evidence_path)
        findings = []
        total_files = 0
        suspicious_files = 0

        try:
            for record in source.iter_files():
                total_files += 1
                path = record.get("path", "")
                name = record.get("name", "")
                ext = (record.get("extension") or "").lower()
                size = record.get("size", 0)
                entropy = record.get("sample_entropy")
                printable_ratio = record.get("printable_ratio")
                null_ratio = record.get("null_ratio")
                ntfs_attr_encrypted = bool(record.get("ntfs_attr_encrypted"))
                ntfs_run_encrypted = bool(record.get("ntfs_run_encrypted"))
                efs_stream_present = bool(record.get("efs_stream_present"))
                stream_names = record.get("stream_names") or []

                rules = []
                strong_flags = 0
                weak_flags = 0

                lower_path = path.lower()
                lower_name = name.lower()

                if ntfs_attr_encrypted:
                    rules.append("ntfs_attribute_marked_encrypted")
                    strong_flags += 2

                if ntfs_run_encrypted:
                    rules.append("ntfs_run_marked_encrypted")
                    strong_flags += 2

                if efs_stream_present:
                    rules.append("efs_stream_detected")
                    strong_flags += 2

                if strong_flags == 0 and self._is_likely_readable_content(ext, entropy, printable_ratio):
                    continue

                if ext in self.ENCRYPTED_CONTAINER_EXTENSIONS:
                    rules.append("known_encrypted_extension")
                    strong_flags += 1

                if any(keyword in lower_name for keyword in self.ENCRYPTION_KEYWORDS):
                    rules.append("encryption_keyword_in_filename")
                    weak_flags += 1

                if any(keyword in lower_path for keyword in self.ENCRYPTION_KEYWORDS):
                    rules.append("encryption_keyword_in_path")
                    weak_flags += 1

                if (
                    entropy is not None
                    and size >= self.MIN_BINARY_SAMPLE_SIZE
                    and entropy >= self.HIGH_ENTROPY_THRESHOLD
                    and printable_ratio is not None
                    and printable_ratio <= 0.25
                ):
                    rules.append("high_entropy_content")
                    strong_flags += 1
                elif (
                    entropy is not None
                    and size >= self.MIN_ELEVATED_SAMPLE_SIZE
                    and entropy >= self.ELEVATED_ENTROPY_THRESHOLD
                    and printable_ratio is not None
                    and printable_ratio <= 0.4
                ):
                    rules.append("elevated_entropy_content")
                    weak_flags += 1

                if (
                    ext in self.POSSIBLE_PROTECTED_ARCHIVES
                    and entropy is not None
                    and entropy >= 7.85
                    and size >= 128 * 1024
                    and printable_ratio is not None
                    and printable_ratio <= 0.3
                ):
                    rules.append("possible_password_protected_archive")
                    strong_flags += 1

                if (
                    size >= 8 * 1024 * 1024
                    and entropy is not None
                    and entropy >= 7.97
                    and printable_ratio is not None
                    and printable_ratio <= 0.2
                ):
                    rules.append("large_high_entropy_blob")
                    strong_flags += 1

                if null_ratio is not None and null_ratio >= 0.35 and entropy is not None and entropy >= 7.5:
                    rules.append("binary_randomized_structure")
                    weak_flags += 1

                # Prevent keyword-only or weak-only alerts: require at least one strong signal.
                if strong_flags == 0:
                    continue

                if not rules:
                    continue

                suspicious_files += 1
                severity = self._score_severity(strong_flags, weak_flags)
                confidence = min(96, 45 + (strong_flags * 18) + (weak_flags * 6))

                details = {
                    "size": size,
                    "extension": ext or "(none)",
                    "sample_entropy": round(entropy, 4) if entropy is not None else None,
                    "printable_ratio": round(printable_ratio, 4) if printable_ratio is not None else None,
                    "null_ratio": round(null_ratio, 4) if null_ratio is not None else None,
                    "ntfs_attr_encrypted": ntfs_attr_encrypted,
                    "ntfs_run_encrypted": ntfs_run_encrypted,
                    "efs_stream_present": efs_stream_present,
                    "stream_names": stream_names,
                    "partition_index": record.get("partition_index"),
                    "timestamps": record.get("timestamps", {}),
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
        finally:
            source.close()

        summary = {
            "imageLoaded": True,
            "selectedModules": 1,
            "reportStatus": "Pending generation" if findings else "No anomalies detected",
            "totalFilesScanned": total_files,
            "suspiciousFiles": suspicious_files,
        }

        return AnalysisReport(
            case_name=case_name,
            examiner=examiner,
            image_path=str(evidence_path),
            module=self.module_name,
            findings=findings,
            summary=summary,
        )
