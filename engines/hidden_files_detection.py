from .base import AnalysisEngine
from .evidence import ForensicImageSource
from .models import AnalysisFinding, AnalysisReport


class HiddenFilesDetectionEngine(AnalysisEngine):
    module_id = "hidden_files_detection"
    module_name = "Hidden Files Detection"
    MAX_REPORTED_FINDINGS = 2500

    DECEPTIVE_EXECUTABLE_EXTENSIONS = {
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js",
        ".jse",
        ".jar",
        ".com",
        ".pif",
        ".lnk",
        ".hta",
    }

    BENIGN_LOOKING_EXTENSIONS = {
        ".txt",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".mp3",
        ".mp4",
        ".csv",
        ".log",
    }

    RLO_CHARS = {
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
    }

    def _score_severity(self, strong_flags, weak_flags):
        if strong_flags >= 3 or (strong_flags >= 2 and weak_flags >= 1):
            return "High"
        if strong_flags >= 2 or (strong_flags >= 1 and weak_flags >= 2):
            return "Medium"
        return "Low"

    def _is_deceptive_double_extension(self, filename):
        lowered = filename.lower()
        parts = lowered.split(".")
        if len(parts) < 3:
            return False

        first_ext = f".{parts[-2]}"
        final_ext = f".{parts[-1]}"
        return first_ext in self.BENIGN_LOOKING_EXTENSIONS and final_ext in self.DECEPTIVE_EXECUTABLE_EXTENSIONS

    def _extract_non_system_ads(self, stream_names):
        ads_names = []
        for raw_name in stream_names:
            if not raw_name:
                continue
            name = str(raw_name)
            lowered = name.lower()
            if lowered.startswith("$"):
                continue
            ads_names.append(name)
        return sorted(set(ads_names))

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
                filename = record.get("filename", name)
                ext = (record.get("extension") or "").lower()
                size = record.get("size", 0)
                entropy = record.get("sample_entropy")
                stream_names = record.get("stream_names") or []

                strong_flags = 0
                weak_flags = 0
                rules = []
                name_traits = []

                ads_streams = self._extract_non_system_ads(stream_names)
                if ads_streams:
                    rules.append("named_alternate_data_stream")
                    strong_flags += 2

                if any(char in filename for char in self.RLO_CHARS):
                    rules.append("unicode_direction_override_in_name")
                    strong_flags += 2
                    name_traits.append("Unicode bidi override")

                if filename.rstrip(" .") != filename:
                    rules.append("trailing_dot_or_space_in_name")
                    strong_flags += 1
                    name_traits.append("Trailing dot/space")

                if ":" in filename:
                    rules.append("colon_in_filename")
                    strong_flags += 1
                    name_traits.append("Colon in filename")

                if self._is_deceptive_double_extension(filename):
                    rules.append("deceptive_double_extension")
                    strong_flags += 1
                    name_traits.append("Deceptive double extension")

                if name.startswith(".") and len(name) > 1:
                    rules.append("dot_prefixed_filename")
                    weak_flags += 1

                if "/." in path and not path.startswith("/."):
                    rules.append("dot_prefixed_parent_directory")
                    weak_flags += 1

                if ext in self.DECEPTIVE_EXECUTABLE_EXTENSIONS and name.startswith("."):
                    rules.append("dot_prefixed_executable")
                    strong_flags += 1

                # Reduce false positives: do not alert on only dot-prefix conventions.
                if strong_flags == 0:
                    continue

                suspicious_files += 1
                severity = self._score_severity(strong_flags, weak_flags)
                confidence = min(97, 48 + (strong_flags * 16) + (weak_flags * 6))

                details = {
                    "size": size,
                    "extension": ext or "(none)",
                    "sample_entropy": round(entropy, 4) if entropy is not None else None,
                    "ads_streams": ads_streams,
                    "name_traits": name_traits,
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
