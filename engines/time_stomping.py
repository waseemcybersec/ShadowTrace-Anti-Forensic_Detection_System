from datetime import datetime, timezone

from .base import AnalysisEngine
from .evidence import ForensicImageSource
from .models import AnalysisFinding, AnalysisReport


class TimeStompingEngine(AnalysisEngine):
    module_id = "time_stomping"
    module_name = "Time Stomping Detection"
    MAX_REPORTED_FINDINGS = 2500

    def _timestamp_epoch(self, value):
        if value is None:
            return None
        if isinstance(value, dict):
            return value.get("epoch")
        if isinstance(value, (int, float)):
            return int(value)
        return None

    def _epoch_to_datetime(self, value):
        if value is None:
            return None
        return datetime.fromtimestamp(value, tz=timezone.utc)

    def _score_severity(self, rule_count, strong_flags):
        if strong_flags >= 2 or rule_count >= 4:
            return "High"
        if rule_count >= 2:
            return "Medium"
        return "Low"

    def analyze(self, evidence_path, case_name, examiner):
        source = ForensicImageSource(evidence_path)
        findings = []
        total_files = 0
        suspicious_files = 0

        try:
            for record in source.iter_files():
                total_files += 1
                time_info = record.get("timestamps") or {}
                timestamps = time_info
                created_epoch = self._timestamp_epoch(time_info.get("created"))
                modified_epoch = self._timestamp_epoch(time_info.get("modified"))
                accessed_epoch = self._timestamp_epoch(time_info.get("accessed"))
                changed_epoch = self._timestamp_epoch(time_info.get("changed"))

                created = self._epoch_to_datetime(created_epoch)
                modified = self._epoch_to_datetime(modified_epoch)
                accessed = self._epoch_to_datetime(accessed_epoch)
                changed = self._epoch_to_datetime(changed_epoch)

                rules = []
                details = {
                    "timestamps": timestamps,
                    "size": record["size"],
                    "partition_index": record["partition_index"],
                }
                strong_flags = 0

                timeline = [dt for dt in (created, modified, accessed, changed) if dt is not None]
                if not timeline:
                    continue

                if created and modified and created > modified:
                    rules.append("created_after_modified")
                    strong_flags += 1

                if changed and modified and changed > modified and record["size"] > 0:
                    rules.append("metadata_changed_after_content")

                if created and changed and created > changed:
                    rules.append("created_after_metadata_change")
                    strong_flags += 1

                now = datetime.now(timezone.utc)
                if any(dt > now for dt in timeline):
                    rules.append("future_timestamp")
                    strong_flags += 1

                unique_times = {ts for ts in (created_epoch, modified_epoch, accessed_epoch, changed_epoch) if ts is not None}
                if record["size"] > 0 and len(unique_times) == 1 and len(timeline) >= 3:
                    rules.append("all_metadata_times_equal")

                if created and modified:
                    gap_days = abs((modified - created).total_seconds()) / 86400
                    if gap_days > 3650:
                        rules.append("large_created_modified_gap")

                if accessed and modified and accessed < modified:
                    rules.append("accessed_before_modified")

                if not rules:
                    continue

                suspicious_files += 1
                severity = self._score_severity(len(rules), strong_flags)
                confidence = min(95, 45 + (len(rules) * 12) + (strong_flags * 10))
                if len(findings) < self.MAX_REPORTED_FINDINGS:
                    findings.append(
                        AnalysisFinding(
                            module=self.module_name,
                            artifact=record["path"],
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
