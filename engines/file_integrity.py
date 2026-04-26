"""
File Integrity Check Engine
============================
Validates file integrity by cross-referencing file header magic bytes (file
signatures) against declared file extensions, detecting mismatches that
indicate anti-forensic renaming, data hiding, or file corruption.

Detection approach
------------------
1. **Magic-number signature database** — A curated map of ~45 file signatures
   covering executables, documents, images, archives, audio/video, databases,
   and scripts.  Each signature records its canonical byte prefix, the human-
   readable type name, and the set of valid extensions for that type.

2. **Header → Extension validation** — For every file in the forensic image
   the engine reads the first 512 bytes (already extracted by the evidence
   layer) and matches them against the signature database.  If the file's
   actual extension is not in the set of valid extensions for the matched
   signature, the file is flagged.

3. **Severity escalation rules** — A simple extension mismatch is a weak
   signal; the engine escalates severity when it detects:
     • An executable disguised as a benign file (MZ/ELF header + .jpg/.pdf/…)
     • A null / zeroed file header on a file with nonzero size
     • A file too small to be valid for its declared type
     • Embedded executable signatures inside non-executable files
     • Known-format extensions whose headers don't match ANY known signature

4. **Strong-signal gating** — To suppress false positives the engine requires
   at least one *strong* indicator before emitting a finding.
"""

import os
from .base import AnalysisEngine
from .evidence import ForensicImageSource
from .models import AnalysisFinding, AnalysisReport


class FileIntegrityEngine(AnalysisEngine):
    module_id = "file_integrity"
    module_name = "File Integrity Check"
    MAX_REPORTED_FINDINGS = 2500

    # ------------------------------------------------------------------ #
    #  Magic-number signature database                                     #
    # ------------------------------------------------------------------ #
    #  Each entry: (magic_bytes, type_label, {valid_extensions})           #
    #  Ordered longest-prefix-first so matching is unambiguous.            #
    # ------------------------------------------------------------------ #
    SIGNATURES = [
        # ---- Images ----
        (b"\xFF\xD8\xFF",                    "JPEG image",           {".jpg", ".jpeg", ".jpe", ".jfif"}),
        (b"\x89PNG\r\n\x1a\n",              "PNG image",            {".png"}),
        (b"GIF87a",                          "GIF image",            {".gif"}),
        (b"GIF89a",                          "GIF image",            {".gif"}),
        (b"BM",                              "BMP image",            {".bmp"}),
        (b"II\x2a\x00",                     "TIFF image (LE)",      {".tif", ".tiff"}),
        (b"MM\x00\x2a",                     "TIFF image (BE)",      {".tif", ".tiff"}),
        (b"\x00\x00\x01\x00",               "ICO icon",             {".ico"}),

        # ---- Documents ----
        (b"%PDF",                            "PDF document",         {".pdf"}),
        (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "MS Office (OLE)",  {".doc", ".xls", ".ppt", ".msg", ".msi"}),
        (b"PK\x03\x04",                     "ZIP / Office XML",     {".zip", ".docx", ".xlsx", ".pptx",
                                                                      ".odt", ".ods", ".odp", ".jar",
                                                                      ".apk", ".xpi", ".epub"}),
        (b"{\\rtf",                          "RTF document",         {".rtf"}),

        # ---- Executables / Libraries ----
        (b"MZ",                              "Windows executable",   {".exe", ".dll", ".sys", ".ocx",
                                                                      ".scr", ".drv", ".cpl", ".msi"}),
        (b"\x7fELF",                         "Linux ELF binary",     {".so", ".elf", ".bin", ".o", ""}),
        (b"\xFE\xED\xFA\xCE",               "Mach-O 32 binary",    {".dylib", ".bundle", ""}),
        (b"\xFE\xED\xFA\xCF",               "Mach-O 64 binary",    {".dylib", ".bundle", ""}),
        (b"\xCA\xFE\xBA\xBE",               "Java class / fat Mach-O", {".class", ""}),
        (b"\xCE\xFA\xED\xFE",               "Mach-O 32 (rev)",     {".dylib", ".bundle", ""}),
        (b"\xCF\xFA\xED\xFE",               "Mach-O 64 (rev)",     {".dylib", ".bundle", ""}),

        # ---- Archives ----
        (b"\x1f\x8b",                        "GZIP archive",        {".gz", ".tgz"}),
        (b"Rar!\x1a\x07",                   "RAR archive",          {".rar"}),
        (b"7z\xBC\xAF\x27\x1C",             "7-Zip archive",       {".7z"}),
        (b"\xFD7zXZ\x00",                   "XZ archive",           {".xz"}),
        (b"BZh",                             "BZIP2 archive",       {".bz2"}),
        (b"\x50\x4b\x05\x06",               "ZIP (empty archive)",  {".zip"}),

        # ---- Audio / Video ----
        (b"ID3",                             "MP3 audio (ID3)",     {".mp3"}),
        (b"\xFF\xFB",                        "MP3 audio",           {".mp3"}),
        (b"\xFF\xF3",                        "MP3 audio",           {".mp3"}),
        (b"\xFF\xF2",                        "MP3 audio",           {".mp3"}),
        (b"OggS",                            "OGG container",       {".ogg", ".oga", ".ogv", ".opus"}),
        (b"fLaC",                            "FLAC audio",          {".flac"}),
        (b"RIFF",                            "RIFF container",      {".wav", ".avi", ".webp"}),

        # ---- Database ----
        (b"SQLite format 3",                 "SQLite database",     {".db", ".sqlite", ".sqlite3"}),

        # ---- Scripts / Text with BOM ----
        (b"\xEF\xBB\xBF",                   "UTF-8 BOM text",      {".txt", ".csv", ".xml", ".html",
                                                                      ".htm", ".json", ".log", ".md",
                                                                      ".yaml", ".yml", ".ini", ".cfg",
                                                                      ".py", ".js", ".ts", ".css"}),
        (b"\xFF\xFE",                        "UTF-16 LE text",      {".txt", ".csv", ".xml", ".html",
                                                                      ".htm", ".log", ".reg"}),
        (b"\xFE\xFF",                        "UTF-16 BE text",      {".txt", ".csv", ".xml", ".html",
                                                                      ".htm", ".log"}),

        # ---- Misc ----
        (b"\x00\x61\x73\x6D",               "WebAssembly module",  {".wasm"}),
        (b"#!",                              "Script (shebang)",    {".sh", ".py", ".pl", ".rb", ".cgi", ""}),
    ]

    # Extensions that normally hold well-known binary formats — if the header
    # doesn't match anything we flag as "possibly fabricated".
    EXPECTED_SIGNATURE_EXTENSIONS = {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".ico",
        ".pdf", ".doc", ".xls", ".ppt", ".docx", ".xlsx", ".pptx",
        ".zip", ".rar", ".7z", ".gz", ".bz2", ".xz",
        ".exe", ".dll", ".sys", ".msi",
        ".mp3", ".ogg", ".flac", ".wav", ".avi",
        ".db", ".sqlite", ".sqlite3",
    }

    # Minimum plausible sizes for common types (bytes).
    MIN_VALID_SIZES = {
        ".jpg": 107, ".jpeg": 107, ".png": 67, ".gif": 14, ".bmp": 26,
        ".pdf": 67, ".doc": 512, ".xls": 512, ".ppt": 512,
        ".docx": 100, ".xlsx": 100, ".pptx": 100,
        ".zip": 22, ".rar": 20, ".7z": 32, ".gz": 20,
        ".exe": 97, ".dll": 97, ".sys": 97,
        ".mp3": 128, ".wav": 44, ".flac": 42,
        ".db": 100, ".sqlite": 100,
    }

    # Benign extensions — used to detect "executable masquerading as benign".
    BENIGN_EXTENSIONS = {
        ".txt", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff",
        ".mp3", ".mp4", ".wav", ".avi", ".mkv", ".mov",
        ".csv", ".log", ".xml", ".html", ".htm", ".json", ".md",
    }

    EXECUTABLE_TYPES = {"Windows executable", "Linux ELF binary",
                        "Mach-O 32 binary", "Mach-O 64 binary",
                        "Mach-O 32 (rev)", "Mach-O 64 (rev)"}

    # Byte sequences searched inside file bodies to find embedded executables.
    EMBEDDED_EXE_SIGNATURES = [
        (b"MZ",       "PE/MZ"),
        (b"\x7fELF",  "ELF"),
    ]

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _identify_header(self, header):
        """Return (type_label, valid_extensions) for the first matching sig."""
        if not header:
            return None, set()
        for magic, type_label, valid_exts in self.SIGNATURES:
            if header[:len(magic)] == magic:
                return type_label, valid_exts
        return None, set()

    def _check_mp4_ftyp(self, header):
        """MP4/MOV files have 'ftyp' at offset 4; handle separately."""
        if header and len(header) >= 8 and header[4:8] == b"ftyp":
            return "MP4/MOV container", {".mp4", ".m4a", ".m4v", ".mov", ".3gp", ".f4v"}
        return None, set()

    def _has_embedded_executable(self, header, skip_initial=2):
        """Check if a non-executable file embeds an EXE/ELF signature after
        the first ``skip_initial`` bytes (to avoid matching the file's own
        header)."""
        if not header or len(header) <= skip_initial:
            return None
        search_area = header[skip_initial:]
        for sig, label in self.EMBEDDED_EXE_SIGNATURES:
            if sig in search_area:
                return label
        return None

    def _score_severity(self, strong_flags, weak_flags):
        if strong_flags >= 3 or (strong_flags >= 2 and weak_flags >= 2):
            return "High"
        if strong_flags >= 2 or (strong_flags >= 1 and weak_flags >= 2):
            return "Medium"
        return "Low"

    # ------------------------------------------------------------------ #
    #  Main analysis                                                       #
    # ------------------------------------------------------------------ #

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
                header = record.get("file_header")  # first 512 bytes
                entropy = record.get("sample_entropy")
                null_ratio = record.get("null_ratio")
                printable_ratio = record.get("printable_ratio")
                timestamps = record.get("timestamps", {})

                rules = []
                strong_flags = 0
                weak_flags = 0
                detected_type = None
                expected_type = None

                # --- Identify actual file type from header ---
                header_type, header_exts = self._identify_header(header)

                # Fallback: check MP4 ftyp at offset 4
                if header_type is None:
                    header_type, header_exts = self._check_mp4_ftyp(header)

                # ================================================
                # Rule 1: Extension ↔ header signature mismatch
                # ================================================
                if header_type is not None and ext and ext not in header_exts:
                    detected_type = header_type
                    expected_type = ext

                    # Sub-rule 1a: Executable masquerading as benign file
                    if header_type in self.EXECUTABLE_TYPES and ext in self.BENIGN_EXTENSIONS:
                        rules.append("executable_masquerading_as_benign")
                        strong_flags += 3  # Very high severity
                    else:
                        rules.append("extension_signature_mismatch")
                        strong_flags += 1

                # ================================================
                # Rule 2: Known-format extension but NO known header
                # ================================================
                if (
                    header_type is None
                    and ext in self.EXPECTED_SIGNATURE_EXTENSIONS
                    and header is not None
                    and size > 0
                ):
                    rules.append("no_signature_for_known_format")
                    weak_flags += 1

                # ================================================
                # Rule 3: Null / zeroed file header
                # ================================================
                if header is not None and size > 0 and len(header) >= 16:
                    if all(b == 0 for b in header[:16]):
                        rules.append("null_file_header")
                        strong_flags += 1

                # ================================================
                # Rule 4: File too small for declared type
                # ================================================
                min_size = self.MIN_VALID_SIZES.get(ext)
                if min_size is not None and 0 < size < min_size:
                    rules.append("below_minimum_valid_size")
                    weak_flags += 1

                # ================================================
                # Rule 5: Embedded executable in non-executable file
                # ================================================
                if ext in self.BENIGN_EXTENSIONS and header_type not in self.EXECUTABLE_TYPES:
                    embedded = self._has_embedded_executable(header)
                    if embedded:
                        rules.append(f"embedded_executable:{embedded}")
                        strong_flags += 2

                # ================================================
                # Rule 6: Extension present but header is highly
                #          entropic (possible encrypted/obfuscated
                #          content pretending to be a normal file)
                # ================================================
                if (
                    ext in self.BENIGN_EXTENSIONS
                    and entropy is not None
                    and entropy >= 7.9
                    and printable_ratio is not None
                    and printable_ratio <= 0.15
                    and header_type is None
                    and size >= 4096
                ):
                    rules.append("high_entropy_benign_extension")
                    strong_flags += 1

                # ------------------------------------------------
                # Gate: require at least one strong signal
                # ------------------------------------------------
                if strong_flags == 0:
                    continue
                if not rules:
                    continue

                suspicious_files += 1
                severity = self._score_severity(strong_flags, weak_flags)
                confidence = min(97, 42 + (strong_flags * 15) + (weak_flags * 5))

                details = {
                    "size": size,
                    "extension": ext or "(none)",
                    "detected_type": detected_type,
                    "expected_type": expected_type,
                    "header_hex": header[:32].hex().upper() if header else None,
                    "sample_entropy": round(entropy, 4) if entropy is not None else None,
                    "printable_ratio": round(printable_ratio, 4) if printable_ratio is not None else None,
                    "null_ratio": round(null_ratio, 4) if null_ratio is not None else None,
                    "integrity_rules": rules.copy(),
                    "partition_index": record.get("partition_index"),
                    "timestamps": timestamps,
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
