# ShadowTrace - Anti-Forensics Detection System

## 1. Tool Overview

**ShadowTrace** (formerly AFDS) is an advanced Digital Forensics and Incident Response (DFIR) application specifically designed to detect **anti-forensic techniques**. While most forensic tools look for existing evidence, ShadowTrace looks for the *absence* of evidence, manipulated data, and deliberate attempts to hide or destroy digital artifacts.

The tool features a professional, GUI and a highly modular backend powered by 6 distinct detection engines:

*   **Time Stomping Detection:** Identifies manipulated MAC (Modified, Accessed, Created) timestamps, future dates, and accessed-before-created anomalies.
*   **Encryption Detection:** Locates hidden cryptographic containers, high-entropy blobs, and password-protected archives disguised as benign files.
*   **Hidden Files Detection:** Detects NTFS Alternate Data Streams (ADS), Unicode direction-override spoofing, trailing-space evasion, and deceptive double-extensions.
*   **Partition Analysis:** Inspects partition tables for overlapping segments, hidden unallocated gaps, and disguised mountable filesystems.
*   **Secure Deletion Detection:** Scans unallocated clusters for DoD 5220.22-M/Gutmann wiping signatures, zero-fill blocks, and wiping-tool artifacts (SDelete, BleachBit).
*   **File Integrity Check:** Validates file magic-number signatures against their declared extensions to catch malware or hidden data masquerading as benign files (e.g., an `.exe` renamed to `.jpg`).

ShadowTrace operates exclusively on raw forensic images (`.dd`, `.raw`, `.img`, `.iso`, etc.) to maintain strict forensic integrity and chain of custody.

---

## 2. Installation Instructions

1. **Clone or Extract the Project:**
   Ensure the `DF_Project` folder is placed on your local drive.

2. **Create a Virtual Environment (Recommended):**
   ```powershell
   cd d:\DF_Project
   python -m venv .venv
   .venv\Scripts\activate
   ```

3. **Install Required Packages:**
   Use the provided requirements file to install the exact dependencies:
   ```powershell
   pip install -r requirements.txt

4. ShadowTrace can be also installed from our official installer. simply download it and double click it and follow the installer instructions.
   ```

---



## 3. Dependencies and Prerequisites

**Prerequisites:**
*   Python 3.10 or higher (Python 3.13+ recommended)
*   A Windows operating system (Primary development platform)

**Mandatory Dependencies:**
*   `pytsk3` (>=20240506): Core Python bindings for The Sleuth Kit, required for low-level forensic image parsing and file extraction.
*   `Pillow` (>=10.0.0): Required for UI enhancements and dynamic logo scaling.
*   *Note: All other libraries used (like `tkinter`, `sqlite3`, `hashlib`, `html`) are part of the Python Standard Library.*

**Optional Dependencies:**
*   `libewf-python` (`pyewf`): Install this if you need to analyze Expert Witness Format images (`.E01`, `.EX01`). Without it, ShadowTrace natively handles raw DD images perfectly.

---

## 4. Execution Steps

1. **Launch the Application:**
   From the project root directory with your virtual environment activated, run:
   ```powershell
   python main.py
   ```

2. **Load Forensic Evidence:**
   Click **Open** on the top toolbar and select a supported forensic image file (e.g., `.dd`, `.raw`).

3. **Select Modules:**
   In the left-hand panel under "Module Filters", check the boxes for the detection engines you wish to run. You can also click **Select All** in the toolbar.

4. **Run Analysis:**
   Click **Analyze**. The console output will show real-time progress. Depending on the size of the forensic image, this may take a few moments.

5. **Review & Export:**
   *   Use the **Evidence Browser** (left) to filter findings by Module or Severity.
   *   Select a row in the central table to view deep metadata in the **Inspector Panel** (right).
   *   Click **Export** (or double-click "Generate Report" in the tree) to generate a rich, professional HTML or Plain Text forensic report.

---

## 5. Platform Compatibility

*   **Operating System:** Built and tested primarily on **Windows 10 / Windows 11**.
*   **GUI Subsystem:** Relies on `tkinter`, which comes pre-packaged with standard Windows Python installers.
*   **Cross-Platform:** While the core logic and `pytsk3` are cross-platform (Linux/macOS), the UI styling and directory pathing are optimized for Windows environments.

---

## 6. Troubleshooting

*   **Error: `ModuleNotFoundError: No module named 'pytsk3'`**
    *   *Fix:* Ensure your virtual environment is activated before running the script. Run `pip install -r requirements.txt` again. If installing `pytsk3` fails on Windows, you may need to install the *Microsoft C++ Build Tools*.
*   **Error: "Invalid Evidence Type" when loading an image**
    *   *Fix:* ShadowTrace strictly enforces forensic best practices and will not analyze live `C:\` drives or arbitrary folders. You must provide a valid forensic image file (`.dd`, `.raw`, `.001`, etc.).
*   **Error: Missing UI Elements / Logo not showing**
    *   *Fix:* Ensure the `assets/` folder exists in the same directory as `main.py` and contains `shadowtrace_logo.png`. Verify `Pillow` is installed.
*   **Application freezes during analysis**
    *   *Fix:* The `Secure Deletion` and `Encryption` engines perform intensive byte-level mathematical calculations (Shannon Entropy). On very large images (>10GB), the UI may briefly pause. Wait for the console log to complete.
