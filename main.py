import os
import sys
import webbrowser
import tempfile
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from datetime import datetime

from engines import EncryptionDetectionEngine, HiddenFilesDetectionEngine, PartitionAnalysisEngine, TimeStompingEngine, SecureDeletionEngine, FileIntegrityEngine
from engines.evidence import SUPPORTED_FORENSIC_EXTENSIONS
from report_generator import ReportGenerator

def get_asset_path(filename):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, "assets", filename)
    return os.path.join("assets", filename)

class AntiForensicsDetectionApp(tk.Tk):
    MAX_GUI_FINDINGS = 6000

    def __init__(self):
        super().__init__()
        self.title("ShadowTrace")
        self.geometry("1400x840")
        self.minsize(1260, 760)

        try:
            self.iconphoto(False, tk.PhotoImage(file=get_asset_path("shadowtrace_logo.png")))
        except Exception:
            pass

        self.image_path = tk.StringVar(value="No forensic image loaded")
        self.case_name = tk.StringVar(value="Case-001")
        self.examiner = tk.StringVar(value="Team DF")
        self.status_text = tk.StringVar(value="Ready | No image loaded")
        self.forensic_image_extensions = SUPPORTED_FORENSIC_EXTENSIONS
        self.module_vars = {
            "Time Stomping Detection": tk.BooleanVar(value=False),
            "Encryption Detection": tk.BooleanVar(value=False),
            "Hidden Files Detection": tk.BooleanVar(value=False),
            "Partition Analysis": tk.BooleanVar(value=False),
            "Secure Deletion Detection": tk.BooleanVar(value=False),
            "File Integrity Check": tk.BooleanVar(value=False),
        }
        self.module_registry = {
            "Time Stomping Detection": TimeStompingEngine(),
            "Encryption Detection": EncryptionDetectionEngine(),
            "Hidden Files Detection": HiddenFilesDetectionEngine(),
            "Partition Analysis": PartitionAnalysisEngine(),
            "Secure Deletion Detection": SecureDeletionEngine(),
            "File Integrity Check": FileIntegrityEngine(),
        }
        self.result_finding_map = {}
        self.all_findings = []
        self.active_workspace_module = None
        self._analysis_completed = False
        self._last_analyzed_modules = []
        self._module_summaries = {}
        self._analysis_time = None
        self._nav_node_map = {}
        self._active_severity_filter = None

        self._configure_style()
        self._build_layout()
        self._write_welcome_log()

    def _configure_style(self):
        self.palette = {
            "bg": "#F3F6FB",
            "panel": "#FFFFFF",
            "panel_alt": "#F7F9FC",
            "surface": "#FFFFFF",
            "toolbar": "#FFFFFF",
            "accent": "#1F6FEB",
            "accent_hover": "#1558C0",
            "accent_soft": "#EAF2FF",
            "text": "#172033",
            "muted": "#5E697A",
            "ok": "#178A55",
            "warn": "#9A6A00",
        }
        self.configure(bg=self.palette["bg"])

        style = ttk.Style(self)
        for preferred in ("vista", "xpnative", "clam"):
            try:
                style.theme_use(preferred)
                break
            except tk.TclError:
                continue

        style.configure("Base.TFrame", background=self.palette["bg"])
        style.configure("Panel.TFrame", background=self.palette["panel"])
        style.configure("Surface.TFrame", background=self.palette["surface"])
        style.configure("Toolbar.TFrame", background=self.palette["toolbar"])

        style.configure(
            "Header.TLabel",
            background=self.palette["toolbar"],
            foreground=self.palette["text"],
            font=("Segoe UI Semibold", 10),
        )
        style.configure(
            "PanelTitle.TLabel",
            background=self.palette["panel"],
            foreground=self.palette["text"],
            font=("Segoe UI Semibold", 9),
        )
        style.configure(
            "PanelText.TLabel",
            background=self.palette["panel"],
            foreground=self.palette["muted"],
            font=("Segoe UI", 9),
        )
        style.configure(
            "ToolbarText.TLabel",
            background=self.palette["toolbar"],
            foreground=self.palette["muted"],
            font=("Segoe UI", 9),
        )

        style.configure(
            "ToolbarButton.TButton",
            font=("Segoe UI Semibold", 9),
            foreground=self.palette["text"],
            background=self.palette["toolbar"],
            bordercolor=self.palette["toolbar"],
            padding=(9, 5),
            relief="flat",
            borderwidth=0,
        )
        style.map(
            "ToolbarButton.TButton",
            background=[("active", self.palette["accent_soft"]), ("pressed", self.palette["accent_soft"])],
            bordercolor=[("active", self.palette["accent_soft"]), ("pressed", self.palette["accent_soft"])],
            foreground=[("active", self.palette["accent"]), ("pressed", self.palette["accent"])],
        )

        style.configure(
            "Secondary.TButton",
            font=("Segoe UI Semibold", 9),
            foreground=self.palette["text"],
            background=self.palette["toolbar"],
            bordercolor=self.palette["toolbar"],
            padding=(9, 5),
            relief="flat",
            borderwidth=0,
        )
        style.map(
            "Secondary.TButton",
            background=[("active", self.palette["accent_soft"]), ("pressed", self.palette["accent_soft"])],
            bordercolor=[("active", self.palette["accent_soft"]), ("pressed", self.palette["accent_soft"])],
            foreground=[("active", self.palette["accent"]), ("pressed", self.palette["accent"])],
        )

        style.configure(
            "WorkspaceTab.TButton",
            font=("Segoe UI Semibold", 8),
            foreground=self.palette["text"],
            background=self.palette["panel_alt"],
            bordercolor="#D8E1ED",
            padding=(8, 4),
        )
        style.map(
            "WorkspaceTab.TButton",
            background=[("active", self.palette["accent_soft"])],
            bordercolor=[("active", "#C5D8FB")],
            foreground=[("active", self.palette["accent"])],
        )

        style.configure(
            "WorkspaceTabActive.TButton",
            font=("Segoe UI Semibold", 8),
            foreground=self.palette["accent"],
            background=self.palette["accent_soft"],
            bordercolor="#B9D0FA",
            padding=(8, 4),
        )

        style.configure(
            "Module.TCheckbutton",
            background=self.palette["panel"],
            foreground=self.palette["text"],
            font=("Segoe UI", 9),
        )
        style.map(
            "Module.TCheckbutton",
            background=[("active", self.palette["panel"])],
            foreground=[("active", self.palette["text"])],
        )

        style.configure(
            "Case.TEntry",
            fieldbackground="#FFFFFF",
            foreground=self.palette["text"],
            insertcolor=self.palette["text"],
            bordercolor="#C8D0DA",
            selectbackground="#DCEBFF",
            selectforeground="#111111",
        )

        style.configure(
            "Forensic.Treeview",
            background="#FFFFFF",
            fieldbackground="#FFFFFF",
            foreground=self.palette["text"],
            bordercolor="#D1D8E1",
            rowheight=26,
        )
        style.map(
            "Forensic.Treeview",
            background=[("selected", "#DCEBFF")],
            foreground=[("selected", "#111111")],
        )
        style.configure(
            "Forensic.Treeview.Heading",
            background="#F1F4F8",
            foreground=self.palette["text"],
            relief="flat",
            font=("Segoe UI Semibold", 8),
        )

        style.map("TNotebook.Tab", foreground=[("selected", "#111111")])

    def _build_layout(self):
        self._build_menu()

        self._build_toolbar()

        root = ttk.Frame(self, style="Base.TFrame")
        root.pack(fill="both", expand=True)

        horizontal_panes = tk.PanedWindow(
            root,
            orient="horizontal",
            sashwidth=5,
            sashrelief="raised",
            bg=self.palette["bg"],
        )
        horizontal_panes.pack(fill="both", expand=True, padx=8, pady=(8, 0))

        left_frame = ttk.Frame(horizontal_panes, style="Panel.TFrame", padding=10)
        center_holder = ttk.Frame(horizontal_panes, style="Base.TFrame")
        right_frame = ttk.Frame(horizontal_panes, style="Panel.TFrame", padding=10)

        horizontal_panes.add(left_frame, minsize=260)
        horizontal_panes.add(center_holder, minsize=600)
        horizontal_panes.add(right_frame, minsize=250)

        self._build_left_panel(left_frame)
        self._build_center_panel(center_holder)
        self._build_right_panel(right_frame)
        self._build_status_bar()

        self._watch_module_selection()

    def _build_toolbar(self):
        toolbar = ttk.Frame(self, style="Toolbar.TFrame", padding=(10, 7))
        toolbar.pack(fill="x", side="top")

        try:
            from PIL import Image, ImageTk
            logo_img = Image.open(get_asset_path("shadowtrace_logo.png")).resize((28, 28), Image.Resampling.LANCZOS)
            self.toolbar_logo = ImageTk.PhotoImage(logo_img)
            tk.Label(toolbar, image=self.toolbar_logo, background=self.palette["bg"]).pack(side="left", padx=(2, 8))
        except Exception as e:
            pass

        ttk.Label(toolbar, text="ShadowTrace", style="Header.TLabel").pack(side="left", padx=(0, 16))

        ttk.Button(toolbar, text="Open", style="ToolbarButton.TButton", command=self.load_image).pack(side="left", padx=3)
        ttk.Button(toolbar, text="Analyze", style="ToolbarButton.TButton", command=self.start_analysis).pack(side="left", padx=3)
        ttk.Button(toolbar, text="Export", style="ToolbarButton.TButton", command=self._show_report_dialog).pack(side="left", padx=3)
        ttk.Button(toolbar, text="Select All", style="ToolbarButton.TButton", command=self.select_all_modules).pack(side="left", padx=3)
        ttk.Button(toolbar, text="Clear", style="ToolbarButton.TButton", command=self.clear_all_modules).pack(side="left", padx=3)

        meta = ttk.Frame(toolbar, style="Toolbar.TFrame")
        meta.pack(side="right")
        ttk.Label(meta, text="Case:", style="ToolbarText.TLabel").pack(side="left")
        ttk.Entry(meta, textvariable=self.case_name, width=15, style="Case.TEntry").pack(side="left", padx=(5, 10))
        ttk.Label(meta, text="Examiner:", style="ToolbarText.TLabel").pack(side="left")
        ttk.Entry(meta, textvariable=self.examiner, width=13, style="Case.TEntry").pack(side="left", padx=(5, 0))

    def _build_left_panel(self, parent):
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=3)
        parent.rowconfigure(3, weight=2)

        ttk.Label(parent, text="Evidence Browser", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")

        tree_wrap = ttk.Frame(parent, style="Surface.TFrame")
        tree_wrap.grid(row=1, column=0, sticky="nsew", pady=(6, 10))
        tree_wrap.rowconfigure(0, weight=1)
        tree_wrap.columnconfigure(0, weight=1)

        self.nav_tree = ttk.Treeview(tree_wrap, style="Forensic.Treeview", show="tree")
        self.nav_tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll = ttk.Scrollbar(tree_wrap, orient="vertical", command=self.nav_tree.yview)
        tree_scroll.grid(row=0, column=1, sticky="ns")
        self.nav_tree.configure(yscrollcommand=tree_scroll.set)
        self.nav_tree.bind("<<TreeviewSelect>>", self._on_nav_tree_select)
        self.nav_tree.bind("<Double-1>", self._on_nav_tree_double_click)

        root_item = self.nav_tree.insert("", "end", text="Case - No image", open=True)
        self.nav_tree.insert(root_item, "end", text="Evidence")
        self.nav_tree.insert(root_item, "end", text="Artifacts")
        self.nav_tree.insert(root_item, "end", text="Findings")
        self.nav_tree.insert(root_item, "end", text="Reports")

        ttk.Label(parent, text="Module Filters", style="PanelTitle.TLabel").grid(row=2, column=0, sticky="w", pady=(2, 0))

        module_wrap = ttk.Frame(parent, style="Panel.TFrame")
        module_wrap.grid(row=3, column=0, sticky="nsew", pady=(6, 6))

        for idx, (name, var) in enumerate(self.module_vars.items()):
            ttk.Checkbutton(module_wrap, text=name, variable=var, style="Module.TCheckbutton").grid(
                row=idx,
                column=0,
                sticky="w",
                pady=3,
            )

    def _build_center_panel(self, parent):
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)

        center_split = tk.PanedWindow(
            parent,
            orient="vertical",
            sashwidth=5,
            sashrelief="flat",
            bg=self.palette["bg"],
        )
        center_split.grid(row=0, column=0, sticky="nsew")

        top = ttk.Frame(center_split, style="Panel.TFrame", padding=10)
        bottom = ttk.Frame(center_split, style="Panel.TFrame", padding=10)
        center_split.add(top, minsize=300)
        center_split.add(bottom, minsize=160)

        top.columnconfigure(0, weight=1)
        top.rowconfigure(2, weight=1)

        header = ttk.Frame(top, style="Panel.TFrame")
        header.grid(row=0, column=0, columnspan=2, sticky="ew")
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="Workspace", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")

        self._workspace_tabs_outer = ttk.Frame(top, style="Panel.TFrame")
        self._workspace_tabs_outer.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(6, 4))
        self._workspace_tabs_outer.columnconfigure(0, weight=1)

        self._workspace_tabs_canvas = tk.Canvas(
            self._workspace_tabs_outer,
            bg=self.palette["panel"],
            highlightthickness=0,
            height=30,
        )
        self._workspace_tabs_canvas.grid(row=0, column=0, sticky="ew")

        self._workspace_tabs_scrollbar = ttk.Scrollbar(
            self._workspace_tabs_outer,
            orient="horizontal",
            command=self._workspace_tabs_canvas.xview,
        )
        # scrollbar starts hidden; shown only when tabs overflow

        self.workspace_tabs_frame = ttk.Frame(self._workspace_tabs_canvas, style="Panel.TFrame")
        self._workspace_tabs_canvas.create_window((0, 0), window=self.workspace_tabs_frame, anchor="nw")
        self.workspace_tabs_frame.bind("<Configure>", self._on_workspace_tabs_configure)
        self._workspace_tabs_canvas.configure(xscrollcommand=self._workspace_tabs_scrollbar.set)

        columns = ("module", "artifact", "severity", "status")
        self.results_table = ttk.Treeview(top, columns=columns, show="headings", style="Forensic.Treeview")
        self.results_table.heading("module", text="Module")
        self.results_table.heading("artifact", text="Artifact")
        self.results_table.heading("severity", text="Severity")
        self.results_table.heading("status", text="Status")
        self.results_table.column("module", width=220, anchor="w")
        self.results_table.column("artifact", width=260, anchor="w")
        self.results_table.column("severity", width=100, anchor="center")
        self.results_table.column("status", width=150, anchor="center")
        self.results_table.grid(row=2, column=0, sticky="nsew", pady=(4, 0))

        table_scroll = ttk.Scrollbar(top, orient="vertical", command=self.results_table.yview)
        table_scroll.grid(row=2, column=1, sticky="ns", pady=(4, 0))
        self.results_table.configure(yscrollcommand=table_scroll.set)

        bottom.columnconfigure(0, weight=1)
        bottom.rowconfigure(1, weight=1)
        ttk.Label(bottom, text="Activity Log", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")

        self.console = tk.Text(
            bottom,
            bg="#FFFFFF",
            fg="#1E1E1E",
            insertbackground="#1E1E1E",
            relief="flat",
            font=("Cascadia Mono", 9),
            wrap="word",
            padx=9,
            pady=8,
        )
        self.console.grid(row=1, column=0, sticky="nsew", pady=(6, 0))
        log_scroll = ttk.Scrollbar(bottom, orient="vertical", command=self.console.yview)
        log_scroll.grid(row=1, column=1, sticky="ns", pady=(6, 0))
        self.console.configure(yscrollcommand=log_scroll.set)

    def _build_right_panel(self, parent):
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(2, weight=1)

        ttk.Label(parent, text="Inspector", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")

        summary = ttk.Frame(parent, style="Surface.TFrame", padding=10)
        summary.grid(row=1, column=0, sticky="ew", pady=(6, 10))
        summary.columnconfigure(1, weight=1)

        self.stats_labels = {
            "Loaded Image": ttk.Label(summary, text="No", background=self.palette["surface"], foreground=self.palette["muted"], font=("Segoe UI", 9)),
            "Selected Modules": ttk.Label(summary, text="6", background=self.palette["surface"], foreground=self.palette["muted"], font=("Segoe UI", 9)),
            "Last Analysis": ttk.Label(summary, text="Not started", background=self.palette["surface"], foreground=self.palette["muted"], font=("Segoe UI", 9)),
            "Report Status": ttk.Label(summary, text="Not generated", background=self.palette["surface"], foreground=self.palette["muted"], font=("Segoe UI", 9)),
        }

        for idx, (name, widget) in enumerate(self.stats_labels.items()):
            ttk.Label(
                summary,
                text=name,
                background=self.palette["surface"],
                foreground=self.palette["text"],
                font=("Segoe UI Semibold", 9),
            ).grid(row=idx, column=0, sticky="w", pady=3)
            widget.grid(row=idx, column=1, sticky="e", pady=3)

        detail_tabs = ttk.Notebook(parent)
        detail_tabs.grid(row=2, column=0, sticky="nsew")

        meta_tab = tk.Frame(detail_tabs, bg="#FFFFFF")
        queue_tab = tk.Frame(detail_tabs, bg="#FFFFFF")
        detail_tabs.add(meta_tab, text="Artifact Details")
        detail_tabs.add(queue_tab, text="Module Queue")

        self.details_box = tk.Text(
            meta_tab,
            bg="#FFFFFF",
            fg="#1E1E1E",
            relief="flat",
            wrap="word",
            font=("Segoe UI", 9),
            padx=8,
            pady=8,
            state="normal",
        )
        self.details_box.pack(fill="both", expand=True)
        self.details_box.insert(
            "end",
            "Select an artifact row from Analysis Results to inspect metadata and notes.\n",
        )
        self.details_box.configure(state="disabled")

        self.queue_box = tk.Text(
            queue_tab,
            bg="#FFFFFF",
            fg="#1E1E1E",
            relief="flat",
            wrap="word",
            font=("Cascadia Mono", 9),
            padx=8,
            pady=8,
            state="normal",
        )
        self.queue_box.pack(fill="both", expand=True)
        self._refresh_module_queue_text()

        self.results_table.bind("<<TreeviewSelect>>", self._on_result_select)

    def _build_status_bar(self):
        status = ttk.Frame(self, style="Toolbar.TFrame")
        status.pack(fill="x", side="bottom")
        ttk.Label(
            status,
            textvariable=self.status_text,
            style="ToolbarText.TLabel",
            padding=(10, 4),
        ).pack(side="left")

    def _build_menu(self):
        menu_bar = tk.Menu(self)
        menu_bar.configure(bg="#F6F8FB", fg="#172033", activebackground="#DCEBFF", activeforeground="#172033")

        file_menu = tk.Menu(menu_bar, tearoff=False)
        file_menu.add_command(label="Load Forensic Image", command=self.load_image)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)
        menu_bar.add_cascade(label="File", menu=file_menu)

        analysis_menu = tk.Menu(menu_bar, tearoff=False)
        analysis_menu.add_command(label="Start Analysis", command=self.start_analysis)
        analysis_menu.add_command(label="Select All Modules", command=self.select_all_modules)
        analysis_menu.add_command(label="Clear Modules", command=self.clear_all_modules)
        menu_bar.add_cascade(label="Analysis", menu=analysis_menu)

        help_menu = tk.Menu(menu_bar, tearoff=False)
        help_menu.add_command(label="About", command=self.show_about)
        menu_bar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menu_bar)

    # show_export_hint replaced by _show_report_dialog (see below)

    def _watch_module_selection(self):
        def refresh_count(*_):
            selected = sum(1 for v in self.module_vars.values() if v.get())
            self.stats_labels["Selected Modules"].configure(text=str(selected))
            self._refresh_module_queue_text()

        for var in self.module_vars.values():
            var.trace_add("write", refresh_count)
        refresh_count()

    def _selected_module_names(self):
        return [name for name, var in self.module_vars.items() if var.get()]

    def _on_workspace_tabs_configure(self, _event=None):
        self._workspace_tabs_canvas.configure(
            scrollregion=self._workspace_tabs_canvas.bbox("all"),
        )
        self._workspace_tabs_canvas.update_idletasks()
        canvas_width = self._workspace_tabs_canvas.winfo_width()
        content_width = self.workspace_tabs_frame.winfo_reqwidth()
        if content_width > canvas_width:
            self._workspace_tabs_scrollbar.grid(row=1, column=0, sticky="ew")
        else:
            self._workspace_tabs_scrollbar.grid_forget()

    def _refresh_workspace_module_tabs(self):
        for child in self.workspace_tabs_frame.winfo_children():
            child.destroy()

        if not self._analysis_completed:
            self.active_workspace_module = None
            self._apply_workspace_filter()
            return

        display_modules = self._last_analyzed_modules
        if not display_modules:
            self.active_workspace_module = None
            self._apply_workspace_filter()
            return

        if self.active_workspace_module not in display_modules:
            self.active_workspace_module = display_modules[0]

        for idx, module_name in enumerate(display_modules):
            style_name = "WorkspaceTabActive.TButton" if module_name == self.active_workspace_module else "WorkspaceTab.TButton"
            ttk.Button(
                self.workspace_tabs_frame,
                text=module_name,
                style=style_name,
                command=lambda name=module_name: self._set_active_workspace_module(name),
            ).grid(row=0, column=idx, sticky="w", padx=(0, 6))

        self._apply_workspace_filter()

    def _set_active_workspace_module(self, module_name):
        self.active_workspace_module = module_name
        self._refresh_workspace_module_tabs()

    def _apply_workspace_filter(self):
        for row_id in self.results_table.get_children():
            self.results_table.delete(row_id)
        self.result_finding_map.clear()

        filtered_findings = list(self.all_findings)

        if self.active_workspace_module:
            filtered_findings = [f for f in filtered_findings if f.module == self.active_workspace_module]

        if self._active_severity_filter:
            filtered_findings = [f for f in filtered_findings if f.severity == self._active_severity_filter]

        if not filtered_findings:
            label = self._active_severity_filter or self.active_workspace_module or "Selected Modules"
            self.results_table.insert("", "end", values=(label, "No findings available", "Info", "Clean"))
            return

        for finding in filtered_findings:
            item_id = self.results_table.insert(
                "",
                "end",
                values=(finding.module, finding.artifact, finding.severity, finding.status),
            )
            self.result_finding_map[item_id] = finding

    def _write_welcome_log(self):
        self._log("ShadowTrace initialized.")
        self._log("Open a forensic image from File > Load Forensic Image.")
        self._log("Select modules and click Analyze to begin.")

    def _log(self, message, tag="INFO"):
        now = datetime.now().strftime("%H:%M:%S")
        self.console.insert("end", f"{now}  {tag:<5}  {message}\n")
        self.console.see("end")

    def _set_status(self, text):
        self.status_text.set(text)

    def _is_forensic_image(self, file_path):
        return file_path.lower().endswith(self.forensic_image_extensions)

    def _forensic_filetypes(self):
        patterns = " ".join(f"*{ext}" for ext in self.forensic_image_extensions)
        return [("Forensic images", patterns)]

    def _refresh_module_queue_text(self):
        enabled = [name for name, var in self.module_vars.items() if var.get()]
        disabled = [name for name, var in self.module_vars.items() if not var.get()]

        self.queue_box.configure(state="normal")
        self.queue_box.delete("1.0", "end")
        self.queue_box.insert("end", "Enabled modules:\n")
        for idx, name in enumerate(enabled, start=1):
            self.queue_box.insert("end", f"  {idx}. {name}\n")

        self.queue_box.insert("end", "\nDisabled modules:\n")
        for idx, name in enumerate(disabled, start=1):
            self.queue_box.insert("end", f"  {idx}. {name}\n")

        self.queue_box.configure(state="disabled")

    def _populate_sample_results(self, findings):
        self.all_findings = list(findings)
        self._apply_workspace_filter()

    def _on_result_select(self, _event):
        selection = self.results_table.selection()
        if not selection:
            return
        finding = self.result_finding_map.get(selection[0])
        if not finding:
            return

        details = finding.details or {}
        timestamps = details.get("timestamps", {})
        entropy = details.get("sample_entropy")
        printable_ratio = details.get("printable_ratio")
        null_ratio = details.get("null_ratio")
        ntfs_attr_encrypted = details.get("ntfs_attr_encrypted")
        ntfs_run_encrypted = details.get("ntfs_run_encrypted")
        efs_stream_present = details.get("efs_stream_present")
        stream_names = details.get("stream_names")
        ads_streams = details.get("ads_streams")
        name_traits = details.get("name_traits")
        partition_description = details.get("partition_description")
        start_sector = details.get("start_sector")
        end_sector = details.get("end_sector")
        length_sectors = details.get("length_sectors")
        is_allocated = details.get("is_allocated")
        is_unallocated = details.get("is_unallocated")
        is_metadata = details.get("is_metadata")
        has_filesystem = details.get("has_filesystem")
        filesystem_offset = details.get("filesystem_offset")
        filesystem_error = details.get("filesystem_error")
        total_partitions = details.get("total_partitions")
        extension = details.get("extension")
        size = details.get("size")
        is_deleted = details.get("is_deleted")
        wipe_pattern = details.get("wipe_pattern")
        deletion_indicators = details.get("deletion_indicators")
        wipe_ratio = details.get("wipe_ratio")
        region_size_mb = details.get("region_size_mb")
        scanned_mb = details.get("scanned_mb")
        zero_filled_blocks = details.get("zero_filled_blocks")
        pattern_filled_blocks = details.get("pattern_filled_blocks")
        random_filled_blocks = details.get("random_filled_blocks")
        detected_patterns = details.get("detected_patterns")
        detected_type = details.get("detected_type")
        expected_type = details.get("expected_type")
        header_hex = details.get("header_hex")
        integrity_rules = details.get("integrity_rules")
        self.details_box.configure(state="normal")
        self.details_box.delete("1.0", "end")
        self.details_box.insert("end", f"Module: {finding.module}\n")
        self.details_box.insert("end", f"Artifact: {finding.artifact}\n")
        self.details_box.insert("end", f"Severity: {finding.severity}\n")
        self.details_box.insert("end", f"Status: {finding.status}\n")
        self.details_box.insert("end", f"Confidence: {finding.confidence}%\n")
        self.details_box.insert("end", f"Rules: {', '.join(finding.rules)}\n\n")

        if extension is not None:
            self.details_box.insert("end", f"File Extension: {extension}\n")
        if size is not None:
            self.details_box.insert("end", f"File Size     : {size} bytes\n")
        if entropy is not None:
            self.details_box.insert("end", f"Sample Entropy: {entropy}\n")
        if printable_ratio is not None:
            self.details_box.insert("end", f"Printable Ratio: {printable_ratio}\n")
        if null_ratio is not None:
            self.details_box.insert("end", f"Null Byte Ratio: {null_ratio}\n")
        if ntfs_attr_encrypted is not None:
            self.details_box.insert("end", f"NTFS Attr Encrypted: {ntfs_attr_encrypted}\n")
        if ntfs_run_encrypted is not None:
            self.details_box.insert("end", f"NTFS Run Encrypted : {ntfs_run_encrypted}\n")
        if efs_stream_present is not None:
            self.details_box.insert("end", f"EFS Stream Present : {efs_stream_present}\n")
        if stream_names:
            self.details_box.insert("end", f"Named Streams     : {', '.join(stream_names)}\n")
        if ads_streams:
            self.details_box.insert("end", f"ADS Streams       : {', '.join(ads_streams)}\n")
        if name_traits:
            self.details_box.insert("end", f"Name Traits       : {', '.join(name_traits)}\n")
        if partition_description is not None:
            self.details_box.insert("end", f"Partition Desc    : {partition_description}\n")
        if start_sector is not None:
            self.details_box.insert("end", f"Start Sector      : {start_sector}\n")
        if end_sector is not None:
            self.details_box.insert("end", f"End Sector        : {end_sector}\n")
        if length_sectors is not None:
            self.details_box.insert("end", f"Length (Sectors)  : {length_sectors}\n")
        if is_allocated is not None:
            self.details_box.insert("end", f"Allocated Flag    : {is_allocated}\n")
        if is_unallocated is not None:
            self.details_box.insert("end", f"Unallocated Flag  : {is_unallocated}\n")
        if is_metadata is not None:
            self.details_box.insert("end", f"Metadata Flag     : {is_metadata}\n")
        if has_filesystem is not None:
            self.details_box.insert("end", f"Filesystem Found  : {has_filesystem}\n")
        if filesystem_offset is not None:
            self.details_box.insert("end", f"Filesystem Offset : {filesystem_offset}\n")
        if filesystem_error:
            self.details_box.insert("end", f"Filesystem Error  : {filesystem_error}\n")
        if total_partitions is not None:
            self.details_box.insert("end", f"Total Partitions  : {total_partitions}\n")
        if is_deleted is not None:
            self.details_box.insert("end", f"Deleted Flag      : {is_deleted}\n")
        if wipe_pattern:
            self.details_box.insert("end", f"Wipe Pattern      : {wipe_pattern}\n")
        if wipe_ratio is not None:
            self.details_box.insert("end", f"Wipe Coverage     : {round(wipe_ratio * 100, 1)}%\n")
        if region_size_mb is not None:
            self.details_box.insert("end", f"Region Size       : {region_size_mb} MB\n")
        if scanned_mb is not None:
            self.details_box.insert("end", f"Scanned           : {scanned_mb} MB\n")
        if zero_filled_blocks is not None:
            self.details_box.insert("end", f"Zero-Filled Blocks: {zero_filled_blocks}\n")
        if pattern_filled_blocks is not None:
            self.details_box.insert("end", f"Pattern Blocks    : {pattern_filled_blocks}\n")
        if random_filled_blocks is not None:
            self.details_box.insert("end", f"Random Blocks     : {random_filled_blocks}\n")
        if detected_patterns:
            self.details_box.insert("end", f"Detected Patterns : {', '.join(detected_patterns)}\n")
        if deletion_indicators:
            self.details_box.insert("end", f"Deletion Rules    : {', '.join(deletion_indicators)}\n")
        if detected_type:
            self.details_box.insert("end", f"Detected Type     : {detected_type}\n")
        if expected_type:
            self.details_box.insert("end", f"Expected Extension: {expected_type}\n")
        if header_hex:
            self.details_box.insert("end", f"Header (hex)      : {header_hex}\n")
        if integrity_rules:
            self.details_box.insert("end", f"Integrity Rules   : {', '.join(integrity_rules)}\n")
        if any(v is not None for v in (extension, size, entropy, printable_ratio, null_ratio)):
            self.details_box.insert("end", "\n")

        self.details_box.insert("end", "Timestamps\n")
        self.details_box.insert("end", self._format_timestamp_block("Created", timestamps.get("created")))
        self.details_box.insert("end", self._format_timestamp_block("Modified", timestamps.get("modified")))
        self.details_box.insert("end", self._format_timestamp_block("Accessed", timestamps.get("accessed")))
        self.details_box.insert("end", self._format_timestamp_block("Changed", timestamps.get("changed")))
        self.details_box.configure(state="disabled")

    def _format_timestamp_block(self, label, timestamp_value):
        if not timestamp_value:
            return f"  {label:<8}: N/A\n\n"

        if isinstance(timestamp_value, dict):
            utc_text = timestamp_value.get("utc", "N/A")
            return f"  {label:<8}: {utc_text}\n\n"

        return f"  {label:<8}: {timestamp_value}\n\n"

    def load_image(self):
        selected = filedialog.askopenfilename(title="Select Forensic Image", filetypes=self._forensic_filetypes())
        if not selected:
            return

        if not self._is_forensic_image(selected):
            messagebox.showerror(
                "Invalid Evidence Type",
                "Only forensic image files are allowed.\n\n"
                "Accepted types: " + ", ".join(self.forensic_image_extensions),
            )
            self._set_status("Blocked | Invalid file type")
            self._log(f"Rejected non-forensic input: {os.path.basename(selected)}", tag="WARN")
            return

        self.image_path.set(selected)
        self.stats_labels["Loaded Image"].configure(text="Yes", foreground=self.palette["ok"])
        self._set_status("Ready | Image loaded")
        self._log(f"Loaded forensic image: {os.path.basename(selected)}")

        # Reset analysis state for new image
        self._analysis_completed = False
        self._last_analyzed_modules = []
        self._module_summaries = {}
        self._analysis_time = None
        self._nav_node_map.clear()
        self._active_severity_filter = None
        self.all_findings = []
        self.active_workspace_module = None
        self._refresh_workspace_module_tabs()
        self.stats_labels["Last Analysis"].configure(text="Not started")
        self.stats_labels["Report Status"].configure(text="Not generated", foreground=self.palette["muted"])

        for item in self.nav_tree.get_children():
            self.nav_tree.delete(item)

        case_root = self.nav_tree.insert("", "end", text=f"Case - {os.path.basename(selected)}", open=True)
        evidence = self.nav_tree.insert(case_root, "end", text="Evidence", open=True)
        self.nav_tree.insert(evidence, "end", text=os.path.basename(selected))
        self.nav_tree.insert(case_root, "end", text="Artifacts")
        self.nav_tree.insert(case_root, "end", text="Findings")
        self.nav_tree.insert(case_root, "end", text="Reports")

    def select_all_modules(self):
        for var in self.module_vars.values():
            var.set(True)
        self._set_status("Ready | All modules selected")

    def clear_all_modules(self):
        for var in self.module_vars.values():
            var.set(False)
        self._set_status("Ready | All modules cleared")

    def start_analysis(self):
        if self.image_path.get() == "No forensic image loaded":
            messagebox.showwarning("Image Required", "Please load a forensic image before analysis.")
            self._set_status("Blocked | No image loaded")
            return

        selected_modules = [name for name, var in self.module_vars.items() if var.get()]
        if not selected_modules:
            messagebox.showwarning("Modules Required", "Select at least one module to continue.")
            self._set_status("Blocked | No modules selected")
            return

        unsupported_modules = [name for name in selected_modules if name not in self.module_registry]
        if unsupported_modules:
            self._log(
                "Skipping not-yet-implemented modules: " + ", ".join(unsupported_modules),
                tag="WARN",
            )

        implemented_modules = [name for name in selected_modules if name in self.module_registry]
        if not implemented_modules:
            self._set_status("Blocked | Selected modules not implemented")
            return

        self._set_status("Analyzing | Prototype mode")
        self._log("------------------------------------------------", tag="PIPE")
        self._log(f"Case Name: {self.case_name.get()}")
        self._log(f"Examiner: {self.examiner.get()}")
        self._log("Analysis pipeline started")
        self._log(f"Modules queued: {', '.join(implemented_modules)}")

        combined_findings = []
        total_files_scanned = 0
        total_suspicious = 0

        for module_name in implemented_modules:
            engine = self.module_registry[module_name]
            try:
                report = engine.analyze(
                    evidence_path=self.image_path.get(),
                    case_name=self.case_name.get(),
                    examiner=self.examiner.get(),
                )
            except Exception as exc:
                messagebox.showerror("Analysis Failed", f"{module_name} could not complete.\n\n{exc}")
                self._set_status("Blocked | Analysis failed")
                self._log(f"{module_name} error: {exc}", tag="ERROR")
                return

            module_scanned = report.summary.get("totalFilesScanned", 0)
            module_suspicious = report.summary.get("suspiciousFiles", 0)
            total_files_scanned += module_scanned
            total_suspicious += module_suspicious

            remaining_capacity = max(0, self.MAX_GUI_FINDINGS - len(combined_findings))
            if remaining_capacity > 0:
                combined_findings.extend(report.findings[:remaining_capacity])

            if len(report.findings) > remaining_capacity:
                omitted = len(report.findings) - remaining_capacity
                self._log(f"{module_name}: omitted {omitted} findings from GUI view for stability", tag="WARN")

            self._module_summaries[module_name] = report.summary

            self._log(f"{module_name}: scanned {module_scanned} files")
            self._log(f"{module_name}: suspicious files {module_suspicious}")

        self._analysis_completed = True
        self._analysis_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._last_analyzed_modules = list(implemented_modules)
        self._populate_sample_results(combined_findings)
        self._refresh_workspace_module_tabs()
        self._populate_evidence_browser()

        self.stats_labels["Loaded Image"].configure(text="Yes", foreground=self.palette["ok"])
        self.stats_labels["Last Analysis"].configure(text=datetime.now().strftime("%Y-%m-%d %H:%M"))
        report_status = "Pending generation" if combined_findings else "No anomalies detected"
        self.stats_labels["Report Status"].configure(text=report_status, foreground=self.palette["warn"])

        self._log(f"Total files scanned: {total_files_scanned}")
        self._log(f"Total suspicious files: {total_suspicious}")
        if combined_findings:
            self._log(f"Total findings: {len(combined_findings)}", tag="NOTE")
        else:
            self._log("No suspicious indicators detected by enabled modules.", tag="NOTE")

    def set_button_theme(self, button, primary=True):
        style = "ToolbarButton.TButton" if primary else "Secondary.TButton"
        button.configure(style=style)

    def show_about(self):
        about_win = tk.Toplevel(self)
        about_win.title("About ShadowTrace")
        about_win.geometry("360x420")
        about_win.resizable(False, False)
        about_win.configure(bg=self.palette["bg"])
        about_win.transient(self)
        about_win.grab_set()

        try:
            from PIL import Image, ImageTk
            logo_img = Image.open(get_asset_path("shadowtrace_logo.png")).resize((120, 120), Image.Resampling.LANCZOS)
            self.about_logo = ImageTk.PhotoImage(logo_img)
            tk.Label(about_win, image=self.about_logo, bg=self.palette["bg"]).pack(pady=(20, 10))
        except Exception:
            pass

        tk.Label(about_win, text="ShadowTrace v1.0", font=("Segoe UI Semibold", 16), bg=self.palette["bg"], fg=self.palette["text"]).pack()
        tk.Label(about_win, text="Advanced Digital Forensics", font=("Segoe UI", 10), bg=self.palette["bg"], fg=self.palette["muted"]).pack(pady=(0, 20))
        
        team_frame = tk.Frame(about_win, bg=self.palette["bg"])
        team_frame.pack(fill="x", padx=40)
        
        tk.Label(team_frame, text="Developed with love by:", font=("Segoe UI Semibold", 11), bg=self.palette["bg"], fg=self.palette["text"]).pack(anchor="w", pady=(0, 10))
        
        for name in ["Waseem Sajjad", "Umar Farooq", "Faisal Yaseen", "Hamiz Rathore"]:
            tk.Label(team_frame, text=f"• {name}", font=("Segoe UI", 11), bg=self.palette["bg"], fg=self.palette["text"]).pack(anchor="w", pady=2)
            
        ttk.Button(about_win, text="Close", style="ToolbarButton.TButton", command=about_win.destroy).pack(side="bottom", pady=20)

    # ================================================================ #
    #  Evidence Browser: Artifacts / Findings / Reports                 #
    # ================================================================ #

    def _populate_evidence_browser(self):
        """Rebuild the nav tree with analysis results."""
        self._nav_node_map.clear()

        for item in self.nav_tree.get_children():
            self.nav_tree.delete(item)

        img_name = os.path.basename(self.image_path.get())
        case_root = self.nav_tree.insert("", "end", text=f"Case - {img_name}", open=True)

        # -- Evidence --
        ev = self.nav_tree.insert(case_root, "end", text="Evidence", open=True)
        self.nav_tree.insert(ev, "end", text=img_name)

        # -- Artifacts (per-module counts) --
        mc = {}
        for f in self.all_findings:
            mc[f.module] = mc.get(f.module, 0) + 1
        total_artifacts = len(self.all_findings)
        art_root = self.nav_tree.insert(
            case_root, "end",
            text=f"Artifacts ({total_artifacts})",
            open=True,
        )
        self._nav_node_map[art_root] = {"type": "artifacts_root"}
        for mod in self._last_analyzed_modules:
            cnt = mc.get(mod, 0)
            nid = self.nav_tree.insert(art_root, "end", text=f"{mod} ({cnt})")
            self._nav_node_map[nid] = {"type": "artifact_module", "name": mod}

        # -- Findings (per-severity counts) --
        sc = {"High": 0, "Medium": 0, "Low": 0}
        for f in self.all_findings:
            sc[f.severity] = sc.get(f.severity, 0) + 1
        find_root = self.nav_tree.insert(
            case_root, "end",
            text=f"Findings ({total_artifacts})",
            open=True,
        )
        self._nav_node_map[find_root] = {"type": "findings_root"}
        for sev in ("High", "Medium", "Low"):
            if sc[sev] > 0:
                nid = self.nav_tree.insert(find_root, "end", text=f"{sev} Severity ({sc[sev]})")
                self._nav_node_map[nid] = {"type": "finding_severity", "severity": sev}

        # -- Reports --
        rep_root = self.nav_tree.insert(case_root, "end", text="Reports", open=True)
        self._nav_node_map[rep_root] = {"type": "reports_root"}
        gen_id = self.nav_tree.insert(rep_root, "end", text="\u2709  Generate Report")
        self._nav_node_map[gen_id] = {"type": "generate_report"}

        self._log("Evidence browser updated with analysis results.")

    def _on_nav_tree_select(self, _event):
        selection = self.nav_tree.selection()
        if not selection:
            return
        node_info = self._nav_node_map.get(selection[0])
        if not node_info:
            return

        ntype = node_info["type"]

        if ntype == "artifacts_root" or ntype == "findings_root":
            # Show all findings
            self._active_severity_filter = None
            self.active_workspace_module = None
            self._refresh_workspace_module_tabs()
            self._apply_workspace_filter()

        elif ntype == "artifact_module":
            mod_name = node_info["name"]
            self._active_severity_filter = None
            self.active_workspace_module = mod_name
            self._refresh_workspace_module_tabs()

        elif ntype == "finding_severity":
            sev = node_info["severity"]
            self._active_severity_filter = sev
            self.active_workspace_module = None
            self._refresh_workspace_module_tabs()
            self._apply_workspace_filter()

    def _on_nav_tree_double_click(self, _event):
        selection = self.nav_tree.selection()
        if not selection:
            return
        node_info = self._nav_node_map.get(selection[0])
        if not node_info:
            return
        if node_info["type"] in ("reports_root", "generate_report"):
            self._show_report_dialog()

    # ================================================================ #
    #  Report Generation Dialog                                         #
    # ================================================================ #

    def _show_report_dialog(self):
        if not self._analysis_completed:
            messagebox.showwarning(
                "No Analysis",
                "Please run an analysis before generating a report.",
            )
            return

        dlg = tk.Toplevel(self)
        dlg.title("Generate Forensic Report")
        dlg.geometry("520x560")
        dlg.resizable(False, False)
        dlg.configure(bg=self.palette["bg"])
        dlg.transient(self)
        dlg.grab_set()

        # -- Header --
        hdr = tk.Frame(dlg, bg="#1A3A6E", height=56)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(
            hdr, text="\u2709   Generate Forensic Report",
            bg="#1A3A6E", fg="#FFFFFF",
            font=("Segoe UI Semibold", 13),
        ).pack(side="left", padx=20)

        body = tk.Frame(dlg, bg=self.palette["bg"])
        body.pack(fill="both", expand=True, padx=24, pady=18)

        # -- Format selector --
        tk.Label(body, text="Report Format", bg=self.palette["bg"],
                 font=("Segoe UI Semibold", 10)).grid(row=0, column=0, sticky="w", pady=(0, 4))
        format_var = tk.StringVar(value="HTML Report")
        fmt_menu = ttk.Combobox(body, textvariable=format_var,
                                values=["HTML Report", "Plain Text"],
                                state="readonly", width=22)
        fmt_menu.grid(row=1, column=0, sticky="w", pady=(0, 14))

        # -- Sections --
        tk.Label(body, text="Include Sections", bg=self.palette["bg"],
                 font=("Segoe UI Semibold", 10)).grid(row=2, column=0, sticky="w", pady=(0, 4))

        section_defs = [
            ("executive_summary", "Executive Summary", True),
            ("case_info", "Case Information", True),
            ("module_details", "Module Analysis Results", True),
            ("findings_table", "Detailed Findings Table", True),
            ("statistics", "Statistics & Metrics", True),
            ("activity_log", "Activity Log", False),
        ]
        section_vars = {}
        for idx, (key, label, default) in enumerate(section_defs):
            v = tk.BooleanVar(value=default)
            section_vars[key] = v
            ttk.Checkbutton(body, text=label, variable=v,
                            style="Module.TCheckbutton").grid(
                row=3 + idx, column=0, sticky="w", padx=12, pady=1)

        # -- Separator --
        ttk.Separator(body, orient="horizontal").grid(
            row=10, column=0, columnspan=2, sticky="ew", pady=14)

        # -- Status label --
        status_var = tk.StringVar(value="Ready to generate report.")
        status_lbl = tk.Label(body, textvariable=status_var, bg=self.palette["bg"],
                              fg=self.palette["muted"], font=("Segoe UI", 9))
        status_lbl.grid(row=11, column=0, sticky="w", columnspan=2)

        # -- Buttons --
        btn_frame = tk.Frame(body, bg=self.palette["bg"])
        btn_frame.grid(row=12, column=0, columnspan=2, sticky="ew", pady=(14, 0))

        ttk.Button(
            btn_frame, text="Preview in Browser",
            style="ToolbarButton.TButton",
            command=lambda: self._preview_report_in_browser(
                format_var, section_vars, status_var),
        ).pack(side="left", padx=(0, 10))

        ttk.Button(
            btn_frame, text="Save Report",
            style="ToolbarButton.TButton",
            command=lambda: self._generate_and_save_report(
                dlg, format_var, section_vars, status_var),
        ).pack(side="left", padx=(0, 10))

        ttk.Button(
            btn_frame, text="Cancel",
            style="Secondary.TButton",
            command=dlg.destroy,
        ).pack(side="right")

    def _build_report_generator(self, section_vars):
        sections = {key: var.get() for key, var in section_vars.items()}
        log_text = self.console.get("1.0", "end")
        gen = ReportGenerator(
            case_name=self.case_name.get(),
            examiner=self.examiner.get(),
            image_path=self.image_path.get(),
            analysis_time=self._analysis_time or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            modules_analyzed=self._last_analyzed_modules,
            module_summaries=self._module_summaries,
            findings=self.all_findings,
            log_text=log_text,
        )
        return gen, sections

    def _preview_report_in_browser(self, format_var, section_vars, status_var):
        gen, sections = self._build_report_generator(section_vars)
        try:
            if format_var.get() == "HTML Report":
                content = gen.generate_html(sections)
                suffix = ".html"
            else:
                content = gen.generate_text(sections)
                suffix = ".txt"

            tmp = tempfile.NamedTemporaryFile(
                delete=False, suffix=suffix, prefix="shadowtrace_report_",
                mode="w", encoding="utf-8",
            )
            tmp.write(content)
            tmp.close()
            webbrowser.open(f"file:///{tmp.name}")
            status_var.set(f"Preview opened: {os.path.basename(tmp.name)}")
            self._log(f"Report preview opened in browser.", tag="NOTE")
        except Exception as exc:
            status_var.set(f"Preview failed: {exc}")

    def _generate_and_save_report(self, dlg, format_var, section_vars, status_var):
        gen, sections = self._build_report_generator(section_vars)
        is_html = format_var.get() == "HTML Report"

        if is_html:
            filetypes = [("HTML files", "*.html"), ("All files", "*.*")]
            default_ext = ".html"
        else:
            filetypes = [("Text files", "*.txt"), ("All files", "*.*")]
            default_ext = ".txt"

        default_name = f"ShadowTrace_Report_{self.case_name.get()}_{datetime.now().strftime('%Y%m%d_%H%M')}"
        path = filedialog.asksaveasfilename(
            title="Save Forensic Report",
            filetypes=filetypes,
            defaultextension=default_ext,
            initialfile=default_name,
        )
        if not path:
            return

        try:
            content = gen.generate_html(sections) if is_html else gen.generate_text(sections)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)

            status_var.set(f"Report saved: {os.path.basename(path)}")
            self.stats_labels["Report Status"].configure(
                text="Generated", foreground=self.palette["ok"],
            )
            self._log(f"Report saved to: {path}", tag="NOTE")
            self._set_status(f"Report saved | {os.path.basename(path)}")

            if is_html and messagebox.askyesno(
                "Report Saved",
                f"Report saved to:\n{path}\n\nOpen in browser?",
            ):
                webbrowser.open(f"file:///{path}")
        except Exception as exc:
            status_var.set(f"Save failed: {exc}")
            messagebox.showerror("Save Failed", f"Could not save report:\n{exc}")


if __name__ == "__main__":
    app = AntiForensicsDetectionApp()
    app.mainloop()
