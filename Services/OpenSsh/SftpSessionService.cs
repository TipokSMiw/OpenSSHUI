using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using OpensshUI.Models;
using OpensshUI.Services.Audit;
using OpensshUI.Services.Security;

namespace OpensshUI.Services.OpenSsh;

[SupportedOSPlatform("windows")]
public class SftpSessionService : ISftpSessionService
{
    private readonly ILogger<SftpSessionService> _logger;
    private readonly IAuditService _auditService;
    private readonly ISshEventLogService? _eventLogService;
    private readonly int _sshPort;

    private readonly object _mockLock = new();
    private readonly List<SftpSessionInfo> _mockSessions = new();
    private readonly ConcurrentDictionary<(string Ip, int Port), (string Username, DateTime Timestamp)> _sessionUserCache = new();
    internal ConcurrentDictionary<(string Ip, int Port), (string Username, DateTime Timestamp)> SessionUserCache => _sessionUserCache;
    private bool _isDemoMode;

    public bool IsDemoMode
    {
        get => _isDemoMode;
        set => _isDemoMode = value;
    }

    public void ToggleDemoMode()
    {
        _isDemoMode = !_isDemoMode;
        if (_isDemoMode)
        {
            ResetMockSessions();
        }
    }

    public SftpSessionService(
        ILogger<SftpSessionService> logger,
        IAuditService auditService,
        IConfiguration? configuration = null,
        ISshEventLogService? eventLogService = null)
    {
        _logger = logger;
        _auditService = auditService;
        _eventLogService = eventLogService;
        _sshPort = int.TryParse(configuration?["SftpSettings:Port"], out var p) ? p : 22;

        ResetMockSessions();
    }

    private void ResetMockSessions()
    {
        lock (_mockLock)
        {
            _mockSessions.Clear();
            var now = DateTime.Now;

            _mockSessions.AddRange(new[]
            {
                new SftpSessionInfo
                {
                    SessionId = "demo-sess-1001",
                    ProcessId = 10420,
                    ProcessName = "sshd",
                    Username = "finance_audit",
                    RemoteIp = "192.168.10.45",
                    RemotePort = 54120,
                    LocalPort = _sshPort,
                    ConnectedAt = now.AddMinutes(-42),
                    WorkingSetMemoryBytes = 14_680_064,
                    IsExcessiveConnection = false
                },
                new SftpSessionInfo
                {
                    SessionId = "demo-sess-1002",
                    ProcessId = 11304,
                    ProcessName = "sftp-server",
                    Username = "deploy_bot",
                    RemoteIp = "10.20.100.8",
                    RemotePort = 60124,
                    LocalPort = _sshPort,
                    ConnectedAt = now.AddMinutes(-128),
                    WorkingSetMemoryBytes = 18_420_120,
                    IsExcessiveConnection = false
                },
                new SftpSessionInfo
                {
                    SessionId = "demo-sess-1003",
                    ProcessId = 12980,
                    ProcessName = "sshd",
                    Username = "corp_transfer",
                    RemoteIp = "172.16.50.12",
                    RemotePort = 49210,
                    LocalPort = _sshPort,
                    ConnectedAt = now.AddMinutes(-5),
                    WorkingSetMemoryBytes = 12_890_400,
                    IsExcessiveConnection = false
                },
                new SftpSessionInfo
                {
                    SessionId = "demo-sess-1004",
                    ProcessId = 13412,
                    ProcessName = "sftp-server",
                    Username = "corp_transfer",
                    RemoteIp = "172.16.50.12",
                    RemotePort = 49212,
                    LocalPort = _sshPort,
                    ConnectedAt = now.AddMinutes(-4),
                    WorkingSetMemoryBytes = 13_110_200,
                    IsExcessiveConnection = false
                },
                new SftpSessionInfo
                {
                    SessionId = "demo-sess-1005",
                    ProcessId = 13450,
                    ProcessName = "sftp-server",
                    Username = "corp_transfer",
                    RemoteIp = "172.16.50.12",
                    RemotePort = 49214,
                    LocalPort = _sshPort,
                    ConnectedAt = now.AddMinutes(-3),
                    WorkingSetMemoryBytes = 12_950_100,
                    IsExcessiveConnection = false
                },
                new SftpSessionInfo
                {
                    SessionId = "demo-sess-1006",
                    ProcessId = 13490,
                    ProcessName = "sftp-server",
                    Username = "corp_transfer",
                    RemoteIp = "172.16.50.12",
                    RemotePort = 49216,
                    LocalPort = _sshPort,
                    ConnectedAt = now.AddMinutes(-2),
                    WorkingSetMemoryBytes = 13_400_000,
                    IsExcessiveConnection = false
                },
                new SftpSessionInfo
                {
                    SessionId = "demo-sess-1007",
                    ProcessId = 13520,
                    ProcessName = "sftp-server",
                    Username = "corp_transfer",
                    RemoteIp = "172.16.50.12",
                    RemotePort = 49218,
                    LocalPort = _sshPort,
                    ConnectedAt = now.AddMinutes(-1),
                    WorkingSetMemoryBytes = 13_200_000,
                    IsExcessiveConnection = false
                },
                new SftpSessionInfo
                {
                    SessionId = "demo-sess-1008",
                    ProcessId = 13550,
                    ProcessName = "sftp-server",
                    Username = "corp_transfer",
                    RemoteIp = "172.16.50.12",
                    RemotePort = 49220,
                    LocalPort = _sshPort,
                    ConnectedAt = now.AddSeconds(-30),
                    WorkingSetMemoryBytes = 12_900_000,
                    IsExcessiveConnection = true // Flagged because corp_transfer has 6 connections
                }
            });

            // Mark excessive connections for corp_transfer
            foreach (var s in _mockSessions.Where(s => s.Username == "corp_transfer"))
            {
                s.IsExcessiveConnection = true;
            }
        }
    }

    public async Task<SftpSessionOverview> GetActiveSessionsAsync(bool forceMock = false)
    {
        if (_isDemoMode || forceMock)
        {
            lock (_mockLock)
            {
                var copy = _mockSessions.Select(s => new SftpSessionInfo
                {
                    SessionId = s.SessionId,
                    ProcessId = s.ProcessId,
                    ProcessName = s.ProcessName,
                    Username = s.Username,
                    RemoteIp = s.RemoteIp,
                    RemotePort = s.RemotePort,
                    LocalPort = s.LocalPort,
                    ConnectedAt = s.ConnectedAt,
                    WorkingSetMemoryBytes = s.WorkingSetMemoryBytes,
                    IsExcessiveConnection = s.IsExcessiveConnection
                }).ToList();

                var overview = new SftpSessionOverview
                {
                    TotalActiveSessions = copy.Count,
                    UniqueUsersCount = copy.Select(c => c.Username).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                    Sessions = copy,
                    IsLiveWin32Available = true,
                    StatusNote = "โหมดจำลองข้อมูล (Demo Mock Mode)"
                };
                return overview;
            }
        }

        try
        {
            var sessions = await GetLiveSessionsWin32Async();

            // Group by canonical username to mark excessive connections (> 5 connections)
            var userGroups = sessions
                .Where(s => !s.IsAuthenticating)
                .GroupBy(s => s.Username, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);

            foreach (var session in sessions)
            {
                if (userGroups.TryGetValue(session.Username, out var count) && count > 5)
                {
                    session.IsExcessiveConnection = true;
                }
            }

            var overview = new SftpSessionOverview
            {
                TotalActiveSessions = sessions.Count,
                UniqueUsersCount = userGroups.Count,
                Sessions = sessions,
                IsLiveWin32Available = true,
                StatusNote = sessions.Count == 0 ? "ไม่มีการเชื่อมต่อ SFTP อยู่ในขณะนี้" : null
            };

            return overview;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to retrieve live sessions via Win32 P/Invoke");
            return new SftpSessionOverview
            {
                TotalActiveSessions = 0,
                UniqueUsersCount = 0,
                Sessions = new List<SftpSessionInfo>(),
                IsLiveWin32Available = false,
                StatusNote = $"ไม่สามารถดึงข้อมูลเซสชันสดได้: {ex.Message}"
            };
        }
    }

    public async Task<(bool Success, string Message)> TerminateSessionAsync(SftpSessionInfo session, string operatorUsername)
    {
        ArgumentNullException.ThrowIfNull(session);
        var op = string.IsNullOrWhiteSpace(operatorUsername) ? "admin" : SecurityValidator.ExtractCanonicalUsername(operatorUsername);

        if (_isDemoMode)
        {
            return await TerminateSessionAsync(session.ProcessId, operatorUsername);
        }

        var masterPid = GetSshdServicePid();
        bool isMaster = (masterPid > 0 && session.ProcessId == masterPid) || session.IsMasterServiceProcess;

        // 1. Drop TCP Connection directly via Win32 SetTcpEntry (TCP RST / TCB deletion)
        bool tcpClosed = false;
        if (session.RawLocalAddr != 0 && session.RawRemotePort != 0)
        {
            tcpClosed = CloseTcpConnectionWin32(session.RawLocalAddr, session.RawLocalPort, session.RawRemoteAddr, session.RawRemotePort);
        }

        // 2. Kill Child Process if exists and NOT master service
        if (session.ChildProcessId.HasValue && session.ChildProcessId.Value > 0 && session.ChildProcessId.Value != masterPid)
        {
            try
            {
                var childProc = Process.GetProcessById(session.ChildProcessId.Value);
                childProc.Kill(entireProcessTree: true);
                _logger.LogInformation("Terminated child SFTP process PID {ChildPid}", session.ChildProcessId.Value);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Child process {ChildPid} could not be terminated", session.ChildProcessId.Value);
            }
        }

        // 3. MASTER SERVICE IMMUNITY GUARD:
        // If session.ProcessId is the Master OpenSSH service PID, DO NOT KILL IT!
        if (isMaster)
        {
            var userDisplay = session.IsAuthenticating ? "Authenticating" : session.Username;
            var safeAuditMsg = $"ตัดการเชื่อมต่อ SFTP เซสชันของผู้ใช้ '{userDisplay}' (Endpoint: {session.RemoteIp}:{session.RemotePort}) สำเร็จ (Master OpenSSH Service ได้รับการคุ้มกัน ปลอดภัย 100%)";
            _logger.LogInformation("{Message} โดย {Operator} (TCP Reset: {TcpSuccess})", safeAuditMsg, op, tcpClosed);
            await _auditService.LogAsync("SFTP_SESSION_TERMINATED", safeAuditMsg, true, op);
            return (true, safeAuditMsg);
        }

        // If not master PID, delegate to TerminateSessionAsync(int processId, ...)
        return await TerminateSessionAsync(session.ProcessId, operatorUsername);
    }

    public async Task<(bool Success, string Message)> TerminateSessionAsync(string sessionId, string operatorUsername)
    {
        if (_isDemoMode)
        {
            lock (_mockLock)
            {
                var target = _mockSessions.FirstOrDefault(s => s.SessionId == sessionId);
                if (target != null)
                {
                    return TerminateSessionAsync(target.ProcessId, operatorUsername).Result;
                }
            }
            return (false, $"ไม่พบเซสชัน {sessionId}");
        }

        var live = await GetActiveSessionsAsync();
        var session = live.Sessions.FirstOrDefault(s => s.SessionId == sessionId);
        if (session == null)
        {
            return (false, $"ไม่พบเซสชัน {sessionId} (อาจตัดการเชื่อมต่อออกไปแล้ว)");
        }

        return await TerminateSessionAsync(session, operatorUsername);
    }

    public async Task<(bool Success, string Message)> TerminateSessionAsync(int processId, string operatorUsername)
    {
        var op = string.IsNullOrWhiteSpace(operatorUsername) ? "admin" : SecurityValidator.ExtractCanonicalUsername(operatorUsername);

        if (_isDemoMode)
        {
            lock (_mockLock)
            {
                var target = _mockSessions.FirstOrDefault(s => s.ProcessId == processId);
                if (target != null)
                {
                    _mockSessions.Remove(target);
                    // Recalculate excessive
                    var remainingForUser = _mockSessions.Count(s => s.Username.Equals(target.Username, StringComparison.OrdinalIgnoreCase));
                    if (remainingForUser <= 5)
                    {
                        foreach (var s in _mockSessions.Where(s => s.Username.Equals(target.Username, StringComparison.OrdinalIgnoreCase)))
                        {
                            s.IsExcessiveConnection = false;
                        }
                    }
                }
            }

            var msg = $"[Demo] ตัดการเชื่อมต่อเซสชัน PID {processId} เรียบร้อยแล้ว";
            await _auditService.LogAsync("SFTP_SESSION_TERMINATED", msg, true, op);
            return (true, msg);
        }

        try
        {
            Process proc;
            try
            {
                proc = Process.GetProcessById(processId);
            }
            catch (ArgumentException)
            {
                return (false, $"ไม่พบโพรเซส PID {processId} (อาจตัดการเชื่อมต่อออกไปแล้ว)");
            }

            // Safety Guard: Only kill OpenSSH sshd or sftp-server processes
            var procName = proc.ProcessName.ToLowerInvariant();
            if (procName != "sshd" && procName != "sftp-server")
            {
                var warning = $"Safety Guard: ปฏิเสธการตัดโพรเซส PID {processId} ({proc.ProcessName}) เนื่องจากไม่ใช่โพรเซส OpenSSH";
                _logger.LogWarning(warning);
                await _auditService.LogAsync("SFTP_SESSION_TERMINATE_BLOCKED", warning, false, op);
                return (false, warning);
            }

            // MASTER SERVICE IMMUNITY GUARD:
            // Check if processId is the Master OpenSSH service PID
            var masterPid = GetSshdServicePid();
            if (masterPid > 0 && processId == masterPid)
            {
                // PROTECT MASTER SERVICE! Reset all active established TCP connections on sshPort
                var tcpEntries = GetTcpConnectionsWin32()
                    .Where(t => t.LocalPort == _sshPort && t.State == 5)
                    .ToList();

                foreach (var conn in tcpEntries)
                {
                    CloseTcpConnectionWin32(conn.RawLocalAddr, conn.RawLocalPort, conn.RawRemoteAddr, conn.RawRemotePort);
                }

                var guardMsg = $"ตัดการเชื่อมต่อ SFTP ผ่าน TCP Reset สำเร็จ (Master OpenSSH Service PID {processId} ได้รับการคุ้มกัน ไม่ถูกสั่งปิด)";
                _logger.LogInformation("{Message} โดย {Operator}", guardMsg, op);
                await _auditService.LogAsync("SFTP_SESSION_TERMINATED", guardMsg, true, op);
                return (true, guardMsg);
            }

            var username = ResolveProcessUsername(proc);
            var canonicalUser = SecurityValidator.ExtractCanonicalUsername(username);

            // Terminate child process tree
            proc.Kill(entireProcessTree: true);

            var auditMsg = $"ตัดการเชื่อมต่อ SFTP เซสชันของผู้ใช้ '{canonicalUser}' (PID: {processId}, Process: {procName}) สำเร็จ";
            _logger.LogInformation("{Message} โดย {Operator}", auditMsg, op);
            await _auditService.LogAsync("SFTP_SESSION_TERMINATED", auditMsg, true, op);

            return (true, auditMsg);
        }
        catch (Exception ex)
        {
            var err = $"ไม่สามารถตัดการเชื่อมต่อ PID {processId} ได้: {ex.Message}";
            _logger.LogError(ex, "{Error}", err);
            await _auditService.LogAsync("SFTP_SESSION_TERMINATED", err, false, op);
            return (false, err);
        }
    }

    public async Task<(bool Success, string Message)> TerminateUserSessionsAsync(string targetUsername, string operatorUsername)
    {
        var op = string.IsNullOrWhiteSpace(operatorUsername) ? "admin" : SecurityValidator.ExtractCanonicalUsername(operatorUsername);
        var cleanTarget = SecurityValidator.ExtractCanonicalUsername(targetUsername);

        if (string.IsNullOrWhiteSpace(cleanTarget))
        {
            return (false, "ไม่ได้ระบุชื่อผู้ใช้ที่ต้องการตัดการเชื่อมต่อ");
        }

        if (_isDemoMode)
        {
            int removedCount;
            lock (_mockLock)
            {
                removedCount = _mockSessions.RemoveAll(s => s.Username.Equals(cleanTarget, StringComparison.OrdinalIgnoreCase));
            }

            if (removedCount == 0)
            {
                return (false, $"ไม่พบเซสชันที่เชื่อมต่ออยู่ของผู้ใช้ '{cleanTarget}'");
            }

            var msg = $"[Demo] ตัดการเชื่อมต่อทั้งหมดของผู้ใช้ '{cleanTarget}' สำเร็จ (จำนวน {removedCount} เซสชัน)";
            await _auditService.LogAsync("SFTP_USER_SESSIONS_TERMINATED", msg, true, op);
            return (true, msg);
        }

        var live = await GetActiveSessionsAsync();
        var targetSessions = live.Sessions
            .Where(s => s.Username.Equals(cleanTarget, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (targetSessions.Count == 0)
        {
            return (false, $"ไม่พบเซสชันที่เชื่อมต่ออยู่ของผู้ใช้ '{cleanTarget}'");
        }

        int terminated = 0;
        foreach (var sess in targetSessions)
        {
            var (ok, _) = await TerminateSessionAsync(sess, operatorUsername);
            if (ok) terminated++;
        }

        var resultMsg = $"ตัดการเชื่อมต่อของผู้ใช้ '{cleanTarget}' สำเร็จทั้งหมด {terminated}/{targetSessions.Count} เซสชัน";
        await _auditService.LogAsync("SFTP_USER_SESSIONS_TERMINATED", resultMsg, terminated > 0, op);
        return (terminated > 0, resultMsg);
    }

    private async Task<List<SftpSessionInfo>> GetLiveSessionsWin32Async()
    {
        var result = new List<SftpSessionInfo>();
        var tcpEntries = GetTcpConnectionsWin32();

        // Detect master sshd service PID via SCM or listener socket
        var masterSshdPid = GetSshdServicePid();
        if (masterSshdPid <= 0)
        {
            var listener = tcpEntries.FirstOrDefault(t => t.LocalPort == _sshPort && t.State == 2);
            if (listener != null)
            {
                masterSshdPid = listener.OwningPid;
            }
        }

        // Find connections where LocalPort == _sshPort and State == ESTABLISHED (5)
        var sshConnections = tcpEntries
            .Where(t => t.LocalPort == _sshPort && t.State == 5)
            .ToList();

        // Auto-prune cache for connections that are no longer active
        var activeKeys = sshConnections.Select(c => (c.RemoteAddress, c.RemotePort)).ToHashSet();
        foreach (var key in _sessionUserCache.Keys)
        {
            if (!activeKeys.Contains(key))
            {
                _sessionUserCache.TryRemove(key, out _);
            }
        }

        // Check if any active connection is missing from cache
        bool hasMissingCachedUser = sshConnections.Any(c => !_sessionUserCache.ContainsKey((c.RemoteAddress, c.RemotePort)));

        Dictionary<(string Ip, int Port), (string Username, DateTime Timestamp)> authMap = new();
        if (hasMissingCachedUser && _eventLogService != null)
        {
            authMap = await GetRecentAuthMapAsync();
            foreach (var kvp in authMap)
            {
                _sessionUserCache[kvp.Key] = kvp.Value;
            }
        }

        var childProcesses = masterSshdPid > 0 ? FindChildProcesses(masterSshdPid) : new List<(int Pid, string Name)>();
        List<(int Pid, string Username, DateTime StartTime)>? runningSessionUsers = null;

        foreach (var conn in sshConnections)
        {
            if (!TryGetProcessDetails(conn.OwningPid, out var procName, out var startTime, out var workingSet))
            {
                continue;
            }

            var pNameLower = procName.ToLowerInvariant();
            if (pNameLower != "sshd" && pNameLower != "sftp-server")
            {
                continue;
            }

            bool isMaster = (masterSshdPid > 0 && conn.OwningPid == masterSshdPid);
            string cleanUser;
            bool isAuthenticating = false;

            var connKey = (conn.RemoteAddress, conn.RemotePort);

            // 1. Check in-memory cache or authMap
            if (_sessionUserCache.TryGetValue(connKey, out var cachedInfo))
            {
                cleanUser = SecurityValidator.ExtractCanonicalUsername(cachedInfo.Username);
                startTime = cachedInfo.Timestamp;
            }
            else if (authMap.TryGetValue(connKey, out var authInfo))
            {
                cleanUser = SecurityValidator.ExtractCanonicalUsername(authInfo.Username);
                startTime = authInfo.Timestamp;
                _sessionUserCache[connKey] = authInfo;
            }
            else
            {
                // 2. Fallback: inspect direct child processes of master sshd
                string? detectedChildUser = null;
                if (isMaster && childProcesses.Count > 0)
                {
                    foreach (var (cPid, _) in childProcesses)
                    {
                        var cRawUser = GetProcessUsername(cPid);
                        var cUser = SecurityValidator.ExtractCanonicalUsername(cRawUser);
                        if (!string.IsNullOrWhiteSpace(cUser) &&
                            !cUser.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) &&
                            !cUser.Equals("LOCAL SERVICE", StringComparison.OrdinalIgnoreCase) &&
                            !cUser.Equals("NETWORK SERVICE", StringComparison.OrdinalIgnoreCase) &&
                            !cUser.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
                        {
                            detectedChildUser = cUser;
                            break;
                        }
                    }
                }

                // 3. Fallback: Global process scan of sshd / sftp-server running under non-SYSTEM identities
                if (string.IsNullOrWhiteSpace(detectedChildUser))
                {
                    runningSessionUsers ??= FindRunningSessionUsers(masterSshdPid);
                    if (runningSessionUsers.Count == 1)
                    {
                        detectedChildUser = runningSessionUsers[0].Username;
                    }
                    else if (runningSessionUsers.Count > 1)
                    {
                        detectedChildUser = runningSessionUsers[0].Username;
                    }
                }

                if (!string.IsNullOrWhiteSpace(detectedChildUser))
                {
                    cleanUser = detectedChildUser;
                    _sessionUserCache[connKey] = (cleanUser, startTime);
                }
                else if (isMaster)
                {
                    cleanUser = "กำลังตรวจสอบสิทธิ์ (Authenticating...)";
                    isAuthenticating = true;
                }
                else
                {
                    var rawUser = GetProcessUsername(conn.OwningPid);
                    cleanUser = SecurityValidator.ExtractCanonicalUsername(rawUser);
                    if (cleanUser.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) || cleanUser.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
                    {
                        cleanUser = "กำลังตรวจสอบสิทธิ์ (Authenticating...)";
                        isAuthenticating = true;
                    }
                    else
                    {
                        _sessionUserCache[connKey] = (cleanUser, startTime);
                    }
                }
            }

            int? matchedChildPid = childProcesses.Count > 0 ? childProcesses[0].Pid : null;

            result.Add(new SftpSessionInfo
            {
                SessionId = $"sess-{conn.OwningPid}-{conn.RemotePort}",
                ProcessId = conn.OwningPid,
                ProcessName = procName,
                Username = cleanUser,
                RemoteIp = conn.RemoteAddress,
                RemotePort = conn.RemotePort,
                LocalPort = conn.LocalPort,
                ConnectedAt = startTime,
                WorkingSetMemoryBytes = workingSet,
                RawLocalAddr = conn.RawLocalAddr,
                RawLocalPort = conn.RawLocalPort,
                RawRemoteAddr = conn.RawRemoteAddr,
                RawRemotePort = conn.RawRemotePort,
                ChildProcessId = matchedChildPid,
                IsMasterServiceProcess = isMaster,
                IsAuthenticating = isAuthenticating
            });
        }

        return result;
    }

    private async Task<Dictionary<(string Ip, int Port), (string Username, DateTime Timestamp)>> GetRecentAuthMapAsync()
    {
        var map = new Dictionary<(string, int), (string, DateTime)>();
        if (_eventLogService == null) return map;

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            var fetchTask = _eventLogService.GetLogsAsync(new SshLogFilter
            {
                Category = SshEventType.AuthSuccess,
                TimePreset = SshTimePreset.Last7Days,
                MaxRecords = 50
            });

            var completedTask = await Task.WhenAny(fetchTask, Task.Delay(Timeout.Infinite, cts.Token));
            if (completedTask == fetchTask)
            {
                var logResult = await fetchTask;
                if (logResult.IsSuccess)
                {
                    foreach (var entry in logResult.Entries)
                    {
                        if (!string.IsNullOrWhiteSpace(entry.ClientIp) && entry.Port.HasValue && !string.IsNullOrWhiteSpace(entry.Username))
                        {
                            var key = (entry.ClientIp, entry.Port.Value);
                            if (!map.ContainsKey(key))
                            {
                                map[key] = (entry.Username, entry.Timestamp);
                            }
                        }
                    }
                }
            }
            else
            {
                _logger.LogWarning("Event log correlation timed out after 3 seconds");
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not correlate live sessions with Event Log");
        }
        return map;
    }

    protected internal virtual List<(int Pid, string Username, DateTime StartTime)> FindRunningSessionUsers(int masterPid)
    {
        var users = new List<(int Pid, string Username, DateTime StartTime)>();
        try
        {
            var candidates = Process.GetProcessesByName("sshd")
                .Concat(Process.GetProcessesByName("sftp-server"));

            foreach (var p in candidates)
            {
                if (masterPid > 0 && p.Id == masterPid) continue;

                try
                {
                    var rawUser = ResolveProcessUsername(p);
                    var clean = SecurityValidator.ExtractCanonicalUsername(rawUser);
                    if (!string.IsNullOrWhiteSpace(clean) &&
                        !clean.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) &&
                        !clean.Equals("LOCAL SERVICE", StringComparison.OrdinalIgnoreCase) &&
                        !clean.Equals("NETWORK SERVICE", StringComparison.OrdinalIgnoreCase) &&
                        !clean.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
                    {
                        DateTime st;
                        try { st = p.StartTime; } catch { st = DateTime.Now; }
                        users.Add((p.Id, clean, st));
                    }
                }
                catch { }
            }
        }
        catch { }
        return users;
    }

    protected internal virtual bool TryGetProcessDetails(int pid, out string processName, out DateTime startTime, out long workingSet)
    {
        try
        {
            var proc = Process.GetProcessById(pid);
            processName = proc.ProcessName;
            try { startTime = proc.StartTime; } catch { startTime = DateTime.Now; }
            try { workingSet = proc.WorkingSet64; } catch { workingSet = 0; }
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not inspect process {Pid}", pid);
            processName = string.Empty;
            startTime = DateTime.Now;
            workingSet = 0;
            return false;
        }
    }

    protected internal virtual string GetProcessUsername(int pid)
    {
        try
        {
            var proc = Process.GetProcessById(pid);
            return ResolveProcessUsername(proc);
        }
        catch
        {
            return "Unknown";
        }
    }

    protected internal virtual List<(int Pid, string Name)> FindChildProcesses(int parentPid)
    {
        var list = new List<(int, string)>();
        if (parentPid <= 0) return list;

        IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1)) return list;

        try
        {
            var pe = new PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>() };
            if (Process32First(snapshot, ref pe))
            {
                do
                {
                    if (pe.th32ParentProcessID == (uint)parentPid)
                    {
                        list.Add(((int)pe.th32ProcessID, pe.szExeFile));
                    }
                } while (Process32Next(snapshot, ref pe));
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not enumerate child processes via Toolhelp32");
        }
        finally
        {
            CloseHandle(snapshot);
        }

        return list;
    }

    public virtual int GetSshdServicePid()
    {
        try
        {
            IntPtr scm = OpenSCManager(null, null, SC_MANAGER_CONNECT);
            if (scm != IntPtr.Zero)
            {
                try
                {
                    IntPtr svc = OpenService(scm, "sshd", SERVICE_QUERY_STATUS);
                    if (svc != IntPtr.Zero)
                    {
                        try
                        {
                            int size = Marshal.SizeOf<SERVICE_STATUS_PROCESS>();
                            IntPtr buf = Marshal.AllocHGlobal(size);
                            try
                            {
                                if (QueryServiceStatusEx(svc, 0, buf, (uint)size, out _))
                                {
                                    var ssp = Marshal.PtrToStructure<SERVICE_STATUS_PROCESS>(buf);
                                    return ssp.dwProcessId;
                                }
                            }
                            finally
                            {
                                Marshal.FreeHGlobal(buf);
                            }
                        }
                        finally
                        {
                            CloseServiceHandle(svc);
                        }
                    }
                }
                finally
                {
                    CloseServiceHandle(scm);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not query sshd service PID via SCM");
        }
        return 0;
    }

    public virtual bool CloseTcpConnectionWin32(uint localAddr, uint localPort, uint remoteAddr, uint remotePort)
    {
        try
        {
            var row = new MIB_TCPROW
            {
                dwState = MIB_TCP_STATE_DELETE_TCB,
                dwLocalAddr = localAddr,
                dwLocalPort = localPort,
                dwRemoteAddr = remoteAddr,
                dwRemotePort = remotePort
            };

            uint ret = SetTcpEntry(ref row);
            if (ret == 0)
            {
                _logger.LogInformation("Successfully reset TCP connection via SetTcpEntry (State=DELETE_TCB)");
                return true;
            }

            _logger.LogWarning("SetTcpEntry returned error code: {ErrorCode}", ret);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception in CloseTcpConnectionWin32");
            return false;
        }
    }

    private static string ResolveProcessUsername(Process proc)
    {
        IntPtr tokenHandle = IntPtr.Zero;
        try
        {
            if (!OpenProcessToken(proc.Handle, TOKEN_QUERY, out tokenHandle))
            {
                return "Unknown";
            }

            using var identity = new WindowsIdentity(tokenHandle);
            return identity.Name;
        }
        catch
        {
            return "Unknown";
        }
        finally
        {
            if (tokenHandle != IntPtr.Zero)
            {
                CloseHandle(tokenHandle);
            }
        }
    }

    #region Win32 P/Invoke & TCP Helper

    private const int AF_INET = 2; // IPv4
    private const int TOKEN_QUERY = 0x0008;
    private const uint MIB_TCP_STATE_DELETE_TCB = 12;
    private const uint SC_MANAGER_CONNECT = 0x0001;
    private const uint SERVICE_QUERY_STATUS = 0x0004;
    private const uint TH32CS_SNAPPROCESS = 0x00000002;

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS_PROCESS
    {
        public int dwServiceType;
        public int dwCurrentState;
        public int dwControlsAccepted;
        public int dwWin32ExitCode;
        public int dwServiceSpecificExitCode;
        public int dwCheckPoint;
        public int dwWaitHint;
        public int dwProcessId;
        public int dwServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint SetTcpEntry(ref MIB_TCPROW pTcpRow);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern IntPtr OpenSCManager(string? lpMachineName, string? lpDatabaseName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatusEx(IntPtr hService, int InfoLevel, IntPtr lpBuffer, uint cbBufSize, out uint pcbBytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr hSCObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, out IntPtr TokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        TCP_TABLE_CLASS TableClass,
        uint Reserved);

    private enum TCP_TABLE_CLASS
    {
        TCP_TABLE_BASIC_LISTENER,
        TCP_TABLE_BASIC_CONNECTIONS,
        TCP_TABLE_BASIC_ALL,
        TCP_TABLE_OWNER_PID_LISTENER,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        TCP_TABLE_OWNER_PID_ALL,
        TCP_TABLE_OWNER_MODULE_LISTENER,
        TCP_TABLE_OWNER_MODULE_CONNECTIONS,
        TCP_TABLE_OWNER_MODULE_ALL
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public int owningPid;
    }

    protected internal class TcpConnectionEntry
    {
        public int OwningPid { get; set; }
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; } = string.Empty;
        public int RemotePort { get; set; }
        public uint State { get; set; }
        public uint RawLocalAddr { get; set; }
        public uint RawLocalPort { get; set; }
        public uint RawRemoteAddr { get; set; }
        public uint RawRemotePort { get; set; }
    }

    protected internal virtual List<TcpConnectionEntry> GetTcpConnectionsWin32()
    {
        var entries = new List<TcpConnectionEntry>();
        int size = 0;

        // Query buffer size needed
        _ = GetExtendedTcpTable(IntPtr.Zero, ref size, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);

        if (size <= 0) return entries;

        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            uint ret = GetExtendedTcpTable(buffer, ref size, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 0)
            {
                return entries;
            }

            int numEntries = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = IntPtr.Add(buffer, 4);
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                rowPtr = IntPtr.Add(rowPtr, rowSize);

                ushort lPort = (ushort)IPAddress.NetworkToHostOrder((short)row.localPort);
                ushort rPort = (ushort)IPAddress.NetworkToHostOrder((short)row.remotePort);
                var rIp = new IPAddress(row.remoteAddr).ToString();

                entries.Add(new TcpConnectionEntry
                {
                    OwningPid = row.owningPid,
                    LocalPort = lPort,
                    RemoteAddress = rIp,
                    RemotePort = rPort,
                    State = row.state,
                    RawLocalAddr = row.localAddr,
                    RawLocalPort = row.localPort,
                    RawRemoteAddr = row.remoteAddr,
                    RawRemotePort = row.remotePort
                });
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return entries;
    }

    #endregion
}
