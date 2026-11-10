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
    private readonly int _sshPort;

    private readonly object _mockLock = new();
    private readonly List<SftpSessionInfo> _mockSessions = new();
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
        IConfiguration? configuration = null)
    {
        _logger = logger;
        _auditService = auditService;
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

    public Task<SftpSessionOverview> GetActiveSessionsAsync(bool forceMock = false)
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
                return Task.FromResult(overview);
            }
        }

        try
        {
            var sessions = GetLiveSessionsWin32();

            // Group by canonical username to mark excessive connections (> 5 connections)
            var userGroups = sessions
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

            return Task.FromResult(overview);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to retrieve live sessions via Win32 P/Invoke");
            return Task.FromResult(new SftpSessionOverview
            {
                TotalActiveSessions = 0,
                UniqueUsersCount = 0,
                Sessions = new List<SftpSessionInfo>(),
                IsLiveWin32Available = false,
                StatusNote = $"ไม่สามารถดึงข้อมูลเซสชันสดได้: {ex.Message}"
            });
        }
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

            var username = ResolveProcessUsername(proc);
            var canonicalUser = SecurityValidator.ExtractCanonicalUsername(username);

            // Terminate entire process tree
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
            var (ok, _) = await TerminateSessionAsync(sess.ProcessId, operatorUsername);
            if (ok) terminated++;
        }

        var resultMsg = $"ตัดการเชื่อมต่อของผู้ใช้ '{cleanTarget}' สำเร็จทั้งหมด {terminated}/{targetSessions.Count} เซสชัน";
        await _auditService.LogAsync("SFTP_USER_SESSIONS_TERMINATED", resultMsg, terminated > 0, op);
        return (terminated > 0, resultMsg);
    }

    private List<SftpSessionInfo> GetLiveSessionsWin32()
    {
        var result = new List<SftpSessionInfo>();
        var tcpEntries = GetTcpConnectionsWin32();

        // Find connections where LocalPort == _sshPort and State == ESTABLISHED (5)
        var sshConnections = tcpEntries
            .Where(t => t.LocalPort == _sshPort && t.State == 5)
            .ToList();

        foreach (var conn in sshConnections)
        {
            try
            {
                var proc = Process.GetProcessById(conn.OwningPid);
                var pName = proc.ProcessName.ToLowerInvariant();

                // OpenSSH connection processes
                if (pName != "sshd" && pName != "sftp-server")
                {
                    continue;
                }

                var rawUser = ResolveProcessUsername(proc);
                var cleanUser = SecurityValidator.ExtractCanonicalUsername(rawUser);

                DateTime startTime;
                try { startTime = proc.StartTime; } catch { startTime = DateTime.Now; }

                long workingSet;
                try { workingSet = proc.WorkingSet64; } catch { workingSet = 0; }

                result.Add(new SftpSessionInfo
                {
                    SessionId = $"sess-{conn.OwningPid}-{conn.RemotePort}",
                    ProcessId = conn.OwningPid,
                    ProcessName = proc.ProcessName,
                    Username = cleanUser,
                    RemoteIp = conn.RemoteAddress,
                    RemotePort = conn.RemotePort,
                    LocalPort = conn.LocalPort,
                    ConnectedAt = startTime,
                    WorkingSetMemoryBytes = workingSet
                });
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Could not inspect process {Pid}", conn.OwningPid);
            }
        }

        return result;
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

    private class TcpConnectionEntry
    {
        public int OwningPid { get; set; }
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; } = string.Empty;
        public int RemotePort { get; set; }
        public uint State { get; set; }
    }

    private List<TcpConnectionEntry> GetTcpConnectionsWin32()
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
                    State = row.state
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
