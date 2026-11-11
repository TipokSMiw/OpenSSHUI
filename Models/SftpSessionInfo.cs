namespace OpensshUI.Models;

/// <summary>
/// Model representing an active OpenSSH/SFTP client session on the Windows host.
/// </summary>
public class SftpSessionInfo
{
    public string SessionId { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "sshd";
    public string Username { get; set; } = string.Empty;
    public string RemoteIp { get; set; } = string.Empty;
    public int RemotePort { get; set; }
    public int LocalPort { get; set; } = 22;
    public DateTime ConnectedAt { get; set; } = DateTime.Now;
    public TimeSpan Duration => DateTime.Now >= ConnectedAt ? DateTime.Now - ConnectedAt : TimeSpan.Zero;
    public long WorkingSetMemoryBytes { get; set; }
    public bool IsExcessiveConnection { get; set; }

    /// <summary>
    /// Raw local IPv4 address in network byte order for Win32 SetTcpEntry.
    /// </summary>
    public uint RawLocalAddr { get; set; }

    /// <summary>
    /// Raw local port in network byte order for Win32 SetTcpEntry.
    /// </summary>
    public uint RawLocalPort { get; set; }

    /// <summary>
    /// Raw remote IPv4 address in network byte order for Win32 SetTcpEntry.
    /// </summary>
    public uint RawRemoteAddr { get; set; }

    /// <summary>
    /// Raw remote port in network byte order for Win32 SetTcpEntry.
    /// </summary>
    public uint RawRemotePort { get; set; }

    /// <summary>
    /// Optional child process ID (e.g., sftp-server or child sshd session process) if identified.
    /// </summary>
    public int? ChildProcessId { get; set; }

    /// <summary>
    /// Indicates whether the owning process is the master OpenSSH daemon service process.
    /// </summary>
    public bool IsMasterServiceProcess { get; set; }

    /// <summary>
    /// Indicates whether the session is currently in pre-authentication/handshake state.
    /// </summary>
    public bool IsAuthenticating { get; set; }
}

/// <summary>
/// Overview summary of active SFTP sessions.
/// </summary>
public class SftpSessionOverview
{
    public int TotalActiveSessions { get; set; }
    public int UniqueUsersCount { get; set; }
    public List<SftpSessionInfo> Sessions { get; set; } = new();
    public bool IsLiveWin32Available { get; set; } = true;
    public string? StatusNote { get; set; }
}
