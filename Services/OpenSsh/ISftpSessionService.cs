using OpensshUI.Models;

namespace OpensshUI.Services.OpenSsh;

/// <summary>
/// Service contract for monitoring and terminating active SFTP client sessions.
/// </summary>
public interface ISftpSessionService
{
    /// <summary>
    /// Gets active SFTP sessions and overview metrics.
    /// </summary>
    Task<SftpSessionOverview> GetActiveSessionsAsync(bool forceMock = false);

    /// <summary>
    /// Terminates an active SFTP session by process ID (with Master Service Immunity Guard).
    /// </summary>
    Task<(bool Success, string Message)> TerminateSessionAsync(int processId, string operatorUsername);

    /// <summary>
    /// Terminates an active SFTP session using session details via Win32 SetTcpEntry (TCP RST).
    /// </summary>
    Task<(bool Success, string Message)> TerminateSessionAsync(SftpSessionInfo session, string operatorUsername);

    /// <summary>
    /// Terminates an active SFTP session by session ID.
    /// </summary>
    Task<(bool Success, string Message)> TerminateSessionAsync(string sessionId, string operatorUsername);

    /// <summary>
    /// Terminates all active sessions belonging to a specific SFTP user.
    /// </summary>
    Task<(bool Success, string Message)> TerminateUserSessionsAsync(string targetUsername, string operatorUsername);

    /// <summary>
    /// Gets or sets whether Demo Mock Mode is active.
    /// </summary>
    bool IsDemoMode { get; set; }

    /// <summary>
    /// Toggles Demo Mock Mode.
    /// </summary>
    void ToggleDemoMode();
}
