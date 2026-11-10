namespace OpensshUI.Models;

/// <summary>
/// Model representing concurrency, keep-alive, and connection limit directives in sshd_config.
/// </summary>
public class SshdConcurrencySettings
{
    /// <summary>
    /// Max unauthenticated concurrent handshakes (e.g. "10:30:100" or "100:30:300").
    /// </summary>
    public string MaxStartups { get; set; } = "10:30:100";

    /// <summary>
    /// Max open sessions per network connection (default 10).
    /// </summary>
    public int MaxSessions { get; set; } = 10;

    /// <summary>
    /// Keep-alive interval in seconds (0 = disabled).
    /// </summary>
    public int ClientAliveInterval { get; set; }

    /// <summary>
    /// Max unanswered client alive messages before disconnecting (default 3).
    /// </summary>
    public int ClientAliveCountMax { get; set; } = 3;

    /// <summary>
    /// Time allowed for successful login in seconds (default 120).
    /// </summary>
    public int LoginGraceTime { get; set; } = 120;

    /// <summary>
    /// Named profile identifier (e.g. "Default", "Standard", "HighTraffic", "Custom").
    /// </summary>
    public string AppliedProfile { get; set; } = "Default";
}
