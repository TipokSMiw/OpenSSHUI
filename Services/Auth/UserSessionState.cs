using System.Collections.Concurrent;
using OpensshUI.Models;
using OpensshUI.Services.Security;

namespace OpensshUI.Services.Auth;

public class UserSessionState
{
    private const int MaxTrackedStateEntries = 1000;
    private static readonly TimeSpan OverrideRetention = TimeSpan.FromHours(12);
    private static readonly ConcurrentDictionary<string, (long Sequence, DateTime UpdatedAtUtc, bool IsActive, WebAdminRole Role)> AccountStateOverrides = new(StringComparer.OrdinalIgnoreCase);
    private static long _globalSequence;

    private bool _isAuthenticated;
    private long _loginSequence;
    private WebAdminRole _role = WebAdminRole.Auditor;

    public bool IsAuthenticated => _isAuthenticated && !IsSessionExpired && !IsRevokedByAdminChange;
    public string CurrentUsername { get; private set; } = string.Empty;
    public string DisplayName { get; private set; } = string.Empty;
    public bool IsAdmin { get; private set; }
    public WebAdminRole Role => ResolveEffectiveRole();
    public DateTime? LoginTime { get; private set; }
    public TimeSpan SessionTimeout { get; private set; } = TimeSpan.FromHours(8);

    public bool IsSessionExpired => LoginTime.HasValue && (DateTime.UtcNow - LoginTime.Value) > SessionTimeout;

    private bool IsRevokedByAdminChange
    {
        get
        {
            if (!_isAuthenticated || string.IsNullOrWhiteSpace(CurrentUsername))
                return false;

            var key = NormalizeKey(CurrentUsername);
            if (AccountStateOverrides.TryGetValue(key, out var state) && state.Sequence > _loginSequence)
            {
                return !state.IsActive;
            }
            return false;
        }
    }

    private WebAdminRole ResolveEffectiveRole()
    {
        if (!_isAuthenticated || IsSessionExpired || IsRevokedByAdminChange)
            return WebAdminRole.Auditor;

        if (!string.IsNullOrWhiteSpace(CurrentUsername))
        {
            var key = NormalizeKey(CurrentUsername);
            if (AccountStateOverrides.TryGetValue(key, out var state) && state.Sequence > _loginSequence)
            {
                return state.IsActive ? state.Role : WebAdminRole.Auditor;
            }
        }

        return _role;
    }

    public bool CanManageSystem => IsAuthenticated && IsAdmin && Role == WebAdminRole.SuperAdmin;
    public bool CanManageSftp => IsAuthenticated && IsAdmin && (Role == WebAdminRole.SuperAdmin || Role == WebAdminRole.Operator);
    public bool IsReadOnly => IsAuthenticated && IsAdmin && Role == WebAdminRole.Auditor;

    public event Action? OnChange;

    public static void NotifyUserStatusChanged(string username, bool isActive, WebAdminRole role)
    {
        if (string.IsNullOrWhiteSpace(username)) return;

        var nowUtc = DateTime.UtcNow;
        if (AccountStateOverrides.Count >= MaxTrackedStateEntries)
        {
            PruneStaleOverrides(nowUtc);
        }

        var key = NormalizeKey(username);
        var seq = Interlocked.Increment(ref _globalSequence);
        AccountStateOverrides[key] = (seq, nowUtc, isActive, role);
    }

    public static int GetTrackedOverrideCount() => AccountStateOverrides.Count;

    public static void ClearAllOverrides() => AccountStateOverrides.Clear();

    private static string NormalizeKey(string username)
    {
        var canonical = SecurityValidator.ExtractCanonicalUsername(username);
        return string.IsNullOrWhiteSpace(canonical) ? username.Trim() : canonical;
    }

    private static void PruneStaleOverrides(DateTime nowUtc)
    {
        var cutoff = nowUtc - OverrideRetention;
        foreach (var kvp in AccountStateOverrides)
        {
            if (kvp.Value.UpdatedAtUtc <= cutoff)
            {
                AccountStateOverrides.TryRemove(kvp.Key, out _);
            }
        }

        if (AccountStateOverrides.Count >= MaxTrackedStateEntries)
        {
            var oldestKeys = AccountStateOverrides
                .OrderBy(kvp => kvp.Value.Sequence)
                .Take(MaxTrackedStateEntries / 4)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var k in oldestKeys)
            {
                AccountStateOverrides.TryRemove(k, out _);
            }
        }
    }

    public void SetSessionTimeout(TimeSpan timeout)
    {
        if (timeout > TimeSpan.Zero)
        {
            SessionTimeout = timeout;
            NotifyStateChanged();
        }
    }

    public void SetUser(string username, string displayName, bool isAdmin, WebAdminRole role = WebAdminRole.Auditor)
    {
        _loginSequence = Interlocked.Increment(ref _globalSequence);
        _isAuthenticated = true;
        CurrentUsername = username;
        DisplayName = displayName;
        IsAdmin = isAdmin;
        _role = role;
        LoginTime = DateTime.UtcNow;
        NotifyStateChanged();
    }

    public void Logout()
    {
        _isAuthenticated = false;
        CurrentUsername = string.Empty;
        DisplayName = string.Empty;
        IsAdmin = false;
        _role = WebAdminRole.Auditor;
        LoginTime = null;
        NotifyStateChanged();
    }

    private void NotifyStateChanged() => OnChange?.Invoke();
}
