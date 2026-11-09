using OpensshUI.Models;

namespace OpensshUI.Services.Auth;

public class UserSessionState
{
    private bool _isAuthenticated;
    public bool IsAuthenticated => _isAuthenticated && !IsSessionExpired;
    public string CurrentUsername { get; private set; } = string.Empty;
    public string DisplayName { get; private set; } = string.Empty;
    public bool IsAdmin { get; private set; }
    public WebAdminRole Role { get; private set; } = WebAdminRole.Auditor;
    public DateTime? LoginTime { get; private set; }
    public TimeSpan SessionTimeout { get; private set; } = TimeSpan.FromHours(8);

    public bool IsSessionExpired => LoginTime.HasValue && (DateTime.UtcNow - LoginTime.Value) > SessionTimeout;

    public bool CanManageSystem => IsAuthenticated && IsAdmin && Role == WebAdminRole.SuperAdmin;
    public bool CanManageSftp => IsAuthenticated && IsAdmin && (Role == WebAdminRole.SuperAdmin || Role == WebAdminRole.Operator);
    public bool IsReadOnly => IsAuthenticated && IsAdmin && Role == WebAdminRole.Auditor;

    public event Action? OnChange;

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
        _isAuthenticated = true;
        CurrentUsername = username;
        DisplayName = displayName;
        IsAdmin = isAdmin;
        Role = role;
        LoginTime = DateTime.UtcNow;
        NotifyStateChanged();
    }

    public void Logout()
    {
        _isAuthenticated = false;
        CurrentUsername = string.Empty;
        DisplayName = string.Empty;
        IsAdmin = false;
        Role = WebAdminRole.Auditor;
        LoginTime = null;
        NotifyStateChanged();
    }

    private void NotifyStateChanged() => OnChange?.Invoke();
}
