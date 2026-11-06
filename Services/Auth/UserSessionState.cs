using OpensshUI.Models;

namespace OpensshUI.Services.Auth;

public class UserSessionState
{
    public bool IsAuthenticated { get; private set; }
    public string CurrentUsername { get; private set; } = string.Empty;
    public string DisplayName { get; private set; } = string.Empty;
    public bool IsAdmin { get; private set; }
    public WebAdminRole Role { get; private set; } = WebAdminRole.SuperAdmin;
    public DateTime? LoginTime { get; private set; }

    public bool CanManageSystem => IsAuthenticated && IsAdmin && Role == WebAdminRole.SuperAdmin;
    public bool CanManageSftp => IsAuthenticated && IsAdmin && (Role == WebAdminRole.SuperAdmin || Role == WebAdminRole.Operator);
    public bool IsReadOnly => IsAuthenticated && IsAdmin && Role == WebAdminRole.Auditor;

    public event Action? OnChange;

    public void SetUser(string username, string displayName, bool isAdmin, WebAdminRole role = WebAdminRole.SuperAdmin)
    {
        IsAuthenticated = true;
        CurrentUsername = username;
        DisplayName = displayName;
        IsAdmin = isAdmin;
        Role = role;
        LoginTime = DateTime.UtcNow;
        NotifyStateChanged();
    }

    public void Logout()
    {
        IsAuthenticated = false;
        CurrentUsername = string.Empty;
        DisplayName = string.Empty;
        IsAdmin = false;
        Role = WebAdminRole.SuperAdmin;
        LoginTime = null;
        NotifyStateChanged();
    }

    private void NotifyStateChanged() => OnChange?.Invoke();
}
