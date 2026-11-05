namespace OpensshUI.Services.Auth;

public class UserSessionState
{
    public bool IsAuthenticated { get; private set; }
    public string CurrentUsername { get; private set; } = string.Empty;
    public string DisplayName { get; private set; } = string.Empty;
    public bool IsAdmin { get; private set; }
    public DateTime? LoginTime { get; private set; }

    public event Action? OnChange;

    public void SetUser(string username, string displayName, bool isAdmin)
    {
        IsAuthenticated = true;
        CurrentUsername = username;
        DisplayName = displayName;
        IsAdmin = isAdmin;
        LoginTime = DateTime.UtcNow;
        NotifyStateChanged();
    }

    public void Logout()
    {
        IsAuthenticated = false;
        CurrentUsername = string.Empty;
        DisplayName = string.Empty;
        IsAdmin = false;
        LoginTime = null;
        NotifyStateChanged();
    }

    private void NotifyStateChanged() => OnChange?.Invoke();
}
