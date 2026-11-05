using OpensshUI.Models;

namespace OpensshUI.Services.Auth;

public class AuthResult
{
    public bool IsSuccess { get; set; }
    public string? ErrorMessage { get; set; }
    public string Username { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public bool IsAdmin { get; set; }
}

public class AdUserInfo
{
    public string SamAccountName { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
}

public class AdSearchResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public List<AdUserInfo> Users { get; set; } = new();
}

public class LdapConnectionTestResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public bool HostReachable { get; set; }
    public bool BindSuccessful { get; set; }
    public bool? BaseDnVerified { get; set; }
    public bool? AdminGroupVerified { get; set; }
    public List<string> Details { get; set; } = new();
}

public interface ILdapAuthService
{
    Task<LdapConfig> GetConfigAsync();
    Task SaveConfigAsync(LdapConfig config, string? newBindPassword = null, string? newFallbackAdminPassword = null);
    Task<AuthResult> AuthenticateAsync(string username, string password);
    Task<LdapConnectionTestResult> TestConnectionAsync(LdapConfig config, string? plainBindPassword = null);
    Task<AdSearchResult> SearchAdUsersAsync(string query);
    Task<bool> IsUsingDefaultFallbackPasswordAsync();
}
