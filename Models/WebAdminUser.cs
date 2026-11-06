namespace OpensshUI.Models;

public enum WebAdminType
{
    Local = 0,
    ActiveDirectory = 1
}

public enum WebAdminRole
{
    SuperAdmin = 0,
    Operator = 1,
    Auditor = 2
}

public class WebAdminUser
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string? Email { get; set; }
    public WebAdminType AccountType { get; set; } = WebAdminType.Local;
    public string? PasswordHash { get; set; }
    public WebAdminRole Role { get; set; } = WebAdminRole.SuperAdmin;
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAt { get; set; }
    public string CreatedBy { get; set; } = "System";
}
