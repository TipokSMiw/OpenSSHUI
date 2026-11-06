using OpensshUI.Models;

namespace OpensshUI.Services.Auth;

public class WebAdminOperationResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;

    public static WebAdminOperationResult Ok(string message = "ดำเนินการสำเร็จ") => new() { Success = true, Message = message };
    public static WebAdminOperationResult Fail(string message) => new() { Success = false, Message = message };
}

public interface IWebAdminService
{
    Task<List<WebAdminUser>> GetAllAdminsAsync();
    Task<WebAdminUser?> GetAdminByIdAsync(int id);
    Task<WebAdminUser?> GetAdminByUsernameAsync(string username);
    Task<WebAdminOperationResult> CreateLocalAdminAsync(string username, string displayName, string? email, string password, WebAdminRole role, string operatorUser);
    Task<WebAdminOperationResult> CreateAdAdminAsync(string username, string displayName, string? email, WebAdminRole role, string operatorUser);
    Task<WebAdminOperationResult> UpdateRoleAsync(int id, WebAdminRole newRole, string operatorUser);
    Task<WebAdminOperationResult> ResetPasswordAsync(int id, string newPassword, string operatorUser);
    Task<WebAdminOperationResult> ToggleStatusAsync(int id, string operatorUser);
    Task<WebAdminOperationResult> DeleteAdminAsync(int id, string operatorUser);
}
