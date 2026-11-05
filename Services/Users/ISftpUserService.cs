using OpensshUI.Models;
using OpensshUI.Services.OpenSsh;

namespace OpensshUI.Services.Users;

public class CreateUserRequest
{
    public string Username { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public SftpAccountType AccountType { get; set; } = SftpAccountType.LocalWindows;
    public string? Password { get; set; }
    public string? SshPublicKey { get; set; }
    public string? Notes { get; set; }

    // Group & Custom Path support
    public List<string> GroupIds { get; set; } = new();
    public string? CustomRootPath { get; set; }
    public SftpPermissionType CustomPermissionType { get; set; } = SftpPermissionType.ReadWrite;
    public SftpAccessMode AccessMode { get; set; } = SftpAccessMode.VirtualFolder;
}

public class UpdateUserRequest
{
    public string Username { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string? Notes { get; set; }

    public List<string> GroupIds { get; set; } = new();
    public string? CustomRootPath { get; set; }
    public SftpPermissionType CustomPermissionType { get; set; } = SftpPermissionType.ReadWrite;
    public SftpAccessMode AccessMode { get; set; } = SftpAccessMode.VirtualFolder;
}

public class GenerateAutomationKeyRequest
{
    public string Username { get; set; } = string.Empty;
    public string KeyType { get; set; } = "ed25519"; // ed25519 or rsa
    public string? Comment { get; set; }
    public string? Passphrase { get; set; }
}

public interface ISftpUserService
{
    Task<List<SftpUser>> GetAllUsersAsync();
    Task<SftpUser?> GetUserAsync(string username);
    Task<(bool Success, string Message)> CreateUserAsync(CreateUserRequest request, string op = "admin");
    Task<(bool Success, string Message)> UpdateUserAsync(UpdateUserRequest request, string op = "admin");
    Task<(bool Success, string Message)> UpdateUserStatusAsync(string username, bool isActive, string op = "admin");
    Task<(bool Success, string Message)> ResetPasswordAsync(string username, string newPassword, string op = "admin");
    Task<(bool Success, string Message)> DeleteUserAsync(string username, bool deleteFiles = false, string op = "admin");
    Task<(bool Success, string Message, SshPublicKey? Key)> AddPublicKeyAsync(string username, string rawKey, string? comment = null, string op = "admin");
    Task<(bool Success, string Message)> DeletePublicKeyAsync(int keyId, string op = "admin");
    Task<(bool Success, string Message, SshKeyGenerateResult? Result)> GenerateAutomationKeyAsync(GenerateAutomationKeyRequest request, string op = "admin");
}
