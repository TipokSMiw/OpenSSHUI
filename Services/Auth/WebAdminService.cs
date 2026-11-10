using Microsoft.EntityFrameworkCore;
using OpensshUI.Data;
using OpensshUI.Models;
using OpensshUI.Services.Audit;
using OpensshUI.Services.Security;

namespace OpensshUI.Services.Auth;

public class WebAdminService : IWebAdminService
{
    private readonly IDbContextFactory<AppDbContext> _dbFactory;
    private readonly IAuditService _auditService;
    private readonly ILogger<WebAdminService> _logger;

    public WebAdminService(
        IDbContextFactory<AppDbContext> dbFactory,
        IAuditService auditService,
        ILogger<WebAdminService> logger)
    {
        _dbFactory = dbFactory;
        _auditService = auditService;
        _logger = logger;
    }

    public async Task<List<WebAdminUser>> GetAllAdminsAsync()
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        return await db.WebAdminUsers
            .OrderBy(u => u.AccountType)
            .ThenBy(u => u.Username)
            .ToListAsync();
    }

    public async Task<WebAdminUser?> GetAdminByIdAsync(int id)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        return await db.WebAdminUsers.FirstOrDefaultAsync(u => u.Id == id);
    }

    private static bool IsSameAccount(string? userA, string? userB)
    {
        if (string.IsNullOrWhiteSpace(userA) || string.IsNullOrWhiteSpace(userB))
            return false;

        if (userA.Trim().Equals(userB.Trim(), StringComparison.OrdinalIgnoreCase))
            return true;

        var canonA = SecurityValidator.ExtractCanonicalUsername(userA);
        var canonB = SecurityValidator.ExtractCanonicalUsername(userB);
        return !string.IsNullOrEmpty(canonA) && canonA.Equals(canonB, StringComparison.OrdinalIgnoreCase);
    }

    public async Task<WebAdminUser?> GetAdminByUsernameAsync(string username)
    {
        if (string.IsNullOrWhiteSpace(username)) return null;
        var clean = username.Trim().ToLowerInvariant();
        var canonical = SecurityValidator.ExtractCanonicalUsername(username).ToLowerInvariant();
        await using var db = await _dbFactory.CreateDbContextAsync();
        return await db.WebAdminUsers.FirstOrDefaultAsync(u => u.Username.ToLower() == clean || u.Username.ToLower() == canonical);
    }

    public async Task<WebAdminOperationResult> CreateLocalAdminAsync(
        string username,
        string displayName,
        string? email,
        string password,
        WebAdminRole role,
        string operatorUser)
    {
        if (string.IsNullOrWhiteSpace(username))
            return WebAdminOperationResult.Fail("กรุณาระบุ Username");

        var cleanUsername = SecurityValidator.ExtractCanonicalUsername(username);
        if (cleanUsername.Length < 3 || cleanUsername.Length > 50)
            return WebAdminOperationResult.Fail("Username ต้องมีความยาวระหว่าง 3 ถึง 50 ตัวอักษร");

        if (string.IsNullOrWhiteSpace(displayName))
            return WebAdminOperationResult.Fail("กรุณาระบุชื่อ-นามสกุล (Display Name)");

        if (string.IsNullOrWhiteSpace(password) || password.Length < 8)
            return WebAdminOperationResult.Fail("รหัสผ่านต้องมีความยาวอย่างน้อย 8 ตัวอักษร");

        var cleanLower = cleanUsername.ToLowerInvariant();
        await using var db = await _dbFactory.CreateDbContextAsync();
        bool exists = await db.WebAdminUsers.AnyAsync(u => u.Username.ToLower() == cleanLower);
        if (exists)
            return WebAdminOperationResult.Fail($"ชื่อผู้ใช้ '{cleanUsername}' มีอยู่ในระบบแล้ว");

        var user = new WebAdminUser
        {
            Username = cleanUsername,
            DisplayName = displayName.Trim(),
            Email = string.IsNullOrWhiteSpace(email) ? null : email.Trim(),
            AccountType = WebAdminType.Local,
            PasswordHash = PasswordHasher.HashPassword(password),
            Role = role,
            IsActive = true,
            CreatedAt = DateTime.UtcNow,
            CreatedBy = operatorUser
        };

        db.WebAdminUsers.Add(user);
        await db.SaveChangesAsync();

        UserSessionState.NotifyUserStatusChanged(cleanUsername, true, role);

        await _auditService.LogAsync("CREATE_WEB_ADMIN", $"Created Local Web Admin '{cleanUsername}' with role {role}", true, operatorUser);
        _logger.LogInformation("Web admin {Admin} created local admin {User} with role {Role}", operatorUser, cleanUsername, role);

        return WebAdminOperationResult.Ok($"สร้างบัญชีผู้ดูแล '{cleanUsername}' เรียบร้อยแล้ว");
    }

    public async Task<WebAdminOperationResult> CreateAdAdminAsync(
        string username,
        string displayName,
        string? email,
        WebAdminRole role,
        string operatorUser)
    {
        if (string.IsNullOrWhiteSpace(username))
            return WebAdminOperationResult.Fail("กรุณาระบุ Username ของ Active Directory");

        var cleanUsername = SecurityValidator.ExtractCanonicalUsername(username);
        if (string.IsNullOrWhiteSpace(cleanUsername))
            return WebAdminOperationResult.Fail("รูปแบบ Username ของ Active Directory ไม่ถูกต้อง");

        var cleanLower = cleanUsername.ToLowerInvariant();
        await using var db = await _dbFactory.CreateDbContextAsync();
        bool exists = await db.WebAdminUsers.AnyAsync(u => u.Username.ToLower() == cleanLower);
        if (exists)
            return WebAdminOperationResult.Fail($"ผู้ใช้ AD '{cleanUsername}' ได้รับสิทธิ์ผู้ดูแลระบบอยู่แล้ว");

        var user = new WebAdminUser
        {
            Username = cleanUsername,
            DisplayName = string.IsNullOrWhiteSpace(displayName) ? cleanUsername : displayName.Trim(),
            Email = string.IsNullOrWhiteSpace(email) ? null : email.Trim(),
            AccountType = WebAdminType.ActiveDirectory,
            PasswordHash = null,
            Role = role,
            IsActive = true,
            CreatedAt = DateTime.UtcNow,
            CreatedBy = operatorUser
        };

        db.WebAdminUsers.Add(user);
        await db.SaveChangesAsync();

        UserSessionState.NotifyUserStatusChanged(cleanUsername, true, role);

        await _auditService.LogAsync("CREATE_AD_WEB_ADMIN", $"Assigned Web Admin access to AD user '{cleanUsername}' with role {role}", true, operatorUser);
        _logger.LogInformation("Web admin {Admin} granted AD user {User} web admin role {Role}", operatorUser, cleanUsername, role);

        return WebAdminOperationResult.Ok($"มอบสิทธิ์ผู้ดูแลระบบให้บัญชี AD '{cleanUsername}' เรียบร้อยแล้ว");
    }

    public async Task<WebAdminOperationResult> UpdateRoleAsync(int id, WebAdminRole newRole, string operatorUser)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var admin = await db.WebAdminUsers.FirstOrDefaultAsync(u => u.Id == id);
        if (admin == null)
            return WebAdminOperationResult.Fail("ไม่พบบัญชีผู้ดูแลระบบที่ต้องการแก้ไข");

        // Guardrail: If changing a SuperAdmin to another role, ensure at least one other active SuperAdmin remains
        if (admin.Role == WebAdminRole.SuperAdmin && newRole != WebAdminRole.SuperAdmin)
        {
            var otherSuperAdminCount = await db.WebAdminUsers
                .CountAsync(u => u.Id != id && u.Role == WebAdminRole.SuperAdmin && u.IsActive);

            if (otherSuperAdminCount == 0)
            {
                return WebAdminOperationResult.Fail("ไม่สามารถลดระดับสิทธิ์ของ Super Admin คนสุดท้ายของระบบได้");
            }
        }

        var oldRole = admin.Role;
        admin.Role = newRole;
        await db.SaveChangesAsync();

        UserSessionState.NotifyUserStatusChanged(admin.Username, admin.IsActive, admin.Role);

        await _auditService.LogAsync("UPDATE_WEB_ADMIN_ROLE", $"Changed role for '{admin.Username}' from {oldRole} to {newRole}", true, operatorUser);
        _logger.LogInformation("Web admin {Admin} updated role for {User} from {Old} to {New}", operatorUser, admin.Username, oldRole, newRole);

        return WebAdminOperationResult.Ok($"ปรับระดับสิทธิ์ของ '{admin.Username}' เป็น {newRole} สำเร็จ");
    }

    public async Task<WebAdminOperationResult> ResetPasswordAsync(int id, string newPassword, string operatorUser)
    {
        if (string.IsNullOrWhiteSpace(newPassword) || newPassword.Length < 8)
            return WebAdminOperationResult.Fail("รหัสผ่านใหม่ต้องมีความยาวอย่างน้อย 8 ตัวอักษร");

        await using var db = await _dbFactory.CreateDbContextAsync();
        var admin = await db.WebAdminUsers.FirstOrDefaultAsync(u => u.Id == id);
        if (admin == null)
            return WebAdminOperationResult.Fail("ไม่พบบัญชีผู้ดูแลระบบที่ต้องการรีเซ็ตรหัสผ่าน");

        if (admin.AccountType != WebAdminType.Local)
            return WebAdminOperationResult.Fail("ไม่สามารถรีเซ็ตรหัสผ่านของบัญชี Active Directory ผ่านระบบนี้ได้ (ต้องจัดการที่ AD)");

        admin.PasswordHash = PasswordHasher.HashPassword(newPassword);
        await db.SaveChangesAsync();

        // Also if this is the fallback admin, synchronize with LdapConfig to maintain consistency
        var ldapConfig = await db.LdapConfigs.FirstOrDefaultAsync();
        if (ldapConfig != null && string.Equals(ldapConfig.FallbackAdminUsername, admin.Username, StringComparison.OrdinalIgnoreCase))
        {
            ldapConfig.FallbackAdminPasswordHash = admin.PasswordHash;
            await db.SaveChangesAsync();
        }

        await _auditService.LogAsync("RESET_WEB_ADMIN_PASSWORD", $"Reset password for local web admin '{admin.Username}'", true, operatorUser);
        _logger.LogInformation("Web admin {Admin} reset password for local user {User}", operatorUser, admin.Username);

        return WebAdminOperationResult.Ok($"เปลี่ยนรหัสผ่านสำหรับ '{admin.Username}' เรียบร้อยแล้ว");
    }

    public async Task<WebAdminOperationResult> ToggleStatusAsync(int id, string operatorUser)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var admin = await db.WebAdminUsers.FirstOrDefaultAsync(u => u.Id == id);
        if (admin == null)
            return WebAdminOperationResult.Fail("ไม่พบบัญชีผู้ดูแลระบบ");

        // Guardrail: Cannot deactivate self (including canonical DOMAIN\user or user@domain forms)
        if (IsSameAccount(admin.Username, operatorUser) && admin.IsActive)
        {
            return WebAdminOperationResult.Fail("ไม่สามารถระงับการใช้งานบัญชีของตนเองที่กำลังเข้าสู่ระบบอยู่ได้");
        }

        // Guardrail: Cannot deactivate last active SuperAdmin
        if (admin.Role == WebAdminRole.SuperAdmin && admin.IsActive)
        {
            var otherSuperAdminCount = await db.WebAdminUsers
                .CountAsync(u => u.Id != id && u.Role == WebAdminRole.SuperAdmin && u.IsActive);

            if (otherSuperAdminCount == 0)
            {
                return WebAdminOperationResult.Fail("ไม่สามารถระงับการใช้งาน Super Admin บัญชีสุดท้ายของระบบได้");
            }
        }

        admin.IsActive = !admin.IsActive;
        await db.SaveChangesAsync();

        UserSessionState.NotifyUserStatusChanged(admin.Username, admin.IsActive, admin.Role);

        var action = admin.IsActive ? "ACTIVATE_WEB_ADMIN" : "DEACTIVATE_WEB_ADMIN";
        var statusText = admin.IsActive ? "เปิดใช้งาน" : "ระงับการใช้งาน";
        await _auditService.LogAsync(action, $"{statusText} web admin '{admin.Username}'", true, operatorUser);
        _logger.LogInformation("Web admin {Admin} changed status of {User} to {Status}", operatorUser, admin.Username, statusText);

        return WebAdminOperationResult.Ok($"เปลี่ยนสถานะของ '{admin.Username}' เป็น '{statusText}' เรียบร้อยแล้ว");
    }

    public async Task<WebAdminOperationResult> DeleteAdminAsync(int id, string operatorUser)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var admin = await db.WebAdminUsers.FirstOrDefaultAsync(u => u.Id == id);
        if (admin == null)
            return WebAdminOperationResult.Fail("ไม่พบบัญชีผู้ดูแลระบบที่ต้องการลบ");

        // Guardrail: Cannot delete self (including canonical DOMAIN\user or user@domain forms)
        if (IsSameAccount(admin.Username, operatorUser))
        {
            return WebAdminOperationResult.Fail("ไม่สามารถลบบัญชีของตนเองที่กำลังเข้าสู่ระบบอยู่ได้");
        }

        // Guardrail: Cannot delete last active SuperAdmin
        if (admin.Role == WebAdminRole.SuperAdmin)
        {
            var otherSuperAdminCount = await db.WebAdminUsers
                .CountAsync(u => u.Id != id && u.Role == WebAdminRole.SuperAdmin && u.IsActive);

            if (otherSuperAdminCount == 0)
            {
                return WebAdminOperationResult.Fail("ไม่สามารถลบ Super Admin บัญชีสุดท้ายของระบบได้");
            }
        }

        // Guardrail: Prevent deleting the primary fallback "admin" user
        var ldapConfig = await db.LdapConfigs.FirstOrDefaultAsync();
        var fallbackUser = ldapConfig?.FallbackAdminUsername ?? "admin";
        if (admin.AccountType == WebAdminType.Local && IsSameAccount(admin.Username, fallbackUser))
        {
            return WebAdminOperationResult.Fail($"ไม่สามารถลบบัญชี Local Admin ฉุกเฉินหลัก ('{admin.Username}') ได้ หากไม่ต้องการให้ใช้งานโปรดเปลี่ยนรหัสผ่านหรือระงับการใช้งานแทน");
        }

        var deletedUsername = admin.Username;
        db.WebAdminUsers.Remove(admin);
        await db.SaveChangesAsync();

        UserSessionState.NotifyUserStatusChanged(deletedUsername, false, WebAdminRole.Auditor);

        await _auditService.LogAsync("DELETE_WEB_ADMIN", $"Deleted web admin '{deletedUsername}'", true, operatorUser);
        _logger.LogInformation("Web admin {Admin} deleted web admin {User}", operatorUser, deletedUsername);

        return WebAdminOperationResult.Ok($"ลบผู้ดูแลระบบ '{deletedUsername}' เรียบร้อยแล้ว");
    }
}
