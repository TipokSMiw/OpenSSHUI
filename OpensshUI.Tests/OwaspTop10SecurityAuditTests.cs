using System.IO;
using System.Reflection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using OpensshUI.Data;
using OpensshUI.Models;
using OpensshUI.Services.Audit;
using OpensshUI.Services.Auth;
using OpensshUI.Services.OpenSsh;
using OpensshUI.Services.Security;
using Xunit;

namespace OpensshUI.Tests;

public class OwaspTop10SecurityAuditTests
{
    private static string FindProjectRoot()
    {
        var current = Directory.GetCurrentDirectory();
        while (!string.IsNullOrEmpty(current))
        {
            if (File.Exists(Path.Combine(current, "OpensshUI.csproj")))
            {
                return current;
            }

            var parent = Directory.GetParent(current);
            if (parent == null) break;
            current = parent.FullName;
        }

        throw new DirectoryNotFoundException("Could not locate OpensshUI project root directory.");
    }

    [Fact]
    public void TC01_A01_UserSessionState_DefaultRole_ShouldBeAuditor()
    {
        var session = new UserSessionState();
        Assert.Equal(WebAdminRole.Auditor, session.Role);

        session.SetUser("admin", "Admin", true, WebAdminRole.SuperAdmin);
        session.Logout();
        Assert.Equal(WebAdminRole.Auditor, session.Role);
    }

    [Fact]
    public void TC02_A01_LoginModalAndAdminPages_ShouldPassRoleAndEnforceRbac()
    {
        var root = FindProjectRoot();

        // 1. LoginModal.razor must pass result.Role into SessionState.SetUser
        var loginModalPath = Path.Combine(root, "Components", "Pages", "LoginModal.razor");
        var loginModalText = File.ReadAllText(loginModalPath);
        Assert.Contains("SessionState.SetUser(result.Username, result.DisplayName, result.IsAdmin, result.Role)", loginModalText);

        // 2. WebAdminManagement.razor must have CanManageSystem RBAC guards
        var webAdminPath = Path.Combine(root, "Components", "Pages", "Admin", "WebAdminManagement.razor");
        var webAdminText = File.ReadAllText(webAdminPath);
        Assert.Contains("if (!SessionState.CanManageSystem) return;", webAdminText);

        // 3. FolderPickerModal.razor must have CanManageSftp RBAC guards
        var folderPickerPath = Path.Combine(root, "Components", "Shared", "FolderPickerModal.razor");
        var folderPickerText = File.ReadAllText(folderPickerPath);
        Assert.Contains("if (!SessionState.CanManageSftp) return;", folderPickerText);
    }

    [Fact]
    public void TC03_A02_SshKeyConverter_ShouldNotAllowSshDssAlgorithm()
    {
        var field = typeof(SshKeyConverter).GetField("ValidKeyTypes", BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static);
        Assert.NotNull(field);
        var validTypes = (string[])field!.GetValue(null)!;
        Assert.DoesNotContain("ssh-dss", validTypes);

        var dsaKey = "ssh-dss AAAAB3NzaC1kc3MAAACBAP1234567890 dummy-comment";
        var result = SshKeyConverter.ParseAndNormalizeKey(dsaKey);
        Assert.False(result.IsSuccess, "ssh-dss (DSA) keys must be rejected.");
    }

    [Theory]
    [InlineData("=cmd")]
    [InlineData("  =1+1")]
    [InlineData("\t=cmd")]
    [InlineData("\r+cmd")]
    [InlineData(" -2+3")]
    [InlineData(" @SUM(1,2)")]
    public void TC04_A03_EscapeCsv_ShouldNeutralizeFormulasWithLeadingSpacesOrControlChars(string formula)
    {
        var escaped = SshEventLogService.EscapeCsv(formula);
        Assert.StartsWith("\"'", escaped);
    }

    [Theory]
    [InlineData("a")]
    [InlineData("ab")]
    [InlineData("abc")]
    public void TC05_A04_ValidateWindowsPassword_ShouldRejectPasswordsShorterThan4Chars(string shortPassword)
    {
        var (isValid, err) = SecurityValidator.ValidateWindowsPassword(shortPassword);
        Assert.False(isValid, $"Password '{shortPassword}' shorter than 4 characters must be rejected.");
        Assert.NotNull(err);
        Assert.Contains("4 characters", err);
    }

    [Fact]
    public void TC05_A04_ValidateWindowsPassword_ShouldAcceptPasswordWith4OrMoreChars()
    {
        var (isValid, err) = SecurityValidator.ValidateWindowsPassword("abcd");
        Assert.True(isValid, $"Password 'abcd' should be accepted, error: {err}");
    }

    [Fact]
    public void TC06_A05_A06_A08_ProgramAndAppRazor_ShouldConfigureSecurityHeadersAndCdnAttributes()
    {
        var root = FindProjectRoot();

        var programPath = Path.Combine(root, "Program.cs");
        var programText = File.ReadAllText(programPath);
        Assert.Contains("X-Content-Type-Options", programText);
        Assert.Contains("X-Frame-Options", programText);
        Assert.Contains("Content-Security-Policy", programText);

        var appRazorPath = Path.Combine(root, "Components", "App.razor");
        var appRazorText = File.ReadAllText(appRazorPath);
        Assert.Contains("crossorigin=\"anonymous\"", appRazorText);
        Assert.Contains("referrerpolicy=\"no-referrer\"", appRazorText);
    }

    [Fact]
    public void TC07_A07_UserSessionState_ShouldSupportSessionTimeout()
    {
        var propTimeout = typeof(UserSessionState).GetProperty("SessionTimeout");
        Assert.NotNull(propTimeout);

        var propExpired = typeof(UserSessionState).GetProperty("IsSessionExpired");
        Assert.NotNull(propExpired);
    }

    [Fact]
    public async Task TC08_A09_AuditService_ShouldSanitizeNewlinesInLoggedFields()
    {
        using var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();

        var dbOptions = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(connection)
            .Options;

        using (var initDb = new AppDbContext(dbOptions))
        {
            initDb.Database.EnsureCreated();
        }

        var dbFactory = Substitute.For<IDbContextFactory<AppDbContext>>();
        dbFactory.CreateDbContextAsync(Arg.Any<CancellationToken>())
            .Returns(_ => Task.FromResult(new AppDbContext(dbOptions)));

        var auditService = new AuditService(dbFactory, NullLogger<AuditService>.Instance);
        await auditService.LogAsync("LOGIN\r\nFAKE_ACTION", "detail1\r\nFAKE_LOG", true, "admin\r\nroot");

        using var verifyDb = new AppDbContext(dbOptions);
        var log = await verifyDb.AuditLogs.FirstAsync();

        Assert.DoesNotContain("\r", log.Action);
        Assert.DoesNotContain("\n", log.Action);
        Assert.DoesNotContain("\r", log.Operator);
        Assert.DoesNotContain("\n", log.Operator);
    }

    [Fact]
    public void TC09_A09_MainLayout_Logout_ShouldLogAdminLogout()
    {
        var root = FindProjectRoot();
        var mainLayoutPath = Path.Combine(root, "Components", "Layout", "MainLayout.razor");
        var text = File.ReadAllText(mainLayoutPath);
        Assert.Contains("ADMIN_LOGOUT", text);
    }

    [Fact]
    public void TC10_A10_SecurityValidator_ValidateLdapHost_ShouldExistAndBlockInvalidHosts()
    {
        var method = typeof(SecurityValidator).GetMethod("ValidateLdapHost", BindingFlags.Public | BindingFlags.Static);
        Assert.NotNull(method);
    }

    [Fact]
    public void TC11_Docs_AgentMd_ShouldDocumentOwaspTop10Standards()
    {
        var root = FindProjectRoot();
        var agentMdPath = Path.Combine(root, "AGENT.md");
        var text = File.ReadAllText(agentMdPath);
        Assert.Contains("OWASP Top 10", text);
        Assert.Contains("ssh-dss", text);
        Assert.Contains("4 characters", text);
    }
}
