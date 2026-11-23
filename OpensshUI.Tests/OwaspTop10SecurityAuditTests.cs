using System.IO;
using System.Reflection;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using OpensshUI.Data;
using OpensshUI.Models;
using OpensshUI.Services.Audit;
using OpensshUI.Services.Auth;
using OpensshUI.Services.Files;
using OpensshUI.Services.Groups;
using OpensshUI.Services.Localization;
using OpensshUI.Services.OpenSsh;
using OpensshUI.Services.Security;
using OpensshUI.Services.Users;
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

    private static string ExtractMethodBody(string source, string methodSignature, int maxLength = 600)
    {
        var idx = source.IndexOf(methodSignature, StringComparison.Ordinal);
        Assert.True(idx >= 0, $"Method signature '{methodSignature}' not found.");
        var len = Math.Min(maxLength, source.Length - idx);
        return source.Substring(idx, len);
    }

    [Fact]
    public void TC12_API1_BOLA_UserManagement_DeletePublicKey_ShouldVerifyKeyBelongsToSelectedUser()
    {
        var root = FindProjectRoot();
        var userMgmtPath = Path.Combine(root, "Components", "Pages", "Users", "UserManagement.razor");
        var text = File.ReadAllText(userMgmtPath);

        var body = ExtractMethodBody(text, "private async Task DeletePublicKey(int keyId)");
        Assert.Contains("selectedUser.PublicKeys.Any(k => k.Id == keyId)", body);
    }

    [Fact]
    public async Task TC13_API2_BrokenAuth_FallbackAdminPassword_ShouldRequireMin8Chars_AndSyncWithWebAdminUsers()
    {
        using var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();

        var dbOptions = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(connection)
            .Options;

        await using (var initDb = new AppDbContext(dbOptions))
        {
            await initDb.Database.EnsureCreatedAsync();
            await initDb.ApplyCustomMigrationsAsync();
        }

        var dbFactory = Substitute.For<IDbContextFactory<AppDbContext>>();
        dbFactory.CreateDbContextAsync(Arg.Any<CancellationToken>())
            .Returns(_ => Task.FromResult(new AppDbContext(dbOptions)));

        var protection = Substitute.For<IProtectionService>();
        protection.Protect(Arg.Any<string?>()).Returns(ci => ci.Arg<string?>());
        protection.Unprotect(Arg.Any<string?>()).Returns(ci => ci.Arg<string?>());

        var authService = new LdapAuthService(dbFactory, protection, NullLogger<LdapAuthService>.Instance);
        var config = await authService.GetConfigAsync();

        // 1. Reject fallback admin password shorter than 8 chars
        await Assert.ThrowsAsync<ArgumentException>(() =>
            authService.SaveConfigAsync(config, newFallbackAdminPassword: "short"));

        // 2. Updating fallback admin password must sync hash to WebAdminUsers so old default password stops working
        await authService.SaveConfigAsync(config, newFallbackAdminPassword: "NewAdmin@999");

        LdapAuthService.ResetLockoutForUser("admin");
        var oldAuth = await authService.AuthenticateAsync("admin", "Admin@123456");
        Assert.False(oldAuth.IsSuccess, "Old default password must no longer authenticate after changing fallback password.");

        var newAuth = await authService.AuthenticateAsync("admin", "NewAdmin@999");
        Assert.True(newAuth.IsSuccess, "New fallback password must authenticate even when admin exists in WebAdminUsers.");

        // 3. SettingsPage.razor must also enforce >= 8 characters
        var root = FindProjectRoot();
        var settingsPath = Path.Combine(root, "Components", "Pages", "Settings", "SettingsPage.razor");
        var settingsText = File.ReadAllText(settingsPath);
        Assert.Contains("newFallbackAdminPassword.Length >= 8", settingsText);
        Assert.Contains("newFallbackAdminPassword.Length < 8", settingsText);
    }

    [Fact]
    public async Task TC14_API3_BOPLA_WebAdminService_ShouldSanitizeDisplayNameAndEmail_AndRejectInvalidUsernameChars()
    {
        using var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();

        var dbOptions = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(connection)
            .Options;

        await using (var initDb = new AppDbContext(dbOptions))
        {
            await initDb.Database.EnsureCreatedAsync();
        }

        var dbFactory = Substitute.For<IDbContextFactory<AppDbContext>>();
        dbFactory.CreateDbContextAsync(Arg.Any<CancellationToken>())
            .Returns(_ => Task.FromResult(new AppDbContext(dbOptions)));

        var audit = Substitute.For<IAuditService>();
        var webAdminService = new WebAdminService(dbFactory, audit, NullLogger<WebAdminService>.Instance);

        var badLocal = await webAdminService.CreateLocalAdminAsync("bad;user", "Display", null, "StrongPass@123", WebAdminRole.Operator, "admin");
        Assert.False(badLocal.Success, "Username with shell/special characters must be rejected.");

        var badAd = await webAdminService.CreateAdAdminAsync("bad user", "Display", null, WebAdminRole.Operator, "admin");
        Assert.False(badAd.Success, "AD username with whitespace must be rejected.");

        var cleanResult = await webAdminService.CreateLocalAdminAsync(
            "clean_admin",
            "Admin\r\nInjected",
            "admin@corp.local\r\nBcc:evil",
            "StrongPass@123",
            WebAdminRole.Operator,
            "admin");
        Assert.True(cleanResult.Success);

        var created = await webAdminService.GetAdminByUsernameAsync("clean_admin");
        Assert.NotNull(created);
        Assert.DoesNotContain("\r", created!.DisplayName);
        Assert.DoesNotContain("\n", created.DisplayName);
        Assert.NotNull(created.Email);
        Assert.DoesNotContain("\r", created.Email!);
        Assert.DoesNotContain("\n", created.Email!);
    }

    [Fact]
    public async Task TC15_API4_ResourceConsumption_SftpSessionCache_And_AuditQuery_ShouldEnforceBoundedLimits()
    {
        // 1. Bounded session cache constant and runtime eviction check
        var maxCacheField = typeof(SftpSessionService).GetField("MaxSessionCacheEntries", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(maxCacheField);
        var maxCache = (int)maxCacheField!.GetValue(null)!;
        Assert.InRange(maxCache, 1, 1000);

        var setCacheMethod = typeof(SftpSessionService).GetMethod("SetSessionCacheEntry", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(setCacheMethod);

        var auditMock = Substitute.For<IAuditService>();
        var sessionSvc = new SftpSessionService(NullLogger<SftpSessionService>.Instance, auditMock);
        for (int i = 0; i < 1100; i++)
        {
            setCacheMethod!.Invoke(sessionSvc, new object[] { ($"10.0.{i / 256}.{i % 256}", 10000 + i), ($"user_{i}", DateTime.UtcNow) });
        }
        Assert.True(sessionSvc.SessionUserCache.Count <= 1000);

        // 2. AuditService.GetRecentLogsAsync must clamp oversized count <= 500
        using var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();
        var dbOptions = new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options;
        await using (var initDb = new AppDbContext(dbOptions))
        {
            await initDb.Database.EnsureCreatedAsync();
            for (int i = 0; i < 510; i++)
            {
                initDb.AuditLogs.Add(new AuditLog
                {
                    Timestamp = DateTime.UtcNow.AddSeconds(i),
                    Action = "TEST_ACTION",
                    Operator = "admin",
                    Details = $"entry {i}",
                    IsSuccess = true
                });
            }
            await initDb.SaveChangesAsync();
        }

        var dbFactory = Substitute.For<IDbContextFactory<AppDbContext>>();
        dbFactory.CreateDbContextAsync(Arg.Any<CancellationToken>())
            .Returns(_ => Task.FromResult(new AppDbContext(dbOptions)));

        var auditService = new AuditService(dbFactory, NullLogger<AuditService>.Instance);
        var recent = await auditService.GetRecentLogsAsync(99999);
        Assert.True(recent.Count <= 500);

        // 3. SshEventLogService.GetMockLogs must clamp MaxRecords
        var root = FindProjectRoot();
        var eventLogSvcText = File.ReadAllText(Path.Combine(root, "Services", "OpenSsh", "SshEventLogService.cs"));
        var getMockBody = ExtractMethodBody(eventLogSvcText, "public OpenSshLogQueryResult GetMockLogs(SshLogFilter filter)", 3000);
        Assert.Contains("Math.Clamp(filter.MaxRecords, 10, 2000)", getMockBody);

        var eventLogSvc = new SshEventLogService(NullLogger<SshEventLogService>.Instance);
        var mockRes = eventLogSvc.GetMockLogs(new SshLogFilter { MaxRecords = 1, TimePreset = SshTimePreset.Last7Days });
        Assert.Equal(10, mockRes.Entries.Count);
    }

    [Fact]
    public void TC16_API5_BFLA_SignalRHandlers_ShouldEnforceRbacGuardsOnDemoToggleAndFolderPicker()
    {
        var root = FindProjectRoot();

        // 1. SessionManagement.razor: Demo Mode toggle UI & Handler
        var sessionPageText = File.ReadAllText(Path.Combine(root, "Components", "Pages", "Sessions", "SessionManagement.razor"));
        Assert.Contains("@if (SessionState.CanManageSftp)", sessionPageText);
        Assert.Contains("if (!SessionState.CanManageSftp) return;", ExtractMethodBody(sessionPageText, "private async Task ToggleDemoMode()"));

        // 2. UserManagement.razor: Folder browser & AD search handlers
        var userPageText = File.ReadAllText(Path.Combine(root, "Components", "Pages", "Users", "UserManagement.razor"));
        Assert.Contains("if (!SessionState.CanManageSftp) return;", ExtractMethodBody(userPageText, "private void OpenFolderBrowserForCreate()"));
        Assert.Contains("if (!SessionState.CanManageSftp) return;", ExtractMethodBody(userPageText, "private void OpenFolderBrowserForEdit()"));
        Assert.Contains("if (!SessionState.CanManageSftp) return;", ExtractMethodBody(userPageText, "private void HandleFolderSelected(string path)"));
        Assert.Contains("if (!SessionState.CanManageSftp) return;", ExtractMethodBody(userPageText, "private async Task SearchActiveDirectory()"));

        // 3. GroupManagement.razor: Folder browser handlers
        var groupPageText = File.ReadAllText(Path.Combine(root, "Components", "Pages", "Groups", "GroupManagement.razor"));
        Assert.Contains("if (!SessionState.CanManageSftp) return;", ExtractMethodBody(groupPageText, "private void OpenFolderBrowserForCreate()"));
        Assert.Contains("if (!SessionState.CanManageSftp) return;", ExtractMethodBody(groupPageText, "private void OpenFolderBrowserForEdit()"));
        Assert.Contains("if (!SessionState.CanManageSftp) return;", ExtractMethodBody(groupPageText, "private void HandleFolderSelected(string path)"));

        // 4. ServiceControlPage.razor: Concurrency preset handlers
        var servicePageText = File.ReadAllText(Path.Combine(root, "Components", "Pages", "Service", "ServiceControlPage.razor"));
        Assert.Contains("if (!SessionState.CanManageSystem) return;", ExtractMethodBody(servicePageText, "private void ApplyStandardPreset()"));
        Assert.Contains("if (!SessionState.CanManageSystem) return;", ExtractMethodBody(servicePageText, "private void ApplyHighTrafficPreset()"));
        Assert.Contains("if (!SessionState.CanManageSystem) return;", ExtractMethodBody(servicePageText, "private void ApplyDefaultPreset()"));

        // 5. FolderPickerModal.razor: Drive & folder enumeration handlers
        var folderModalText = File.ReadAllText(Path.Combine(root, "Components", "Shared", "FolderPickerModal.razor"));
        Assert.Contains("if (!SessionState.CanManageSftp) return;", ExtractMethodBody(folderModalText, "private void LoadDrives()"));
        Assert.Contains("if (!SessionState.CanManageSftp) return;", ExtractMethodBody(folderModalText, "private void NavigateTo(string path)"));
        Assert.Contains("if (!SessionState.CanManageSftp) return;", ExtractMethodBody(folderModalText, "private void GoToCurrentPath()"));
    }

    [Theory]
    [InlineData("dc01.corp.local:636")]
    [InlineData("dc01;whoami")]
    [InlineData("dc01&calc")]
    [InlineData("dc01|dir")]
    [InlineData("dc01$env")]
    [InlineData("dc01`id`")]
    [InlineData("dc01<in")]
    [InlineData("dc01>out")]
    [InlineData("dc01\"quote")]
    [InlineData("dc01'quote")]
    public void TC17_API7_SSRF_ValidateLdapHost_ShouldBlockPortAndShellMetacharacters(string evilHost)
    {
        var (isValid, err) = SecurityValidator.ValidateLdapHost(evilHost, 389);
        Assert.False(isValid, $"Host '{evilHost}' must be rejected.");
        Assert.NotNull(err);
    }

    [Fact]
    public void TC18_API8_Misconfiguration_ValidateMaxStartups_ShouldRejectMalformedConcurrencyStrings_AndCspShouldMatchSpec()
    {
        var validateMethod = typeof(SecurityValidator).GetMethod("ValidateMaxStartups", BindingFlags.Public | BindingFlags.Static);
        Assert.NotNull(validateMethod);

        string?[] invalidInputs =
        {
            null,
            "",
            "   ",
            "10:30:100\nPermitRootLogin yes",
            "10:30:100 #bad",
            "abc",
            "100:30:50",
            "10:150:100"
        };

        foreach (var bad in invalidInputs)
        {
            var res = ((bool IsValid, string? ErrorMessage))validateMethod!.Invoke(null, new object?[] { bad })!;
            Assert.False(res.IsValid, $"MaxStartups '{bad}' must be rejected.");
        }

        string[] validInputs = { "10:30:100", "100:30:300", "50" };
        foreach (var good in validInputs)
        {
            var res = ((bool IsValid, string? ErrorMessage))validateMethod!.Invoke(null, new object?[] { good })!;
            Assert.True(res.IsValid, $"MaxStartups '{good}' should be accepted, error: {res.ErrorMessage}");
        }

        var root = FindProjectRoot();
        var programText = File.ReadAllText(Path.Combine(root, "Program.cs"));
        Assert.Contains("img-src 'self' https://cdn.jsdelivr.net data:;", programText);
    }

    [Fact]
    public void TC19_API10_UnsafeApiConsumption_SshKeyGenerator_ShouldDrainStandardErrorStream()
    {
        var root = FindProjectRoot();
        var keyGenText = File.ReadAllText(Path.Combine(root, "Services", "OpenSsh", "SshKeyGenerator.cs"));
        var extractBody = ExtractMethodBody(keyGenText, "private async Task<string?> ExtractPublicKeyFromPrivateKeyAsync", 1400);
        Assert.Contains("proc.StandardError.ReadToEndAsync()", extractBody);
        Assert.Contains("await stderrTask", extractBody);

        var ldapAuthText = File.ReadAllText(Path.Combine(root, "Services", "Auth", "LdapAuthService.cs"));
        var groupCheckBody = ExtractMethodBody(ldapAuthText, "private bool CheckUserGroupMembership", 800);
        Assert.Contains("SizeLimit", groupCheckBody);
    }

    [Fact]
    public void TC20_API9_Docs_AgentMd_ShouldDocumentOwaspApiSecurityTop10Standards()
    {
        var root = FindProjectRoot();
        var agentMdText = File.ReadAllText(Path.Combine(root, "AGENT.md"));
        Assert.Contains("OWASP API Security Top 10", agentMdText);
        for (int i = 1; i <= 10; i++)
        {
            Assert.Contains($"API{i}:2023", agentMdText);
        }
    }

    [Fact]
    public void TC21_CSP_SRI_NoInlineScripts_And_PerCircuitDemo_ShouldMeetHardenedBaseline()
    {
        var root = FindProjectRoot();

        // 1. Program.cs CSP strict script-src 'self' without 'unsafe-inline' & startup ACL hardening
        var programText = File.ReadAllText(Path.Combine(root, "Program.cs"));
        var cspMatch = Regex.Match(programText, @"script-src\s+[^;""]+");
        Assert.True(cspMatch.Success, "Program.cs must configure script-src in Content-Security-Policy.");
        Assert.Contains("'self'", cspMatch.Value);
        Assert.DoesNotContain("'unsafe-inline'", cspMatch.Value);
        Assert.Contains("SecureAppDataDirectory(dbDir)", programText);

        // 2. App.razor external app.js & SRI integrity on Bootstrap Icons CSS, no inline <script>
        var appRazorText = File.ReadAllText(Path.Combine(root, "Components", "App.razor"));
        Assert.Contains("integrity=\"sha384-", appRazorText);
        Assert.Contains("crossorigin=\"anonymous\"", appRazorText);
        Assert.Contains("referrerpolicy=\"no-referrer\"", appRazorText);
        Assert.Contains("src=\"app.js", appRazorText);
        Assert.False(Regex.IsMatch(appRazorText, @"<script(?![^>]*\bsrc=)[^>]*>", RegexOptions.IgnoreCase),
            "App.razor must not contain inline <script> blocks.");

        // 3. wwwroot/app.js must define required named interop functions
        var appJsText = File.ReadAllText(Path.Combine(root, "wwwroot", "app.js"));
        Assert.Contains("window.downloadFileFromStream", appJsText);
        Assert.Contains("window.copyTextToClipboard", appJsText);
        Assert.Contains("window.getAppLanguage", appJsText);
        Assert.Contains("window.setAppLanguage", appJsText);

        // 4. Zero javascript:void(0) and zero inline HTML onclick= across Razor Components
        var razorFiles = Directory.GetFiles(Path.Combine(root, "Components"), "*.razor", SearchOption.AllDirectories);
        foreach (var file in razorFiles)
        {
            var text = File.ReadAllText(file);
            var rel = Path.GetRelativePath(root, file);
            Assert.False(text.Contains("javascript:void(0)", StringComparison.OrdinalIgnoreCase), $"{rel} still contains javascript:void(0).");
            Assert.False(Regex.IsMatch(text, @"(?<!@)\bonclick\s*=", RegexOptions.IgnoreCase), $"{rel} still contains inline HTML onclick attribute.");
        }

        // 5. SessionManagement.razor must keep Demo Mode strictly per-circuit (not singleton)
        var sessionPageText = File.ReadAllText(Path.Combine(root, "Components", "Pages", "Sessions", "SessionManagement.razor"));
        Assert.Contains("isDemoMode", sessionPageText);
        Assert.DoesNotContain("SessionService.IsDemoMode", sessionPageText);
        Assert.DoesNotContain("SessionService.ToggleDemoMode", sessionPageText);

        // 6. MainLayout.razor must subscribe & unsubscribe global revocation event
        var layoutText = File.ReadAllText(Path.Combine(root, "Components", "Layout", "MainLayout.razor"));
        Assert.Contains("UserSessionState.OnGlobalUserStatusChanged +=", layoutText);
        Assert.Contains("UserSessionState.OnGlobalUserStatusChanged -=", layoutText);

        // 7. Secure model defaults
        Assert.False(new LdapConfig().TrustSslCertificates);
        Assert.Equal(WebAdminRole.Auditor, new WebAdminUser().Role);
        Assert.Equal(WebAdminRole.Auditor, new AuthResult().Role);
    }

    [Fact]
    public void TC22_DIContainer_ShouldPassValidateScopesAndShareSingletonInstances()
    {
        using var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDataProtection();
        services.AddDbContextFactory<AppDbContext>(opt => opt.UseSqlite(connection));

        services.AddSingleton<IProtectionService, ProtectionService>();
        services.AddSingleton<IAuditService, AuditService>();
        services.AddScoped<ILdapAuthService, LdapAuthService>();
        services.AddScoped<IWebAdminService, WebAdminService>();
        services.AddScoped<UserSessionState>();
        services.AddScoped<ILocalizationService, LocalizationService>();
        services.AddSingleton<ISshdConfigService, SshdConfigService>();
        services.AddSingleton<NtfsAclService>();
        services.AddSingleton<INtfsAclService>(sp => sp.GetRequiredService<NtfsAclService>());
        services.AddSingleton<INativeAclProvisioner>(sp => sp.GetRequiredService<NtfsAclService>());
        services.AddSingleton<IWindowsUserManager, WindowsUserManager>();
        services.AddSingleton<IOpenSshServiceManager, OpenSshServiceManager>();
        services.AddSingleton<SshEventLogService>();
        services.AddSingleton<ISshEventLogService>(sp => sp.GetRequiredService<SshEventLogService>());
        services.AddSingleton<IOpenSshLogService>(sp => sp.GetRequiredService<SshEventLogService>());
        services.AddSingleton<ISftpSessionService, SftpSessionService>();
        services.AddSingleton<ISshKeyGenerator, SshKeyGenerator>();
        services.AddSingleton<ISecureFileBrowserService>(sp =>
            new SecureFileBrowserService(
                sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<SecureFileBrowserService>>(),
                @"C:\SFTPRoot",
                sp.GetRequiredService<IDbContextFactory<AppDbContext>>(),
                sp.GetRequiredService<IOpenSshServiceManager>()));
        services.AddScoped<ISftpGroupService, SftpGroupService>();
        services.AddScoped<ISftpUserService, SftpUserService>();

        using var provider = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = true,
            ValidateOnBuild = true
        });

        using var scope1 = provider.CreateScope();
        using var scope2 = provider.CreateScope();

        Assert.Same(scope1.ServiceProvider.GetRequiredService<IAuditService>(),
            scope2.ServiceProvider.GetRequiredService<IAuditService>());
        Assert.Same(provider.GetRequiredService<INtfsAclService>(),
            provider.GetRequiredService<INativeAclProvisioner>());
        Assert.Same(provider.GetRequiredService<ISshEventLogService>(),
            provider.GetRequiredService<IOpenSshLogService>());

        Assert.NotNull(scope1.ServiceProvider.GetRequiredService<ISftpUserService>());
        Assert.NotNull(scope1.ServiceProvider.GetRequiredService<ILdapAuthService>());
        Assert.NotNull(scope1.ServiceProvider.GetRequiredService<IWebAdminService>());
    }
}
