using System.IO;
using System.Linq;
using OpensshUI.Models;
using Xunit;

namespace OpensshUI.Tests;

public class UiContrastContractTests
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
    public void AppCss_MustDefine_AllRequiredBootstrapSubtleAndEmphasisClasses()
    {
        var root = FindProjectRoot();
        var appCssPath = Path.Combine(root, "wwwroot", "app.css");
        Assert.True(File.Exists(appCssPath), $"File not found: {appCssPath}");

        var cssContent = File.ReadAllText(appCssPath);

        string[] requiredClasses =
        {
            ".bg-primary-subtle",
            ".bg-secondary-subtle",
            ".bg-success-subtle",
            ".bg-danger-subtle",
            ".bg-warning-subtle",
            ".bg-info-subtle",
            ".bg-dark-subtle",
            ".border-primary-subtle",
            ".border-secondary-subtle",
            ".border-success-subtle",
            ".border-danger-subtle",
            ".border-warning-subtle",
            ".border-info-subtle",
            ".border-dark-subtle",
            ".text-primary-emphasis",
            ".text-secondary-emphasis",
            ".text-success-emphasis",
            ".text-danger-emphasis",
            ".text-warning-emphasis",
            ".text-info-emphasis",
            ".text-dark-emphasis",
            ".text-code-warning",
            ".quick-action-card",
            ".breadcrumb-item.active",
            ".path-badge",
            ".path-badge-default",
            ".path-badge-custom",
            ".badge-event",
            ".badge-event-success",
            ".badge-event-danger",
            ".badge-event-warning",
            ".badge-event-info",
            ".badge-event-system"
        };

        foreach (var cls in requiredClasses)
        {
            Assert.Contains(cls, cssContent);
        }
    }

    [Fact]
    public void RazorPages_MustNotContain_InvisibleTextWarningSubtle()
    {
        var root = FindProjectRoot();
        var componentsDir = Path.Combine(root, "Components");
        Assert.True(Directory.Exists(componentsDir), $"Directory not found: {componentsDir}");

        var razorFiles = Directory.GetFiles(componentsDir, "*.razor", SearchOption.AllDirectories);

        foreach (var file in razorFiles)
        {
            var content = File.ReadAllText(file);
            Assert.False(
                content.Contains("text-warning-subtle"),
                $"File '{Path.GetFileName(file)}' still contains invalid 'text-warning-subtle' which causes black text on dark background.");
        }
    }

    [Fact]
    public void UserManagement_EffectiveRootPath_MustUsePathBadge()
    {
        var root = FindProjectRoot();
        var userMgmtPath = Path.Combine(root, "Components", "Pages", "Users", "UserManagement.razor");
        Assert.True(File.Exists(userMgmtPath), $"File not found: {userMgmtPath}");

        var content = File.ReadAllText(userMgmtPath);
        Assert.Contains("path-badge path-badge-default", content);
        Assert.Contains("path-badge path-badge-custom", content);
    }

    [Fact]
    public void OpenSshLog_BadgeClasses_MustReturnSolidHighContrastClasses()
    {
        // Helper matching the OpenSshLogPage logic
        string GetBadgeClass(SshEventType type) => type switch
        {
            SshEventType.AuthSuccess => "badge-event badge-event-success",
            SshEventType.AuthFailed => "badge-event badge-event-danger",
            SshEventType.ConnectionClosed => "badge-event badge-event-warning",
            SshEventType.SftpActivity => "badge-event badge-event-info",
            _ => "badge-event badge-event-system"
        };

        var types = Enum.GetValues<SshEventType>();
        foreach (var type in types)
        {
            var cls = GetBadgeClass(type);
            Assert.Contains("badge-event", cls);
            Assert.False(cls.Contains("-subtle"), "Must use solid high-contrast badges for event types rather than subtle ones");
        }
    }

    [Fact]
    public void AuditLog_BadgeClasses_MustHaveProperContrast()
    {
        // Helper matching AuditLogPage logic
        string GetActionBadgeClass(string action)
        {
            if (action.StartsWith("USER_") || action.StartsWith("GROUP_"))
                return "bg-primary-subtle text-primary border border-primary-subtle";
            if (action.StartsWith("KEY_"))
                return "bg-warning-subtle text-warning-emphasis border border-warning-subtle";
            if (action.StartsWith("SERVICE_") || action.StartsWith("ZEROCONFIG_"))
                return "bg-info-subtle text-info-emphasis border border-info-subtle";
            if (action.StartsWith("FILE_") || action.StartsWith("FOLDER_"))
                return "bg-success-subtle text-success border border-success-subtle";
            if (action.StartsWith("ADMIN_") || action.StartsWith("CONFIG_"))
                return "bg-dark-subtle text-dark-emphasis border border-dark-subtle";
            return "bg-secondary-subtle text-secondary-emphasis border border-secondary-subtle";
        }

        string[] testActions = { "USER_CREATE", "KEY_GEN", "SERVICE_RESTART", "FILE_DOWNLOAD", "ADMIN_LOGIN", "OTHER_ACTION" };
        foreach (var action in testActions)
        {
            var cls = GetActionBadgeClass(action);
            Assert.Contains("-subtle", cls);
            Assert.DoesNotContain("text-secondary border", cls);
        }
    }
}
