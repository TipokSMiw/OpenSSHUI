using System.Text.RegularExpressions;
using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.JSInterop;
using NSubstitute;
using OpensshUI.Data;
using OpensshUI.Models;
using OpensshUI.Services.Audit;
using OpensshUI.Services.Auth;
using OpensshUI.Services.Localization;
using OpensshUI.Services.OpenSsh;
using Xunit;

namespace OpensshUI.Tests;

public class LocalizationServiceTests
{
    private static readonly Regex PlaceholderRegex = new(@"\{(\d+)\}", RegexOptions.Compiled);

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
    public void TC_I18N_01_AppStrings_ThaiAndEnglish_MustHave100PercentKeyParity()
    {
        var thKeys = AppStrings.GetAllKeys(AppStrings.Thai);
        var enKeys = AppStrings.GetAllKeys(AppStrings.English);

        thKeys.Should().NotBeEmpty();
        thKeys.Should().BeEquivalentTo(enKeys);

        foreach (var key in thKeys)
        {
            AppStrings.Get(key, AppStrings.Thai).Should().NotBeNullOrWhiteSpace($"Thai key '{key}' must have a non-empty translation.");
            AppStrings.Get(key, AppStrings.English).Should().NotBeNullOrWhiteSpace($"English key '{key}' must have a non-empty translation.");
        }
    }

    [Fact]
    public void TC_I18N_02_AppStrings_ParameterizedKeys_MustHaveMatchingPlaceholders()
    {
        var allKeys = AppStrings.GetAllKeys(AppStrings.Thai);

        foreach (var key in allKeys)
        {
            var thVal = AppStrings.Get(key, AppStrings.Thai);
            var enVal = AppStrings.Get(key, AppStrings.English);

            var thPlaceholders = PlaceholderRegex.Matches(thVal).Select(m => m.Value).Distinct().OrderBy(x => x).ToList();
            var enPlaceholders = PlaceholderRegex.Matches(enVal).Select(m => m.Value).Distinct().OrderBy(x => x).ToList();

            enPlaceholders.Should().BeEquivalentTo(thPlaceholders, $"key '{key}' must have matching format placeholders in TH and EN.");
        }
    }

    [Fact]
    public void TC_I18N_03_LocalizationService_DefaultLanguage_MustBeThai()
    {
        var svc = new LocalizationService();
        svc.CurrentLanguage.Should().Be(AppStrings.Thai);
        svc.IsThai.Should().BeTrue();
    }

    [Fact]
    public void TC_I18N_04_LocalizationService_SetLanguage_FiresOnLanguageChangedAndNormalizes()
    {
        var svc = new LocalizationService();
        int eventCount = 0;
        svc.OnLanguageChanged += () => eventCount++;

        svc.SetLanguage("en");
        svc.CurrentLanguage.Should().Be("en");
        svc.IsThai.Should().BeFalse();
        eventCount.Should().Be(1);

        // Setting same language again should not re-fire
        svc.SetLanguage("EN");
        eventCount.Should().Be(1);

        // Unsupported language falls back to "th" and fires
        svc.SetLanguage("fr");
        svc.CurrentLanguage.Should().Be("th");
        svc.IsThai.Should().BeTrue();
        eventCount.Should().Be(2);
    }

    [Fact]
    public void TC_I18N_05_LocalizationService_IndexerAndGet_ReturnsLocalizedAndFormattedStrings()
    {
        var svc = new LocalizationService();

        svc["Nav.Dashboard"].Should().Be("แดชบอร์ด");
        svc.Get("Home.ActiveAccounts", 5).Should().Be("5 บัญชีใช้งานอยู่");

        svc.SetLanguage("en");
        svc["Nav.Dashboard"].Should().Be("Dashboard");
        svc.Get("Home.ActiveAccounts", 5).Should().Be("5 active accounts");

        // Unknown key safely returns key name
        svc["NonExistent.Key"].Should().Be("NonExistent.Key");
    }

    [Fact]
    public async Task TC_I18N_06_LocalizationService_InitializeAndPersist_CallsNamedJsInterop()
    {
        var js = Substitute.For<IJSRuntime>();
        js.InvokeAsync<string?>("getAppLanguage", Arg.Any<object?[]?>())
            .Returns(ValueTask.FromResult<string?>("en"));

        var svc = new LocalizationService(js);
        await svc.InitializeAsync();

        svc.CurrentLanguage.Should().Be("en");

        await svc.SetLanguageAndPersistAsync("th");
        svc.CurrentLanguage.Should().Be("th");

        await js.Received(1).InvokeAsync<Microsoft.JSInterop.Infrastructure.IJSVoidResult>("setAppLanguage", Arg.Is<object?[]?>(args => args != null && args.Length == 1 && (string?)args[0] == "th"));
    }

    [Fact]
    public async Task TC_I18N_07_ServiceLayer_BilingualMessages_SupportBothThaiAndEnglish()
    {
        // 1. SshLogParser static helper
        var raw = "Accepted publickey for alice from 10.0.0.5 port 52123 ssh2";
        var thEntry = SshLogParser.Parse(raw, DateTime.UtcNow, language: AppStrings.Thai);
        var enEntry = SshLogParser.Parse(raw, DateTime.UtcNow, language: AppStrings.English);

        thEntry.SummaryMessage.Should().Contain("เข้าสู่ระบบสำเร็จ");
        enEntry.SummaryMessage.Should().Contain("Login succeeded");

        // 2. WebAdminService with Scoped ILocalizationService
        using var connection = new SqliteConnection("DataSource=:memory:");
        await connection.OpenAsync();
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(connection)
            .Options;
        await using (var dbInit = new AppDbContext(options))
        {
            await dbInit.Database.EnsureCreatedAsync();
        }
        var dbFactory = Substitute.For<IDbContextFactory<AppDbContext>>();
        dbFactory.CreateDbContextAsync(Arg.Any<CancellationToken>())
            .Returns(_ => Task.FromResult(new AppDbContext(options)));

        var auditMock = Substitute.For<IAuditService>();
        var localizer = new LocalizationService();
        localizer.SetLanguage("en");

        var adminSvc = new WebAdminService(dbFactory, auditMock, NullLogger<WebAdminService>.Instance, localizer);
        var res = await adminSvc.CreateLocalAdminAsync("ab", "Short", null, "Password123!", WebAdminRole.Operator, "admin");
        res.Success.Should().BeFalse();
        res.Message.Should().Contain("between 3 and 50 characters");
    }

    [Fact]
    public void TC_I18N_08_ArchitecturalRule_LocalizedRazorComponents_MustImplementIDisposableAndHaveNoFlagEmojis()
    {
        var root = FindProjectRoot();
        var componentsDir = Path.Combine(root, "Components");
        var razorFiles = Directory.GetFiles(componentsDir, "*.razor", SearchOption.AllDirectories);
        razorFiles.Should().NotBeEmpty();

        foreach (var file in razorFiles)
        {
            var content = File.ReadAllText(file);
            var fileName = Path.GetFileName(file);

            content.Should().NotContain("🇹🇭", $"Razor file '{fileName}' must not contain flag emojis (AGENT.md Zero Redundant Emojis rule).");
            content.Should().NotContain("🇺🇸", $"Razor file '{fileName}' must not contain flag emojis (AGENT.md Zero Redundant Emojis rule).");
            content.Should().NotContain("🇬🇧", $"Razor file '{fileName}' must not contain flag emojis (AGENT.md Zero Redundant Emojis rule).");

            if (content.Contains("OnLanguageChanged +="))
            {
                content.Should().Contain("@implements IDisposable", $"'{fileName}' subscribes to OnLanguageChanged and must implement IDisposable.");
                content.Should().Contain("OnLanguageChanged -=", $"'{fileName}' must unsubscribe OnLanguageChanged in Dispose().");
            }
        }
    }
}
