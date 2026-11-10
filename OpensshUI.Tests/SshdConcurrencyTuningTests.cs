using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using NSubstitute;
using OpensshUI.Models;
using OpensshUI.Services.OpenSsh;
using Xunit;

namespace OpensshUI.Tests;

public class SshdConcurrencyTuningTests
{
    private readonly ILogger<SshdConfigService> _logger = Substitute.For<ILogger<SshdConfigService>>();
    private readonly IConfiguration _config;
    private readonly SshdConfigService _sut;

    public SshdConcurrencyTuningTests()
    {
        var inMemory = new Dictionary<string, string?>
        {
            ["SftpSettings:SshdConfigPath"] = @"C:\dummy\sshd_config"
        };
        _config = new ConfigurationBuilder().AddInMemoryCollection(inMemory).Build();
        _sut = new SshdConfigService(_logger, _config);
    }

    [Fact]
    public void GetConcurrencySettings_WhenFileDoesNotExist_ReturnsStandardDefaults()
    {
        // Act: Non-existent path
        var settings = _sut.GetConcurrencySettings(@"C:\non_existent_path\sshd_config");

        // Assert
        settings.Should().NotBeNull();
        settings.MaxStartups.Should().Be("10:30:100");
        settings.MaxSessions.Should().Be(10);
        settings.ClientAliveInterval.Should().Be(0);
        settings.ClientAliveCountMax.Should().Be(3);
        settings.LoginGraceTime.Should().Be(120);
        settings.AppliedProfile.Should().Be("Default");
    }

    [Fact]
    public void GetConcurrencySettings_WhenFileContainsDirectives_ParsesCorrectly()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        try
        {
            var sampleContent = @"
# Global section
Port 22
MaxStartups 100:30:300
MaxSessions 30
ClientAliveInterval 30
ClientAliveCountMax 3
LoginGraceTime 30

Match Group SFTP-Users
    ChrootDirectory C:\SFTPRoot\%u
    ForceCommand internal-sftp
";
            File.WriteAllText(tempFile, sampleContent);

            // Act
            var settings = _sut.GetConcurrencySettings(tempFile);

            // Assert
            settings.MaxStartups.Should().Be("100:30:300");
            settings.MaxSessions.Should().Be(30);
            settings.ClientAliveInterval.Should().Be(30);
            settings.ClientAliveCountMax.Should().Be(3);
            settings.LoginGraceTime.Should().Be(30);
            settings.AppliedProfile.Should().Be("HighTraffic");
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    [Fact]
    public void Parse_GlobalDirectives_IncludesMaxStartupsInGlobalLines()
    {
        // Arrange
        var sampleContent = @"
Port 22
MaxStartups 50:30:200

Match User deployer
    ForceCommand internal-sftp
";

        // Act
        var parsed = _sut.Parse(sampleContent);

        // Assert
        parsed.GlobalLines.Should().Contain(l => l.Contains("MaxStartups 50:30:200"));
        parsed.MatchBlocks.Should().HaveCount(1);
        parsed.MatchBlocks[0].Directives.Should().NotContain(d => d.Key == "MaxStartups");
    }

    [Fact]
    public async Task UpdateConcurrencySettingsAsync_WritesInGlobalSection_WithoutBleedingIntoMatchBlocks()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        try
        {
            var initialContent = @"
Port 22
Subsystem sftp internal-sftp

Match Group Developers
    ChrootDirectory C:\DevRoot
    ForceCommand internal-sftp
";
            File.WriteAllText(tempFile, initialContent);

            var newSettings = new SshdConcurrencySettings
            {
                MaxStartups = "100:30:300",
                MaxSessions = 25,
                ClientAliveInterval = 30,
                ClientAliveCountMax = 3,
                LoginGraceTime = 45,
                AppliedProfile = "HighTraffic"
            };

            // Act
            // Note: In unit test environment, sshd.exe might not exist in Windows candidate paths,
            // but AtomicWriteAndApplyCoreAsync writes the file safely
            var (ok, msg) = await _sut.UpdateConcurrencySettingsAsync(newSettings, tempFile);

            // Assert
            ok.Should().BeTrue(msg);
            var updatedContent = File.ReadAllText(tempFile);
            var reParsed = _sut.Parse(updatedContent);

            // Verify GlobalLines has the directives
            reParsed.GlobalLines.Should().Contain(l => l.Contains("MaxStartups 100:30:300"));
            reParsed.GlobalLines.Should().Contain(l => l.Contains("MaxSessions 25"));
            reParsed.GlobalLines.Should().Contain(l => l.Contains("ClientAliveInterval 30"));
            reParsed.GlobalLines.Should().Contain(l => l.Contains("LoginGraceTime 45"));

            // Verify Match block is untouched and has NO concurrency directives
            reParsed.MatchBlocks.Should().HaveCount(1);
            var devBlock = reParsed.MatchBlocks[0];
            devBlock.Pattern.Should().Be("Developers");
            devBlock.Directives.Should().NotContain(d => d.Key == "MaxStartups");
            devBlock.Directives.Should().NotContain(d => d.Key == "MaxSessions");
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
            // Clean up any test backups
            var dir = Path.GetDirectoryName(tempFile);
            var fileName = Path.GetFileName(tempFile);
            if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
            {
                foreach (var b in Directory.GetFiles(dir, $"{fileName}.bak_*"))
                {
                    try { File.Delete(b); } catch { }
                }
            }
        }
    }
}
