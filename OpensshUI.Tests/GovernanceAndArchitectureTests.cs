using System.Reflection;
using FluentAssertions;
using OpensshUI.Services.Auth;
using OpensshUI.Services.OpenSsh;
using OpensshUI.Services.Security;
using Xunit;

namespace OpensshUI.Tests;

/// <summary>
/// Architecture & Governance Gatekeeper Tests (Automated Verification of AGENT.md Commandments).
/// Ensures that future code changes and AI refactoring do not accidentally regress security standards.
/// </summary>
public class GovernanceAndArchitectureTests
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
    public void AGENT_MD_MustContain_AllEightSecurityCommandments()
    {
        var root = FindProjectRoot();
        var agentMdPath = Path.Combine(root, "AGENT.md");
        File.Exists(agentMdPath).Should().BeTrue();

        var text = File.ReadAllText(agentMdPath);

        // Verify Commandments C1 through C8 are permanently present
        text.Should().Contain("[C1] Canonical Username Everywhere");
        text.Should().Contain("[C2] Full-Spectrum Safe Custom Path");
        text.Should().Contain("[C3] RFC 4251 Wire-Format Verification");
        text.Should().Contain("[C4] DirectChroot Preservation");
        text.Should().Contain("[C5] Atomic sshd_config Pipeline");
        text.Should().Contain("[C6] Junction Detach Safety Before Recursive Delete");
        text.Should().Contain("[C7] Bounded In-Memory State & Auto-Pruning");
        text.Should().Contain("[C8] Least Privilege AD Fallback Guard");

        // Verify Anti-Regression Matrix and Checklist
        text.Should().Contain("Anti-Regression Matrix");
        text.Should().Contain("Pre-Commit Quality & Security Gate");
        text.Should().Contain("Zero Dead Code & Stream Draining Discipline");
        text.Should().Contain("[Check 5] Zero Dead Code & Ghost Injections");
        text.Should().Contain("[Check 6] 100% Service Contract Test Coverage");
        text.Should().Contain("[Check 7] Test Suite 100% Pass");
    }

    [Fact]
    public void ArchitecturalRule_SshKeyConverter_MustNeverAllowWeakCiphers()
    {
        // Enforce Commandment C3 / OWASP A02: ssh-dss must never be allowed in ValidKeyTypes
        var field = typeof(SshKeyConverter).GetField("ValidKeyTypes", BindingFlags.Public | BindingFlags.Static);
        field.Should().NotBeNull();

        var validTypes = (string[])field!.GetValue(null)!;
        validTypes.Should().NotContain("ssh-dss", "ssh-dss (DSA 1024-bit) algorithm is cryptographically weak and must remain strictly disabled.");
        validTypes.Should().Contain(new[] { "ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256" });
    }

    [Fact]
    public void ArchitecturalRule_InMemoryCaches_MustHaveBoundedCapacityConstants()
    {
        // Enforce Commandment C7 / AGENT.md §3.6.4: Bounded memory state with max capacity
        var ldapMaxField = typeof(LdapAuthService).GetField("MaxTrackedLoginUsers", BindingFlags.NonPublic | BindingFlags.Static);
        ldapMaxField.Should().NotBeNull();
        var ldapMax = (int)ldapMaxField!.GetValue(null)!;
        ldapMax.Should().BeGreaterThan(0).And.BeLessThanOrEqualTo(1000);

        var sessionMaxField = typeof(UserSessionState).GetField("MaxTrackedStateEntries", BindingFlags.NonPublic | BindingFlags.Static);
        sessionMaxField.Should().NotBeNull();
        var sessionMax = (int)sessionMaxField!.GetValue(null)!;
        sessionMax.Should().BeGreaterThan(0).And.BeLessThanOrEqualTo(1000);
    }

    [Fact]
    public void ArchitecturalRule_SecurityValidator_MustExportCanonicalAndSafePathMethods()
    {
        // Enforce Commandments C1 and C2: Canonical username and safe path validation
        var extractMethod = typeof(SecurityValidator).GetMethod("ExtractCanonicalUsername", BindingFlags.Public | BindingFlags.Static);
        extractMethod.Should().NotBeNull();

        var safePathMethod = typeof(SecurityValidator).GetMethod("ValidateSafeCustomPath", BindingFlags.Public | BindingFlags.Static, null, new[] { typeof(string), typeof(string) }, null);
        safePathMethod.Should().NotBeNull();
    }

    [Fact]
    public void ArchitecturalRule_RazorPages_MustNotDirectlyInvokeForbiddenSystemApis()
    {
        // Enforce AGENT.md §2 Architectural Rule 2 (UI Decoupling):
        // Razor pages in Components/Pages must not directly call Process.Start or raw System.IO mutating APIs
        var root = FindProjectRoot();
        var pagesDir = Path.Combine(root, "Components", "Pages");

        var razorFiles = Directory.GetFiles(pagesDir, "*.razor", SearchOption.AllDirectories);
        razorFiles.Length.Should().BeGreaterThan(0);

        foreach (var file in razorFiles)
        {
            var content = File.ReadAllText(file);
            var fileName = Path.GetFileName(file);

            content.Should().NotContain("Process.Start(", $"Razor Component '{fileName}' must not start OS processes directly. Delegate to Service Layer.");
            content.Should().NotContain("File.WriteAllText(", $"Razor Component '{fileName}' must not write files directly. Delegate to Service Layer.");
            content.Should().NotContain("Directory.Delete(", $"Razor Component '{fileName}' must not delete directories directly. Delegate to Service Layer.");
        }
    }

    [Fact]
    public void ArchitecturalRule_EditorConfigAndRoslynAnalyzers_MustBeEnforced()
    {
        var root = FindProjectRoot();
        var editorConfigPath = Path.Combine(root, ".editorconfig");
        File.Exists(editorConfigPath).Should().BeTrue(".editorconfig must exist in root to enforce Roslyn AST analyzers.");

        var editorConfigText = File.ReadAllText(editorConfigPath);
        editorConfigText.Should().Contain("dotnet_diagnostic.IDE0051.severity = warning");
        editorConfigText.Should().Contain("dotnet_diagnostic.IDE0059.severity = warning");
        editorConfigText.Should().Contain("dotnet_diagnostic.IDE0005.severity = warning");
        editorConfigText.Should().Contain("dotnet_diagnostic.CS0168.severity = warning");
        editorConfigText.Should().Contain("dotnet_diagnostic.CS1998.severity = warning");

        var csprojPath = Path.Combine(root, "OpensshUI.csproj");
        var csprojText = File.ReadAllText(csprojPath);
        csprojText.Should().Contain("<EnforceCodeStyleInBuild>true</EnforceCodeStyleInBuild>");
        csprojText.Should().Contain("<GenerateDocumentationFile>true</GenerateDocumentationFile>");
    }
}
