using System.Diagnostics;
using System.Runtime.Versioning;
using OpensshUI.Services.Security;

namespace OpensshUI.Services.OpenSsh;

[SupportedOSPlatform("windows")]
public class SshKeyGenerator : ISshKeyGenerator
{
    private readonly ILogger<SshKeyGenerator> _logger;
    private readonly string _sshKeygenPath;

    public SshKeyGenerator(ILogger<SshKeyGenerator> logger)
    {
        _logger = logger;

        // OpenSSH ssh-keygen location on Windows: usually %SystemRoot%\System32\OpenSSH\ssh-keygen.exe
        var systemPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "OpenSSH", "ssh-keygen.exe");
        _sshKeygenPath = File.Exists(systemPath) ? systemPath : "ssh-keygen.exe";
    }

    public async Task<SshKeyGenerateResult> GenerateKeyPairAsync(string keyType, string? comment = null, string? passphrase = null)
    {
        var normalizedType = (keyType ?? "ed25519").Trim().ToLowerInvariant();
        if (normalizedType.StartsWith("ssh-"))
        {
            normalizedType = normalizedType.Substring(4);
        }

        if (normalizedType != "ed25519" && normalizedType != "rsa")
        {
            return new SshKeyGenerateResult
            {
                Success = false,
                ErrorMessage = $"Unsupported key algorithm '{keyType}'. Supported algorithms are 'ed25519' and 'rsa'."
            };
        }

        var (okPassphrase, passphraseErr) = SecurityValidator.ValidateSshPassphrase(passphrase);
        if (!okPassphrase)
        {
            return new SshKeyGenerateResult
            {
                Success = false,
                ErrorMessage = passphraseErr
            };
        }

        var cleanComment = string.IsNullOrWhiteSpace(comment)
            ? $"automation-{DateTime.UtcNow:yyyyMMdd}"
            : SecurityValidator.SanitizeSingleLine(comment.Trim());

        // Create temporary isolated directory with a unique GUID
        var tempDir = Path.Combine(Path.GetTempPath(), "opensshui_gen_" + Guid.NewGuid().ToString("N"));
        var keyFilePath = Path.Combine(tempDir, "id_automation");
        var pubFilePath = keyFilePath + ".pub";

        try
        {
            Directory.CreateDirectory(tempDir);

            var psi = new ProcessStartInfo
            {
                FileName = _sshKeygenPath,
                WorkingDirectory = tempDir,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            psi.ArgumentList.Add("-q");
            psi.ArgumentList.Add("-t");
            psi.ArgumentList.Add(normalizedType);

            if (normalizedType == "rsa")
            {
                psi.ArgumentList.Add("-b");
                psi.ArgumentList.Add("4096");
            }

            psi.ArgumentList.Add("-C");
            psi.ArgumentList.Add(cleanComment);

            psi.ArgumentList.Add("-N");
            psi.ArgumentList.Add(passphrase ?? string.Empty);

            psi.ArgumentList.Add("-f");
            psi.ArgumentList.Add(keyFilePath);

            using var proc = new Process { StartInfo = psi };
            proc.Start();

            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();

            var completed = await Task.Run(() => proc.WaitForExit(15000));
            if (!completed)
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                _logger.LogWarning("ssh-keygen timed out while generating {KeyType} key.", normalizedType);
                return new SshKeyGenerateResult
                {
                    Success = false,
                    ErrorMessage = "Key generation process timed out."
                };
            }

            _ = await stdoutTask;
            var stderr = await stderrTask;

            // In Windows OpenSSH, saving public key to certain user profile/temp locations can report 'eother'
            // even though the private key was successfully generated with valid entropy.
            // Check if private key was generated.
            if (!File.Exists(keyFilePath) || new FileInfo(keyFilePath).Length == 0)
            {
                _logger.LogError("ssh-keygen failed with exit code {ExitCode}: {Stderr}", proc.ExitCode, stderr);
                return new SshKeyGenerateResult
                {
                    Success = false,
                    ErrorMessage = string.IsNullOrWhiteSpace(stderr) ? "ssh-keygen failed to generate private key file." : stderr.Trim()
                };
            }

            var privateKeyPem = await File.ReadAllTextAsync(keyFilePath);

            string? publicKeyContent = null;
            if (File.Exists(pubFilePath) && new FileInfo(pubFilePath).Length > 0)
            {
                publicKeyContent = await File.ReadAllTextAsync(pubFilePath);
            }
            else
            {
                // Robust extraction directly from the generated private key using ssh-keygen -y
                publicKeyContent = await ExtractPublicKeyFromPrivateKeyAsync(keyFilePath, passphrase);
            }

            if (string.IsNullOrWhiteSpace(publicKeyContent))
            {
                return new SshKeyGenerateResult
                {
                    Success = false,
                    ErrorMessage = string.IsNullOrWhiteSpace(stderr) ? "Failed to extract public key from generated key pair." : stderr.Trim()
                };
            }

            var parse = SshKeyConverter.ParseAndNormalizeKey(publicKeyContent);
            if (!parse.IsSuccess)
            {
                return new SshKeyGenerateResult
                {
                    Success = false,
                    ErrorMessage = parse.ErrorMessage ?? "Failed to parse generated public key."
                };
            }

            var finalComment = string.IsNullOrWhiteSpace(cleanComment) ? parse.Comment : cleanComment;
            var parts = parse.RawPublicKey.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var normalizedPublicKey = parts.Length >= 2
                ? $"{parts[0]} {parts[1]}" + (string.IsNullOrWhiteSpace(finalComment) ? "" : $" {finalComment}")
                : parse.RawPublicKey;

            return new SshKeyGenerateResult
            {
                Success = true,
                KeyType = parse.KeyType,
                PublicKeyOpenSsh = normalizedPublicKey,
                PrivateKeyPem = privateKeyPem.Trim(),
                FingerprintSha256 = parse.FingerprintSha256,
                Comment = finalComment ?? string.Empty
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error generating SSH key pair of type {KeyType}", normalizedType);
            return new SshKeyGenerateResult
            {
                Success = false,
                ErrorMessage = $"Error generating SSH key: {ex.Message}"
            };
        }
        finally
        {
            // Immediate security cleanup: wipe and remove temporary files and directory
            try
            {
                if (File.Exists(keyFilePath)) File.Delete(keyFilePath);
                if (File.Exists(pubFilePath)) File.Delete(pubFilePath);
                if (Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not delete temporary key generation folder {TempDir}", tempDir);
            }
        }
    }

    private async Task<string?> ExtractPublicKeyFromPrivateKeyAsync(string keyFilePath, string? passphrase)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = _sshKeygenPath,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            psi.ArgumentList.Add("-y");
            psi.ArgumentList.Add("-P");
            psi.ArgumentList.Add(passphrase ?? string.Empty);
            psi.ArgumentList.Add("-f");
            psi.ArgumentList.Add(keyFilePath);

            using var proc = new Process { StartInfo = psi };
            proc.Start();

            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var completed = await Task.Run(() => proc.WaitForExit(5000));
            if (!completed)
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                return null;
            }

            var stdout = await stdoutTask;
            if (proc.ExitCode == 0 && !string.IsNullOrWhiteSpace(stdout))
            {
                return stdout.Trim();
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to extract public key via ssh-keygen -y");
        }

        return null;
    }
}
