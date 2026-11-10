using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using OpensshUI.Services.Security;

namespace OpensshUI.Services.OpenSsh;

public class SshKeyParseResult
{
    public bool IsSuccess { get; set; }
    public string? ErrorMessage { get; set; }
    public string KeyType { get; set; } = string.Empty;
    public string RawPublicKey { get; set; } = string.Empty; // Single-line OpenSSH format
    public string FingerprintSha256 { get; set; } = string.Empty;
    public string? Comment { get; set; }
}

public static class SshKeyConverter
{
    private const int MaxKeyInputLength = 16384;

    public static readonly string[] ValidKeyTypes = {
        "ssh-rsa",
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521"
    };

    public static SshKeyParseResult ParseAndNormalizeKey(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return new SshKeyParseResult { IsSuccess = false, ErrorMessage = "SSH Key content cannot be empty." };
        }

        if (input.Length > MaxKeyInputLength)
        {
            return new SshKeyParseResult { IsSuccess = false, ErrorMessage = "SSH Key content exceeds maximum allowed length (16 KB)." };
        }

        var trimmed = input.Trim();

        // 1. Check if PuTTY / RFC 4716 format
        if (trimmed.Contains("BEGIN SSH2 PUBLIC KEY"))
        {
            return ParseRfc4716PuTTY(trimmed);
        }

        // 2. Check if OpenSSH format (single line or multi-line pasted with trailing comments)
        var lines = trimmed.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2)
            {
                var type = parts[0].ToLowerInvariant();
                if (ValidKeyTypes.Contains(type))
                {
                    var base64 = parts[1];
                    var rawComment = parts.Length > 2 ? string.Join(" ", parts.Skip(2)) : null;
                    var cleanComment = string.IsNullOrWhiteSpace(rawComment) ? null : SecurityValidator.SanitizeSingleLine(rawComment);

                    try
                    {
                        var keyBytes = Convert.FromBase64String(base64);
                        if (keyBytes.Length < 16)
                        {
                            return new SshKeyParseResult
                            {
                                IsSuccess = false,
                                ErrorMessage = "Invalid OpenSSH public key: binary payload is too short or truncated."
                            };
                        }

                        var wireKeyType = ExtractKeyTypeFromBytes(keyBytes);
                        if (string.IsNullOrEmpty(wireKeyType) || !string.Equals(wireKeyType, type, StringComparison.OrdinalIgnoreCase))
                        {
                            return new SshKeyParseResult
                            {
                                IsSuccess = false,
                                ErrorMessage = $"SSH key binary header ('{wireKeyType}') does not match declared key type ('{type}')."
                            };
                        }

                        var fingerprint = ComputeSha256Fingerprint(keyBytes);

                        var rawKey = $"{type} {base64}" + (string.IsNullOrWhiteSpace(cleanComment) ? "" : $" {cleanComment}");
                        // Final safety check: ensure strictly single line
                        rawKey = SecurityValidator.SanitizeSingleLine(rawKey);

                        return new SshKeyParseResult
                        {
                            IsSuccess = true,
                            KeyType = type,
                            RawPublicKey = rawKey,
                            FingerprintSha256 = fingerprint,
                            Comment = cleanComment
                        };
                    }
                    catch (FormatException)
                    {
                        return new SshKeyParseResult { IsSuccess = false, ErrorMessage = "Invalid Base64 payload in OpenSSH key." };
                    }
                }
            }
        }

        return new SshKeyParseResult
        {
            IsSuccess = false,
            ErrorMessage = "Unrecognized key format or unsupported key type (ssh-dss is disabled). Please provide a standard OpenSSH key (RSA, ED25519, ECDSA) or PuTTY RFC 4716 public key."
        };
    }

    private static string ExtractKeyTypeFromBytes(byte[] keyBytes)
    {
        // RFC 4251: string is uint32 (big-endian length) followed by ASCII bytes
        if (keyBytes.Length > 4)
        {
            int len = (keyBytes[0] << 24) | (keyBytes[1] << 16) | (keyBytes[2] << 8) | keyBytes[3];
            if (len > 0 && len <= 64 && len + 4 <= keyBytes.Length)
            {
                return Encoding.ASCII.GetString(keyBytes, 4, len).ToLowerInvariant();
            }
        }

        return string.Empty;
    }

    private static SshKeyParseResult ParseRfc4716PuTTY(string content)
    {
        try
        {
            var lines = content.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            var sbBase64 = new StringBuilder();
            string? comment = null;
            bool inKey = false;

            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (trimmed.StartsWith("---- BEGIN SSH2 PUBLIC KEY ----"))
                {
                    inKey = true;
                    continue;
                }
                if (trimmed.StartsWith("---- END SSH2 PUBLIC KEY ----"))
                {
                    break;
                }
                if (!inKey) continue;

                if (trimmed.StartsWith("Comment:", StringComparison.OrdinalIgnoreCase))
                {
                    comment = trimmed.Substring(8).Trim().Trim('"');
                    continue;
                }

                // Ignore other headers like Subject: etc.
                if (trimmed.Contains(':') && !trimmed.Contains('/'))
                {
                    continue;
                }

                sbBase64.Append(trimmed);
            }

            var fullBase64 = sbBase64.ToString().Replace(" ", "").Replace("\t", "");
            var keyBytes = Convert.FromBase64String(fullBase64);

            // Extract the key type from the first binary string in keyBytes
            string keyType = ExtractKeyTypeFromBytes(keyBytes);

            if (string.IsNullOrEmpty(keyType) || !ValidKeyTypes.Contains(keyType) || keyBytes.Length < 16)
            {
                return new SshKeyParseResult
                {
                    IsSuccess = false,
                    ErrorMessage = "Unsupported or invalid SSH key type inside RFC 4716 public key payload."
                };
            }

            var fingerprint = ComputeSha256Fingerprint(keyBytes);
            var safeComment = string.IsNullOrWhiteSpace(comment) ? "converted-from-putty" : SecurityValidator.SanitizeSingleLine(comment);
            var openSshKey = SecurityValidator.SanitizeSingleLine($"{keyType} {fullBase64} {safeComment}");

            return new SshKeyParseResult
            {
                IsSuccess = true,
                KeyType = keyType,
                RawPublicKey = openSshKey,
                FingerprintSha256 = fingerprint,
                Comment = safeComment
            };
        }
        catch (Exception ex)
        {
            return new SshKeyParseResult
            {
                IsSuccess = false,
                ErrorMessage = $"Failed to parse PuTTY RFC 4716 public key: {ex.Message}"
            };
        }
    }

    private static string ComputeSha256Fingerprint(byte[] keyBytes)
    {
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(keyBytes);
        var base64Hash = Convert.ToBase64String(hash).TrimEnd('=');
        return $"SHA256:{base64Hash}";
    }
}
