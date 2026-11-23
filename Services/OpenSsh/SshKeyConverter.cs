using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
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

                        var (isMaterialValid, materialError) = ValidateWireKeyMaterial(type, keyBytes);
                        if (!isMaterialValid)
                        {
                            return new SshKeyParseResult
                            {
                                IsSuccess = false,
                                ErrorMessage = materialError ?? "Invalid or weak SSH public key material."
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

    private static bool TryReadRfc4251Field(ReadOnlySpan<byte> data, ref int offset, out ReadOnlySpan<byte> value)
    {
        value = default;
        if (offset < 0 || data.Length - offset < 4)
        {
            return false;
        }

        uint len = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(offset, 4));
        offset += 4;

        if (len > (uint)(data.Length - offset))
        {
            return false;
        }

        value = data.Slice(offset, (int)len);
        offset += (int)len;
        return true;
    }

    private static (bool IsValid, string? ErrorMessage) ValidateWireKeyMaterial(string expectedKeyType, byte[] keyBytes)
    {
        var span = keyBytes.AsSpan();
        int offset = 0;

        if (!TryReadRfc4251Field(span, ref offset, out var wireTypeBytes))
        {
            return (false, "Malformed RFC 4251 SSH public key header.");
        }

        var wireType = Encoding.ASCII.GetString(wireTypeBytes).ToLowerInvariant();
        if (!string.Equals(wireType, expectedKeyType, StringComparison.OrdinalIgnoreCase))
        {
            return (false, $"SSH key binary header ('{wireType}') does not match declared key type ('{expectedKeyType}').");
        }

        switch (wireType)
        {
            case "ssh-ed25519":
                if (!TryReadRfc4251Field(span, ref offset, out var edPub) || edPub.Length != 32)
                {
                    return (false, "Invalid Ed25519 SSH key: public key payload must be exactly 32 bytes.");
                }
                return (true, null);

            case "ssh-rsa":
                if (!TryReadRfc4251Field(span, ref offset, out var rsaExp) || rsaExp.Length < 1 ||
                    !TryReadRfc4251Field(span, ref offset, out var rsaMod) || rsaMod.Length < 1)
                {
                    return (false, "Malformed RSA SSH public key payload.");
                }

                // Strip leading 0x00 sign bytes from mpint modulus before computing key bit length
                int nonZeroIdx = 0;
                while (nonZeroIdx < rsaMod.Length && rsaMod[nonZeroIdx] == 0)
                {
                    nonZeroIdx++;
                }

                var significantMod = rsaMod.Slice(nonZeroIdx);
                if (significantMod.Length == 0)
                {
                    return (false, "Invalid RSA SSH public key: modulus is zero.");
                }

                int modBits = (significantMod.Length - 1) * 8 + BitOperations.Log2(significantMod[0]) + 1;
                if (modBits < 2048)
                {
                    return (false, $"RSA key strength ({modBits}-bit) is below the minimum 2048-bit security requirement.");
                }
                return (true, null);

            case "ecdsa-sha2-nistp256":
            case "ecdsa-sha2-nistp384":
            case "ecdsa-sha2-nistp521":
                if (!TryReadRfc4251Field(span, ref offset, out var curveBytes) ||
                    !TryReadRfc4251Field(span, ref offset, out var ecPoint) || ecPoint.Length < 33)
                {
                    return (false, "Malformed ECDSA SSH public key payload.");
                }

                var curveName = Encoding.ASCII.GetString(curveBytes).ToLowerInvariant();
                var expectedCurve = wireType.Substring("ecdsa-sha2-".Length);
                if (!string.Equals(curveName, expectedCurve, StringComparison.OrdinalIgnoreCase))
                {
                    return (false, $"ECDSA curve identifier ('{curveName}') does not match '{expectedCurve}'.");
                }
                return (true, null);

            default:
                return (false, "Unsupported SSH key type.");
        }
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

            var (isMaterialValid, materialError) = ValidateWireKeyMaterial(keyType, keyBytes);
            if (!isMaterialValid)
            {
                return new SshKeyParseResult
                {
                    IsSuccess = false,
                    ErrorMessage = materialError ?? "Invalid or weak SSH key material inside RFC 4716 public key payload."
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
