namespace OpensshUI.Services.OpenSsh;

public class SshKeyGenerateResult
{
    public bool Success { get; set; }
    public string? ErrorMessage { get; set; }
    public string KeyType { get; set; } = string.Empty; // e.g. ssh-ed25519, ssh-rsa
    public string PublicKeyOpenSsh { get; set; } = string.Empty;
    public string PrivateKeyPem { get; set; } = string.Empty;
    public string FingerprintSha256 { get; set; } = string.Empty;
    public string Comment { get; set; } = string.Empty;
}

public interface ISshKeyGenerator
{
    Task<SshKeyGenerateResult> GenerateKeyPairAsync(string keyType, string? comment = null, string? passphrase = null);
}
