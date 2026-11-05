namespace OpensshUI.Models;

public class SshPublicKey
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string KeyType { get; set; } = string.Empty; // e.g. ssh-rsa, ssh-ed25519, ecdsa-sha2-nistp256
    public string FingerprintSha256 { get; set; } = string.Empty;
    public string RawPublicKey { get; set; } = string.Empty;
    public string? Comment { get; set; }
    public DateTime AddedAt { get; set; } = DateTime.UtcNow;

    public SftpUser? User { get; set; }
}
