namespace OpensshUI.Models;

public class LdapConfig
{
    public int Id { get; set; } = 1;
    public string Server { get; set; } = "127.0.0.1";
    public int Port { get; set; } = 389;
    public bool UseSsl { get; set; } = false;
    public bool TrustSslCertificates { get; set; } = true;
    public string Domain { get; set; } = "domain.local";
    public string BaseDn { get; set; } = "DC=domain,DC=local";
    public string? EncryptedBindDn { get; set; }
    public string? EncryptedBindPassword { get; set; }
    public string AdminGroup { get; set; } = "SFTP-Admins";
    public bool IsLdapEnabled { get; set; } = false;

    // Fallback Local Administrator for emergency login
    public string FallbackAdminUsername { get; set; } = "admin";
    public string FallbackAdminPasswordHash { get; set; } = string.Empty;
}
