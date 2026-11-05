using Microsoft.AspNetCore.DataProtection;

namespace OpensshUI.Services.Security;

public class ProtectionService : IProtectionService
{
    private readonly IDataProtector _protector;

    public ProtectionService(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("OpensshUI.CredentialsProtector.v1");
    }

    public string? Protect(string? clearText)
    {
        if (string.IsNullOrEmpty(clearText)) return clearText;
        return _protector.Protect(clearText);
    }

    public string? Unprotect(string? cipherText)
    {
        if (string.IsNullOrEmpty(cipherText)) return cipherText;
        try
        {
            return _protector.Unprotect(cipherText);
        }
        catch
        {
            return null;
        }
    }
}
