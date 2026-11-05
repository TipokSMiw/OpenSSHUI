namespace OpensshUI.Services.Security;

public interface IProtectionService
{
    string? Protect(string? clearText);
    string? Unprotect(string? cipherText);
}
