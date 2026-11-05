using System.Runtime.Versioning;

namespace OpensshUI.Services.OpenSsh;

/// <summary>
/// Backward-compatible adapter for INativeAclProvisioner extending NtfsAclService.
/// </summary>
[SupportedOSPlatform("windows")]
public class NativeAclProvisioner : NtfsAclService
{
    public NativeAclProvisioner(ILogger<NativeAclProvisioner> logger) : base(logger)
    {
    }
}
