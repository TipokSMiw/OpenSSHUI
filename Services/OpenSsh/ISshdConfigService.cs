namespace OpensshUI.Services.OpenSsh;

public class SshdDirective
{
    public string Key { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
    public string RawLine { get; set; } = string.Empty;
}

public class SshdMatchBlock
{
    public string MatchType { get; set; } = string.Empty; // "User", "Group", etc.
    public string Pattern { get; set; } = string.Empty;   // e.g. "deployuser", "SFTP-Users"
    public List<string> Comments { get; set; } = new();
    public List<SshdDirective> Directives { get; set; } = new();
    public bool IsManaged { get; set; }
}

public class SshdConfigFile
{
    public List<string> GlobalLines { get; set; } = new();
    public List<SshdMatchBlock> MatchBlocks { get; set; } = new();
}

public interface ISshdConfigService
{
    string ConfigPath { get; }
    string FindSshdExecutable();
    SshdConfigFile Parse(string configContent);
    string Serialize(SshdConfigFile configFile);
    ConfigValidationResult ValidateSyntax(string configFilePath);
    ConfigValidationResult ValidateSyntaxContent(string configContent);
    Task<(bool Success, string Message)> AtomicWriteAndApplyAsync(string newContent, string? targetPath = null);
    Task<(bool Success, string Message)> SyncManagedBlocksAsync(IEnumerable<DirectChrootRule> rules, string sftpRoot, string keysPath, string? targetPath = null);
    List<string> GetBackupFiles(int maxBackups = 5);
}
