namespace OpensshUI.Models;

public enum SshTimePreset
{
    Last1Hour,
    Today,
    Last7Days,
    Custom
}

public class SshLogFilter
{
    public SshTimePreset TimePreset { get; set; } = SshTimePreset.Today;
    public DateTime? FromDate { get; set; }
    public DateTime? ToDate { get; set; }
    public SshEventType? Category { get; set; }
    public string? Keyword { get; set; }
    public int MaxRecords { get; set; } = 100;
}
