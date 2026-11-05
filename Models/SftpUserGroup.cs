namespace OpensshUI.Models;

public class SftpUserGroup
{
    public string Username { get; set; } = string.Empty;
    public SftpUser? User { get; set; }

    public string GroupId { get; set; } = string.Empty;
    public SftpGroup? Group { get; set; }

    public DateTime JoinedAt { get; set; } = DateTime.UtcNow;
}
