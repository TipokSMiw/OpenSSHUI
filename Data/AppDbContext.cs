using Microsoft.EntityFrameworkCore;
using OpensshUI.Models;

namespace OpensshUI.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }

    public DbSet<SftpUser> SftpUsers => Set<SftpUser>();
    public DbSet<SshPublicKey> SshPublicKeys => Set<SshPublicKey>();
    public DbSet<SftpGroup> SftpGroups => Set<SftpGroup>();
    public DbSet<SftpUserGroup> SftpUserGroups => Set<SftpUserGroup>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<LdapConfig> LdapConfigs => Set<LdapConfig>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<SftpUser>(entity =>
        {
            entity.HasKey(e => e.Username);
            entity.Property(e => e.Username).HasMaxLength(100);
            entity.Property(e => e.DisplayName).HasMaxLength(200);
            entity.Property(e => e.HomeDirectory).HasMaxLength(500);
            entity.Property(e => e.CustomRootPath).HasMaxLength(500);

            entity.HasMany(e => e.PublicKeys)
                  .WithOne(e => e.User)
                  .HasForeignKey(e => e.Username)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<SftpGroup>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasMaxLength(50);
            entity.Property(e => e.Name).HasMaxLength(100);
            entity.Property(e => e.Description).HasMaxLength(500);
            entity.Property(e => e.RootPath).HasMaxLength(500);
            entity.HasIndex(e => e.Name).IsUnique();
        });

        modelBuilder.Entity<SftpUserGroup>(entity =>
        {
            entity.HasKey(e => new { e.Username, e.GroupId });

            entity.HasOne(e => e.User)
                  .WithMany(u => u.UserGroups)
                  .HasForeignKey(e => e.Username)
                  .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(e => e.Group)
                  .WithMany(g => g.Members)
                  .HasForeignKey(e => e.GroupId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<SshPublicKey>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Username).HasMaxLength(100);
            entity.Property(e => e.KeyType).HasMaxLength(50);
            entity.Property(e => e.FingerprintSha256).HasMaxLength(150);
            entity.Property(e => e.Comment).HasMaxLength(255);
            entity.HasIndex(e => e.Username);
        });

        modelBuilder.Entity<AuditLog>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Action).HasMaxLength(100);
            entity.Property(e => e.Operator).HasMaxLength(100);
            entity.Property(e => e.ClientIp).HasMaxLength(50);
            entity.HasIndex(e => e.Timestamp);
        });

        modelBuilder.Entity<LdapConfig>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Server).HasMaxLength(255);
            entity.Property(e => e.Domain).HasMaxLength(255);
            entity.Property(e => e.BaseDn).HasMaxLength(255);
            entity.Property(e => e.AdminGroup).HasMaxLength(255);
        });
    }

    /// <summary>
    /// Ensures SQLite tables and columns for Groups and User custom paths exist even if DB was created previously.
    /// </summary>
    public async Task ApplyCustomMigrationsAsync()
    {
        if (!Database.IsSqlite()) return;

        // 1. Create SftpGroups table if not exists
        await Database.ExecuteSqlRawAsync(@"
            CREATE TABLE IF NOT EXISTS ""SftpGroups"" (
                ""Id"" TEXT NOT NULL CONSTRAINT ""PK_SftpGroups"" PRIMARY KEY,
                ""Name"" TEXT NOT NULL,
                ""Description"" TEXT NULL,
                ""RootPath"" TEXT NOT NULL,
                ""PermissionType"" INTEGER NOT NULL DEFAULT 0,
                ""AccessMode"" INTEGER NOT NULL DEFAULT 0,
                ""CreatedAt"" TEXT NOT NULL
            );
        ");

        await Database.ExecuteSqlRawAsync(@"
            CREATE UNIQUE INDEX IF NOT EXISTS ""IX_SftpGroups_Name"" ON ""SftpGroups"" (""Name"");
        ");

        // 2. Create SftpUserGroups table if not exists
        await Database.ExecuteSqlRawAsync(@"
            CREATE TABLE IF NOT EXISTS ""SftpUserGroups"" (
                ""Username"" TEXT NOT NULL,
                ""GroupId"" TEXT NOT NULL,
                ""JoinedAt"" TEXT NOT NULL,
                CONSTRAINT ""PK_SftpUserGroups"" PRIMARY KEY (""Username"", ""GroupId""),
                CONSTRAINT ""FK_SftpUserGroups_SftpUsers_Username"" FOREIGN KEY (""Username"") REFERENCES ""SftpUsers"" (""Username"") ON DELETE CASCADE,
                CONSTRAINT ""FK_SftpUserGroups_SftpGroups_GroupId"" FOREIGN KEY (""GroupId"" ) REFERENCES ""SftpGroups"" (""Id"") ON DELETE CASCADE
            );
        ");

        // 3. Add columns to SftpUsers if missing
        await AddColumnIfNotExistsAsync("SftpUsers", "CustomRootPath", "TEXT NULL");
        await AddColumnIfNotExistsAsync("SftpUsers", "CustomPermissionType", "INTEGER NOT NULL DEFAULT 0");
        await AddColumnIfNotExistsAsync("SftpUsers", "AccessMode", "INTEGER NOT NULL DEFAULT 0");

        // Add columns to LdapConfigs if missing
        await AddColumnIfNotExistsAsync("LdapConfigs", "TrustSslCertificates", "INTEGER NOT NULL DEFAULT 1");

        // 4. Performance Indexes on SshPublicKeys, AuditLogs, and SftpUserGroups
        await Database.ExecuteSqlRawAsync(@"
            CREATE INDEX IF NOT EXISTS ""IX_SshPublicKeys_Username"" ON ""SshPublicKeys"" (""Username"");
        ");
        await Database.ExecuteSqlRawAsync(@"
            CREATE INDEX IF NOT EXISTS ""IX_AuditLogs_Timestamp"" ON ""AuditLogs"" (""Timestamp"");
        ");
        await Database.ExecuteSqlRawAsync(@"
            CREATE INDEX IF NOT EXISTS ""IX_SftpUserGroups_GroupId"" ON ""SftpUserGroups"" (""GroupId"");
        ");
    }

    private async Task AddColumnIfNotExistsAsync(string tableName, string columnName, string columnDefinition)
    {
        try
        {
            var conn = Database.GetDbConnection();
            if (conn.State != System.Data.ConnectionState.Open)
            {
                await conn.OpenAsync();
            }

            bool found = false;
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = $"PRAGMA table_info(\"{tableName}\");";
                using var reader = await cmd.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    var name = reader["name"]?.ToString();
                    if (string.Equals(name, columnName, StringComparison.OrdinalIgnoreCase))
                    {
                        found = true;
                        break;
                    }
                }
            }

            if (!found)
            {
                using var alterCmd = conn.CreateCommand();
                alterCmd.CommandText = $"ALTER TABLE \"{tableName}\" ADD COLUMN \"{columnName}\" {columnDefinition};";
                await alterCmd.ExecuteNonQueryAsync();
            }
        }
        catch
        {
            // Ignore if column already exists or table structure error
        }
    }
}
