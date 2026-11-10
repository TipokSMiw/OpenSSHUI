using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using OpensshUI.Components;
using OpensshUI.Data;
using OpensshUI.Services.Audit;
using OpensshUI.Services.Auth;
using OpensshUI.Services.Files;
using OpensshUI.Services.Groups;
using OpensshUI.Services.OpenSsh;
using OpensshUI.Services.Security;
using OpensshUI.Services.Users;

var builder = WebApplication.CreateBuilder(args);

// Add Razor Components & Interactive Server Mode
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Data Protection for credential encryption (DPAPI-protected on Windows)
var keysDir = Path.Combine(builder.Environment.ContentRootPath, "app_data", "dp_keys");
Directory.CreateDirectory(keysDir);
var dpBuilder = builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(keysDir))
    .SetApplicationName("OpensshUI");

if (OperatingSystem.IsWindows())
{
    dpBuilder.ProtectKeysWithDpapi(protectToLocalMachine: true);
}

// Database: SQLite with DbContextFactory
var dbDir = Path.Combine(builder.Environment.ContentRootPath, "app_data");
Directory.CreateDirectory(dbDir);
var rawConnectionString = builder.Configuration.GetConnectionString("DefaultConnection") 
    ?? $"Data Source={Path.Combine(dbDir, "sftp_admin.db")}";

var sqliteBuilder = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder(rawConnectionString);
if (sqliteBuilder.DefaultTimeout == 0)
{
    sqliteBuilder.DefaultTimeout = 5; // 5-second busy timeout for concurrent Blazor/Audit operations
}
var connectionString = sqliteBuilder.ToString();

builder.Services.AddDbContextFactory<AppDbContext>(options =>
    options.UseSqlite(connectionString));

// Application Services
builder.Services.AddSingleton<IProtectionService, ProtectionService>();
builder.Services.AddScoped<IAuditService, AuditService>();
builder.Services.AddScoped<ILdapAuthService, LdapAuthService>();
builder.Services.AddScoped<IWebAdminService, WebAdminService>();
builder.Services.AddScoped<UserSessionState>();

// OpenSSH & Windows Host Services
builder.Services.AddSingleton<ISshdConfigService, SshdConfigService>();
builder.Services.AddSingleton<INtfsAclService, NtfsAclService>();
builder.Services.AddSingleton<INativeAclProvisioner, NtfsAclService>();
builder.Services.AddSingleton<IWindowsUserManager, WindowsUserManager>();
builder.Services.AddSingleton<IOpenSshServiceManager, OpenSshServiceManager>();
builder.Services.AddSingleton<ISshEventLogService, SshEventLogService>();
builder.Services.AddSingleton<IOpenSshLogService, SshEventLogService>();
builder.Services.AddSingleton<ISftpSessionService, SftpSessionService>();
builder.Services.AddSingleton<ISshKeyGenerator, SshKeyGenerator>();
builder.Services.AddSingleton<ISecureFileBrowserService, SecureFileBrowserService>(sp =>
{
    var logger = sp.GetRequiredService<ILogger<SecureFileBrowserService>>();
    var dbFactory = sp.GetRequiredService<IDbContextFactory<AppDbContext>>();
    var sshService = sp.GetRequiredService<IOpenSshServiceManager>();
    var root = builder.Configuration["SftpSettings:SftpRoot"] ?? @"C:\SFTPRoot";
    return new SecureFileBrowserService(logger, root, dbFactory, sshService);
});
builder.Services.AddScoped<ISftpGroupService, SftpGroupService>();
builder.Services.AddScoped<ISftpUserService, SftpUserService>();

var app = builder.Build();

// Auto-create database & tables on startup
using (var scope = app.Services.CreateScope())
{
    var dbFactory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>();
    using var db = dbFactory.CreateDbContext();
    db.Database.EnsureCreated();
    await db.ApplyCustomMigrationsAsync();

    // Enable WAL mode & normal synchronous for concurrency & performance
    if (db.Database.IsSqlite())
    {
        await db.Database.ExecuteSqlRawAsync("PRAGMA journal_mode = WAL;");
        await db.Database.ExecuteSqlRawAsync("PRAGMA synchronous = NORMAL;");
    }

    // Ensure default LDAP / Fallback Admin configuration exists
    var ldapService = scope.ServiceProvider.GetRequiredService<ILdapAuthService>();
    await ldapService.GetConfigAsync();
}

// HTTP request pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

// Configurable HTTPS redirection
if (app.Configuration.GetValue<bool>("SecuritySettings:RequireHttps"))
{
    app.UseHttpsRedirection();
}

// HTTP Security Headers (OWASP A05:2021 Security Misconfiguration Defense)
app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    context.Response.Headers.Append("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    context.Response.Headers.Append("Content-Security-Policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net data:; img-src 'self' data:; script-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; frame-ancestors 'none';");
    await next();
});

app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
