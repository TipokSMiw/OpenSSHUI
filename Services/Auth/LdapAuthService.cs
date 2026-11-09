using System.Collections.Concurrent;
using System.DirectoryServices.Protocols;
using System.Net;
using Microsoft.EntityFrameworkCore;
using OpensshUI.Data;
using OpensshUI.Models;
using OpensshUI.Services.Security;

namespace OpensshUI.Services.Auth;

public class LdapAuthService : ILdapAuthService
{
    private const int MaxFailedAttempts = 5;
    private const int MaxTrackedLoginUsers = 1000;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(5);
    private static readonly ConcurrentDictionary<string, (int FailedCount, DateTime? LockoutUntilUtc, DateTime LastAttemptUtc)> LoginAttempts = new(StringComparer.OrdinalIgnoreCase);

    private readonly IDbContextFactory<AppDbContext> _dbFactory;
    private readonly IProtectionService _protectionService;
    private readonly ILogger<LdapAuthService> _logger;

    public LdapAuthService(
        IDbContextFactory<AppDbContext> dbFactory,
        IProtectionService protectionService,
        ILogger<LdapAuthService> logger)
    {
        _dbFactory = dbFactory;
        _protectionService = protectionService;
        _logger = logger;
    }

    public static void ResetLockoutForUser(string username)
    {
        if (!string.IsNullOrWhiteSpace(username))
        {
            LoginAttempts.TryRemove(username.Trim(), out _);
        }
    }

    public static int GetTrackedAttemptCount() => LoginAttempts.Count;

    public static void ClearAllLoginAttempts() => LoginAttempts.Clear();

    public static void RecordFailedAttemptForTesting(string username, DateTime? simulatedTimeUtc = null)
    {
        RecordFailedAttemptCore(username, simulatedTimeUtc ?? DateTime.UtcNow);
    }

    private string? UnprotectOrFallback(string? value)
    {
        if (string.IsNullOrEmpty(value)) return value;
        return _protectionService.Unprotect(value) ?? value;
    }

    public async Task<LdapConfig> GetConfigAsync()
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var config = await db.LdapConfigs.OrderBy(c => c.Id).FirstOrDefaultAsync();
        if (config == null)
        {
            config = new LdapConfig
            {
                Id = 1,
                Server = "127.0.0.1",
                Port = 389,
                UseSsl = false,
                TrustSslCertificates = true,
                Domain = "corp.local",
                BaseDn = "DC=corp,DC=local",
                AdminGroup = "SFTP-Admins",
                FallbackAdminUsername = "admin",
                FallbackAdminPasswordHash = PasswordHasher.HashPassword("Admin@123456") // default fallback
            };
            db.LdapConfigs.Add(config);
            await db.SaveChangesAsync();
        }
        else if (!string.IsNullOrEmpty(config.EncryptedBindDn))
        {
            config.EncryptedBindDn = UnprotectOrFallback(config.EncryptedBindDn);
        }
        return config;
    }

    public async Task SaveConfigAsync(LdapConfig config, string? newBindPassword = null, string? newFallbackAdminPassword = null)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var existing = await db.LdapConfigs.FirstOrDefaultAsync(c => c.Id == config.Id);
        if (existing == null)
        {
            existing = config;
            if (!string.IsNullOrEmpty(existing.EncryptedBindDn))
            {
                var plainDn = UnprotectOrFallback(existing.EncryptedBindDn);
                existing.EncryptedBindDn = _protectionService.Protect(plainDn);
            }
            db.LdapConfigs.Add(existing);
        }
        else
        {
            existing.Server = config.Server;
            existing.Port = config.Port;
            existing.UseSsl = config.UseSsl;
            existing.TrustSslCertificates = config.TrustSslCertificates;
            existing.Domain = config.Domain;
            existing.BaseDn = config.BaseDn;
            existing.AdminGroup = config.AdminGroup;
            existing.IsLdapEnabled = config.IsLdapEnabled;
            existing.FallbackAdminUsername = config.FallbackAdminUsername;
            if (!string.IsNullOrEmpty(config.EncryptedBindDn))
            {
                var plainDn = UnprotectOrFallback(config.EncryptedBindDn);
                existing.EncryptedBindDn = _protectionService.Protect(plainDn);
            }
            else
            {
                existing.EncryptedBindDn = null;
            }
        }

        if (!string.IsNullOrEmpty(newBindPassword))
        {
            existing.EncryptedBindPassword = _protectionService.Protect(newBindPassword);
        }

        if (!string.IsNullOrEmpty(newFallbackAdminPassword))
        {
            existing.FallbackAdminPasswordHash = PasswordHasher.HashPassword(newFallbackAdminPassword);
        }

        await db.SaveChangesAsync();
    }

    private static bool IsLockedOut(string username, out TimeSpan remaining)
    {
        remaining = TimeSpan.Zero;
        if (LoginAttempts.TryGetValue(username, out var state) && state.LockoutUntilUtc.HasValue)
        {
            var now = DateTime.UtcNow;
            if (state.LockoutUntilUtc.Value > now)
            {
                remaining = state.LockoutUntilUtc.Value - now;
                return true;
            }
            LoginAttempts.TryRemove(username, out _);
        }
        return false;
    }

    private static void RecordFailedAttempt(string username)
    {
        RecordFailedAttemptCore(username, DateTime.UtcNow);
    }

    private static void RecordFailedAttemptCore(string username, DateTime nowUtc)
    {
        if (LoginAttempts.Count >= MaxTrackedLoginUsers)
        {
            PruneExpiredAttempts(nowUtc);
        }

        LoginAttempts.AddOrUpdate(
            username,
            _ => (1, null, nowUtc),
            (_, current) =>
            {
                int nextCount = current.FailedCount + 1;
                DateTime? lockoutUntil = nextCount >= MaxFailedAttempts
                    ? nowUtc.Add(LockoutDuration)
                    : current.LockoutUntilUtc;
                return (nextCount, lockoutUntil, nowUtc);
            });
    }

    private static void PruneExpiredAttempts(DateTime nowUtc)
    {
        var expirationCutoff = nowUtc - LockoutDuration;
        foreach (var kvp in LoginAttempts)
        {
            var isExpiredLockout = kvp.Value.LockoutUntilUtc.HasValue && kvp.Value.LockoutUntilUtc.Value <= nowUtc;
            var isStaleAttempt = !kvp.Value.LockoutUntilUtc.HasValue && kvp.Value.LastAttemptUtc <= expirationCutoff;
            if (isExpiredLockout || isStaleAttempt)
            {
                LoginAttempts.TryRemove(kvp.Key, out _);
            }
        }

        // Hard cap safeguard if still above MaxTrackedLoginUsers during an active flood
        if (LoginAttempts.Count >= MaxTrackedLoginUsers)
        {
            var oldestNonLocked = LoginAttempts
                .Where(kvp => !kvp.Value.LockoutUntilUtc.HasValue || kvp.Value.LockoutUntilUtc.Value <= nowUtc)
                .OrderBy(kvp => kvp.Value.LastAttemptUtc)
                .Take(MaxTrackedLoginUsers / 4)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var key in oldestNonLocked)
            {
                LoginAttempts.TryRemove(key, out _);
            }
        }
    }

    public async Task<AuthResult> AuthenticateAsync(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            return new AuthResult
            {
                IsSuccess = false,
                ErrorMessage = "Username and password are required."
            };
        }

        var cleanUsername = username.Trim();

        // Brute-force lockout check
        if (IsLockedOut(cleanUsername, out var remaining))
        {
            _logger.LogWarning("Rejected login attempt for locked-out user {User}. Remaining lockout: {Seconds}s", cleanUsername, (int)remaining.TotalSeconds);
            return new AuthResult
            {
                IsSuccess = false,
                ErrorMessage = $"Too many failed login attempts. Account is temporarily locked for {Math.Max(1, (int)Math.Ceiling(remaining.TotalMinutes))} minute(s)."
            };
        }

        var config = await GetConfigAsync();

        // 1. Check if user is registered in WebAdminUsers table
        await using (var db = await _dbFactory.CreateDbContextAsync())
        {
            var adminRecord = await db.WebAdminUsers.FirstOrDefaultAsync(u => u.Username.ToLower() == cleanUsername.ToLower());
            if (adminRecord != null)
            {
                if (!adminRecord.IsActive)
                {
                    _logger.LogWarning("Login attempt for deactivated web admin {User}", cleanUsername);
                    return new AuthResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "บัญชีผู้ดูแลระบบนี้ถูกระงับการใช้งาน กรุณาติดต่อ Super Administrator"
                    };
                }

                if (adminRecord.AccountType == WebAdminType.Local)
                {
                    if (!string.IsNullOrEmpty(adminRecord.PasswordHash) && PasswordHasher.VerifyPassword(password, adminRecord.PasswordHash))
                    {
                        ResetLockoutForUser(cleanUsername);
                        adminRecord.LastLoginAt = DateTime.UtcNow;
                        await db.SaveChangesAsync();

                        return new AuthResult
                        {
                            IsSuccess = true,
                            Username = adminRecord.Username,
                            DisplayName = adminRecord.DisplayName,
                            IsAdmin = true,
                            Role = adminRecord.Role
                        };
                    }

                    RecordFailedAttempt(cleanUsername);
                    return new AuthResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"
                    };
                }
                else if (adminRecord.AccountType == WebAdminType.ActiveDirectory)
                {
                    if (!config.IsLdapEnabled)
                    {
                        return new AuthResult
                        {
                            IsSuccess = false,
                            ErrorMessage = "Active Directory ถูกปิดใช้งานในระบบ จึงไม่สามารถเข้าสู่ระบบด้วยบัญชีโดเมนได้"
                        };
                    }

                    var adAuth = await Task.Run(() => PerformLdapAuth(config, cleanUsername, password, checkAdminGroup: false));
                    if (adAuth.IsSuccess)
                    {
                        ResetLockoutForUser(cleanUsername);
                        adminRecord.LastLoginAt = DateTime.UtcNow;
                        await db.SaveChangesAsync();

                        return new AuthResult
                        {
                            IsSuccess = true,
                            Username = adminRecord.Username,
                            DisplayName = string.IsNullOrEmpty(adminRecord.DisplayName) ? cleanUsername : adminRecord.DisplayName,
                            IsAdmin = true,
                            Role = adminRecord.Role
                        };
                    }

                    RecordFailedAttempt(cleanUsername);
                    return adAuth;
                }
            }
        }

        // 2. Fallback Local Admin Login (Disaster recovery / backward compatibility)
        if (string.Equals(cleanUsername, config.FallbackAdminUsername, StringComparison.OrdinalIgnoreCase))
        {
            if (PasswordHasher.VerifyPassword(password, config.FallbackAdminPasswordHash))
            {
                ResetLockoutForUser(cleanUsername);
                return new AuthResult
                {
                    IsSuccess = true,
                    Username = config.FallbackAdminUsername,
                    DisplayName = "Local Administrator",
                    IsAdmin = true,
                    Role = WebAdminRole.SuperAdmin
                };
            }

            if (!config.IsLdapEnabled)
            {
                RecordFailedAttempt(cleanUsername);
                return new AuthResult
                {
                    IsSuccess = false,
                    ErrorMessage = "Invalid administrator credentials."
                };
            }
        }

        // 3. Fallback Active Directory Group Membership
        if (!config.IsLdapEnabled)
        {
            RecordFailedAttempt(cleanUsername);
            return new AuthResult
            {
                IsSuccess = false,
                ErrorMessage = "Active Directory authentication is currently disabled and credentials do not match local administrator."
            };
        }

        return await Task.Run(() =>
        {
            var res = PerformLdapAuth(config, cleanUsername, password, checkAdminGroup: true);
            if (!res.IsSuccess)
            {
                RecordFailedAttempt(cleanUsername);
            }
            else
            {
                ResetLockoutForUser(cleanUsername);
            }
            return res;
        });
    }

    private AuthResult PerformLdapAuth(LdapConfig config, string cleanUsername, string password, bool checkAdminGroup)
    {
        try
        {
            var userDn = cleanUsername.Contains('@') ? cleanUsername : $"{cleanUsername}@{config.Domain}";
            using var connection = CreateLdapConnection(config);

            var credential = new NetworkCredential(userDn, password);
            connection.Bind(credential); // Throws if invalid password

            // Check if user is in admin group
            bool isAdmin = !checkAdminGroup || string.IsNullOrWhiteSpace(config.AdminGroup);
            if (!isAdmin)
            {
                isAdmin = CheckUserGroupMembership(connection, config, cleanUsername);
            }

            if (!isAdmin)
            {
                return new AuthResult
                {
                    IsSuccess = false,
                    Username = cleanUsername,
                    DisplayName = cleanUsername,
                    IsAdmin = false,
                    ErrorMessage = "User authenticated but does not belong to the authorized Admin group."
                };
            }

            return new AuthResult
            {
                IsSuccess = true,
                Username = cleanUsername,
                DisplayName = cleanUsername,
                IsAdmin = true,
                Role = WebAdminRole.SuperAdmin
            };
        }
        catch (LdapException lex)
        {
            _logger.LogWarning(lex, "LDAP authentication failed for user {User}", cleanUsername);
            return new AuthResult { IsSuccess = false, ErrorMessage = $"LDAP Error ({lex.ErrorCode}): {lex.Message}" };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error authenticating user {User}", cleanUsername);
            return new AuthResult { IsSuccess = false, ErrorMessage = ex.Message };
        }
    }

    private LdapConnection CreateLdapConnection(LdapConfig config)
    {
        var identifier = new LdapDirectoryIdentifier(config.Server.Trim(), config.Port);
        var connection = new LdapConnection(identifier)
        {
            Timeout = TimeSpan.FromSeconds(8)
        };

        connection.SessionOptions.ProtocolVersion = 3;

        if (config.UseSsl)
        {
            connection.SessionOptions.SecureSocketLayer = true;
            if (config.TrustSslCertificates)
            {
                connection.SessionOptions.VerifyServerCertificate = (conn, cert) => true;
            }
            connection.AuthType = AuthType.Basic;
        }
        else
        {
            // For Windows Active Directory on cleartext port 389, Negotiate (NTLM/Kerberos) is required
            connection.AuthType = AuthType.Negotiate;
        }

        return connection;
    }

    public async Task<LdapConnectionTestResult> TestConnectionAsync(LdapConfig config, string? plainBindPassword = null)
    {
        var result = new LdapConnectionTestResult();

        if (string.IsNullOrWhiteSpace(config.Server))
        {
            result.Success = false;
            result.Message = "กรุณาระบุ LDAP Server / Host";
            return result;
        }

        if (config.Port <= 0 || config.Port > 65535)
        {
            result.Success = false;
            result.Message = "พอร์ตต้องอยู่ระหว่าง 1 ถึง 65535";
            return result;
        }

        return await Task.Run(() =>
        {
            // Step 1: TCP Socket Ping (Network Reachability)
            try
            {
                using var tcp = new System.Net.Sockets.TcpClient();
                var connectTask = tcp.ConnectAsync(config.Server.Trim(), config.Port);
                bool connected = connectTask.Wait(TimeSpan.FromSeconds(3));
                if (connected && tcp.Connected)
                {
                    result.HostReachable = true;
                    result.Details.Add($"เชื่อมต่อเครือข่ายไปยัง '{config.Server}:{config.Port}' สำเร็จ (TCP Open)");
                }
                else
                {
                    result.HostReachable = false;
                    result.Message = $"ไม่สามารถเชื่อมต่อไปยัง Host '{config.Server}:{config.Port}' ได้ (Connection Timeout หรือ Host ไม่ตอบสนอง)";
                    result.Details.Add($"ตรวจสอบว่า Host '{config.Server}' เปิดใช้งานและ Firewall อนุญาตพอร์ต {config.Port}");
                    return result;
                }
            }
            catch (Exception ex)
            {
                result.HostReachable = false;
                result.Message = $"ไม่สามารถเชื่อมต่อระดับเครือข่ายไปยัง '{config.Server}:{config.Port}': {ex.Message}";
                result.Details.Add($"TCP Connection Error: {ex.Message}");
                return result;
            }

            // Step 2: LDAP Protocol Connection & Bind
            string? bindUser = UnprotectOrFallback(config.EncryptedBindDn);
            string? bindPass = plainBindPassword;
            if (string.IsNullOrEmpty(bindPass) && !string.IsNullOrEmpty(config.EncryptedBindPassword))
            {
                bindPass = _protectionService.Unprotect(config.EncryptedBindPassword);
            }

            LdapConnection? connection = null;
            try
            {
                connection = CreateLdapConnection(config);

                if (!string.IsNullOrEmpty(bindUser) && !string.IsNullOrEmpty(bindPass))
                {
                    var cred = new NetworkCredential(bindUser, bindPass);
                    connection.Bind(cred);
                    result.BindSuccessful = true;
                    result.Details.Add($"ยืนยันสิทธิ์บัญชี Bind สำเร็จ: '{bindUser}'");
                }
                else
                {
                    connection.Bind();
                    result.BindSuccessful = true;
                    result.Details.Add("เชื่อมต่อ LDAP สำเร็จ (Anonymous / Unauthenticated)");
                }
            }
            catch (LdapException lex)
            {
                result.BindSuccessful = false;
                result.Message = $"การยืนยันสิทธิ์ LDAP ผิดพลาด ({lex.ErrorCode}): {lex.Message}";
                result.Details.Add($"รหัสข้อผิดพลาด LDAP {lex.ErrorCode}: {lex.Message}");
                if (string.IsNullOrEmpty(bindUser))
                {
                    result.Details.Add("คำแนะนำ: Active Directory ส่วนใหญ่ไม่อนุญาต Anonymous Bind กรุณาระบุ Admin Bind Account และ Password");
                }
                return result;
            }
            catch (Exception ex)
            {
                result.BindSuccessful = false;
                result.Message = $"การยืนยันสิทธิ์ LDAP ผิดพลาด: {ex.Message}";
                result.Details.Add(ex.Message);
                return result;
            }

            using (connection)
            {
                // Step 3: Base DN Verification (if provided)
                if (!string.IsNullOrWhiteSpace(config.BaseDn))
                {
                    try
                    {
                        var baseReq = new SearchRequest(
                            config.BaseDn.Trim(),
                            "(objectClass=*)",
                            SearchScope.Base,
                            "namingContexts", "subschemaSubentry");
                        var baseResp = (SearchResponse)connection.SendRequest(baseReq);
                        result.BaseDnVerified = baseResp.Entries.Count > 0;
                        if (result.BaseDnVerified.Value)
                        {
                            result.Details.Add($"ตรวจพบ Base DN: '{config.BaseDn}' ถูกต้องในไดเรกทอรี");
                        }
                    }
                    catch (Exception ex)
                    {
                        result.BaseDnVerified = false;
                        result.Details.Add($"ไม่พบ Base DN '{config.BaseDn}': {ex.Message}");
                    }
                }

                // Step 4: Admin Group Verification (if provided and Base DN valid)
                if (!string.IsNullOrWhiteSpace(config.AdminGroup) && result.BaseDnVerified != false && !string.IsNullOrWhiteSpace(config.BaseDn))
                {
                    try
                    {
                        var targetGroup = SecurityValidator.EscapeLdapFilter(config.AdminGroup.Trim());
                        var grpReq = new SearchRequest(
                            config.BaseDn.Trim(),
                            $"(&(objectCategory=group)(|(cn={targetGroup})(sAMAccountName={targetGroup})))",
                            SearchScope.Subtree,
                            "cn", "distinguishedName");
                        var grpResp = (SearchResponse)connection.SendRequest(grpReq);
                        result.AdminGroupVerified = grpResp.Entries.Count > 0;
                        if (result.AdminGroupVerified.Value)
                        {
                            var grpDn = grpResp.Entries[0].DistinguishedName;
                            result.Details.Add($"พบกลุ่ม Admin Group '{config.AdminGroup}' ใน AD: {grpDn}");
                        }
                        else
                        {
                            result.Details.Add($"คำเตือน: ไม่พบกลุ่ม '{config.AdminGroup}' ภายใต้ Base DN (โปรดตรวจสอบชื่อกลุ่มใน AD)");
                        }
                    }
                    catch (Exception ex)
                    {
                        result.AdminGroupVerified = false;
                        result.Details.Add($"ตรวจสอบกลุ่ม '{config.AdminGroup}' ไม่สำเร็จ: {ex.Message}");
                    }
                }

                result.Success = result.HostReachable && result.BindSuccessful && (result.BaseDnVerified != false);
                if (result.Success)
                {
                    if (result.AdminGroupVerified == false)
                    {
                        result.Message = "เชื่อมต่อและยืนยันสิทธิ์ LDAP สำเร็จ แต่ไม่พบกลุ่ม Admin Group ใน AD ตามที่ระบุ";
                    }
                    else
                    {
                        result.Message = "เชื่อมต่อและตรวจสอบการตั้งค่า Active Directory / LDAP สำเร็จครบถ้วน";
                    }
                }

                return result;
            }
        });
    }

    public async Task<AdSearchResult> SearchAdUsersAsync(string query)
    {
        var config = await GetConfigAsync();

        if (!config.IsLdapEnabled)
        {
            return new AdSearchResult
            {
                Success = false,
                Message = "Active Directory (LDAP) ยังไม่ได้เปิดใช้งานในระบบ กรุณาเปิดใช้งานและตั้งค่าการเชื่อมต่อที่เมนู 'ตั้งค่าระบบ'"
            };
        }

        if (string.IsNullOrWhiteSpace(config.Server))
        {
            return new AdSearchResult
            {
                Success = false,
                Message = "ยังไม่ได้ระบุ Server / Domain Controller ในการตั้งค่า LDAP"
            };
        }

        return await Task.Run(() =>
        {
            var results = new List<AdUserInfo>();
            try
            {
                using var connection = CreateLdapConnection(config);

                var bindPass = _protectionService.Unprotect(config.EncryptedBindPassword);
                if (!string.IsNullOrEmpty(config.EncryptedBindDn) && !string.IsNullOrEmpty(bindPass))
                {
                    connection.Bind(new NetworkCredential(config.EncryptedBindDn, bindPass));
                }
                else
                {
                    connection.Bind();
                }

                var safeQuery = SecurityValidator.EscapeLdapFilter((query ?? "").Trim());
                var filter = string.IsNullOrWhiteSpace(safeQuery)
                    ? "(&(objectCategory=person)(objectClass=user))"
                    : $"(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=*{safeQuery}*)(displayName=*{safeQuery}*)))";

                var searchRequest = new SearchRequest(
                    config.BaseDn,
                    filter,
                    SearchScope.Subtree,
                    "sAMAccountName", "displayName", "mail")
                {
                    SizeLimit = 50
                };

                var response = (SearchResponse)connection.SendRequest(searchRequest);
                foreach (SearchResultEntry entry in response.Entries)
                {
                    var sam = entry.Attributes["sAMAccountName"]?[0]?.ToString() ?? "";
                    var display = entry.Attributes["displayName"]?[0]?.ToString() ?? sam;
                    var mail = entry.Attributes["mail"]?[0]?.ToString() ?? "";

                    if (!string.IsNullOrEmpty(sam))
                    {
                        results.Add(new AdUserInfo
                        {
                            SamAccountName = sam,
                            DisplayName = display,
                            Email = mail
                        });
                    }
                }

                return new AdSearchResult
                {
                    Success = true,
                    Message = results.Count > 0 ? $"พบผู้ใช้งาน {results.Count} รายการ" : "ไม่พบบัญชีผู้ใช้ใน Active Directory ที่ตรงกับเงื่อนไข",
                    Users = results
                };
            }
            catch (LdapException lex)
            {
                _logger.LogError(lex, "Failed to search AD users due to LDAP error {Code}", lex.ErrorCode);
                return new AdSearchResult
                {
                    Success = false,
                    Message = $"เกิดข้อผิดพลาดในการเชื่อมต่อ LDAP ({lex.ErrorCode}): {lex.Message}"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to search AD users.");
                return new AdSearchResult
                {
                    Success = false,
                    Message = $"ไม่สามารถค้นหาผู้ใช้จาก Active Directory ได้: {ex.Message}"
                };
            }
        });
    }

    public async Task<bool> IsUsingDefaultFallbackPasswordAsync()
    {
        var config = await GetConfigAsync();
        return PasswordHasher.VerifyPassword("Admin@123456", config.FallbackAdminPasswordHash);
    }

    private bool CheckUserGroupMembership(LdapConnection connection, LdapConfig config, string username)
    {
        try
        {
            var safeUsername = SecurityValidator.EscapeLdapFilter(username);
            var filter = $"(&(objectCategory=person)(objectClass=user)(sAMAccountName={safeUsername}))";
            var request = new SearchRequest(config.BaseDn, filter, SearchScope.Subtree, "memberOf");
            var response = (SearchResponse)connection.SendRequest(request);

            if (response.Entries.Count == 0) return false;
            var entry = response.Entries[0];
            var memberOf = entry.Attributes["memberOf"];
            if (memberOf == null) return false;

            var targetGroup = config.AdminGroup.Trim();
            for (int i = 0; i < memberOf.Count; i++)
            {
                var groupDn = (memberOf[i]?.ToString() ?? "").Trim();
                if (groupDn.Equals(targetGroup, StringComparison.OrdinalIgnoreCase) ||
                    groupDn.StartsWith($"CN={targetGroup},", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not determine group membership for {User}", username);
            return false;
        }
    }
}
