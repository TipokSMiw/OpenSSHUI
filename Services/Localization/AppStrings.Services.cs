namespace OpensshUI.Services.Localization;

public static partial class AppStrings
{
    private static void RegisterServiceLayerStrings(Dictionary<string, string> th, Dictionary<string, string> en)
    {
        // SshLogParser
        Add(th, en, "Svc.Log.AcceptedAuth", "เข้าสู่ระบบสำเร็จ ({0}) - ผู้ใช้: {1}", "Login succeeded ({0}) - User: {1}");
        Add(th, en, "Svc.Log.SessionStarted", "เริ่มเซสชัน SFTP - ผู้ใช้: {0} ({1}:{2})", "SFTP session started - User: {0} ({1}:{2})");
        Add(th, en, "Svc.Log.FailedInvalidUser", "ยืนยันตัวตนล้มเหลว (ผู้ใช้ไม่มีในระบบ: {0}) จาก {1}", "Authentication failed (invalid user: {0}) from {1}");
        Add(th, en, "Svc.Log.FailedKey", "ยืนยันตัวตนล้มเหลว (Public Key ไม่ถูกต้อง) - ผู้ใช้: {0}", "Authentication failed (invalid Public Key) - User: {0}");
        Add(th, en, "Svc.Log.FailedMethod", "ยืนยันตัวตนล้มเหลว ({0}) - ผู้ใช้: {1}", "Authentication failed ({0}) - User: {1}");
        Add(th, en, "Svc.Log.DirectInvalidUser", "ตรวจพบบัญชีผู้ใช้ไม่ถูกต้อง (Invalid User): {0} จาก {1}", "Invalid user detected: {0} from {1}");
        Add(th, en, "Svc.Log.ClosedIpOnly", "ตัดการเชื่อมต่อ - IP: {0}:{1}", "Connection closed - IP: {0}:{1}");
        Add(th, en, "Svc.Log.ClosedUser", "ตัดการเชื่อมต่อ - ผู้ใช้: {0} ({1}:{2})", "Connection closed - User: {0} ({1}:{2})");
        Add(th, en, "Svc.Log.SftpSubsystem", "เริ่มเซสชัน SFTP Subsystem", "SFTP subsystem session started");
        Add(th, en, "Svc.Log.SftpSubsystemByUser", "เริ่มเซสชัน SFTP Subsystem โดย {0}", "SFTP subsystem session started by {0}");

        // WebAdminService
        Add(th, en, "Svc.WebAdmin.InvalidUsernameLen", "ชื่อผู้ใช้ต้องมีความยาวระหว่าง 3 ถึง 50 ตัวอักษร", "Username must be between 3 and 50 characters.");
        Add(th, en, "Svc.WebAdmin.InvalidUsernameChars", "ชื่อผู้ใช้รองรับเฉพาะตัวอักษรภาษาอังกฤษ ตัวเลข และเครื่องหมาย . _ - เท่านั้น", "Username may only contain English letters, numbers, and . _ -.");
        Add(th, en, "Svc.WebAdmin.PasswordMinLen", "รหัสผ่านต้องมีความยาวอย่างน้อย 8 ตัวอักษร", "Password must be at least 8 characters long.");
        Add(th, en, "Svc.WebAdmin.DuplicateUser", "ชื่อผู้ใช้ '{0}' มีอยู่ในระบบแล้ว", "Username '{0}' already exists.");
        Add(th, en, "Svc.WebAdmin.CannotDemoteLastSuper", "ไม่สามารถลดระดับสิทธิ์ได้ เนื่องจาก '{0}' เป็น Super Admin คนสุดท้ายของระบบ", "Cannot demote '{0}' because they are the last active Super Admin.");
        Add(th, en, "Svc.WebAdmin.CannotDisableSelf", "ไม่สามารถระงับการใช้งานบัญชีของตนเองที่กำลังล็อกอินอยู่ได้", "Cannot suspend your own currently logged-in account.");
        Add(th, en, "Svc.WebAdmin.CannotDisableLastSuper", "ไม่สามารถระงับการใช้งาน Super Admin บัญชีสุดท้ายของระบบได้", "Cannot disable the last active Super Admin account.");
        Add(th, en, "Svc.WebAdmin.CannotDeleteSelf", "ไม่สามารถลบบัญชีของตนเองที่กำลังล็อกอินอยู่ได้", "Cannot delete your own currently logged-in account.");
        Add(th, en, "Svc.WebAdmin.CannotDeleteLastSuper", "ไม่สามารถลบ Super Admin บัญชีสุดท้ายของระบบได้", "Cannot delete the last active Super Admin account.");

        // LdapAuthService
        Add(th, en, "Svc.Ldap.AccountDisabled", "บัญชีผู้ดูแลระบบของคุณถูกระงับการใช้งาน (Disabled) กรุณาติดต่อ SuperAdmin", "Your administrator account is disabled. Please contact a SuperAdmin.");
        Add(th, en, "Svc.Ldap.NotEnabled", "ยังไม่ได้เปิดใช้งาน Active Directory (LDAP)", "Active Directory (LDAP) is not enabled.");
        Add(th, en, "Svc.Ldap.NoServer", "ยังไม่ได้ระบุ Server / IP ของ Domain Controller", "Domain Controller Server / IP is not configured.");
        Add(th, en, "Svc.Ldap.InvalidPort", "พอร์ตต้องอยู่ระหว่าง 1 ถึง 65535", "Port must be between 1 and 65535.");
        Add(th, en, "Svc.Ldap.SpecifyServer", "กรุณาระบุ LDAP Server", "Please specify an LDAP Server.");

        // SftpSessionService
        Add(th, en, "Svc.Session.NotFound", "ไม่พบเซสชันที่ต้องการตัดการเชื่อมต่อ", "Target session not found.");
        Add(th, en, "Svc.Session.ProcessNotFound", "ไม่พบโพรเซส PID {0} (อาจตัดการเชื่อมต่อไปแล้ว)", "Process PID {0} not found (may have already disconnected).");
        Add(th, en, "Svc.Session.NotOpenSsh", "PID {0} ({1}) ไม่ใช่โพรเซส OpenSSH (sftp-server/sshd) จึงถูกปฏิเสธการยุติโพรเซสเพื่อความปลอดภัย", "PID {0} ({1}) is not an OpenSSH process (sftp-server/sshd) and was protected from termination.");
        Add(th, en, "Svc.Session.DemoProtected", "โหมดจำลอง (Demo Mode): บัญชี '{0}' ได้รับการคุ้มกัน (Simulation)", "Demo Mode: Account '{0}' is protected (Simulation).");
    }
}
