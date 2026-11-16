using System.Collections.Frozen;

namespace OpensshUI.Services.Localization;

/// <summary>
/// Static immutable Thai/English (th/en) translation catalog.
/// Organized into partial files by feature area for maintainability.
/// </summary>
public static partial class AppStrings
{
    public const string Thai = "th";
    public const string English = "en";
    public const string DefaultLanguage = Thai;

    private static readonly FrozenDictionary<string, string> ThStrings;
    private static readonly FrozenDictionary<string, string> EnStrings;

    static AppStrings()
    {
        var th = new Dictionary<string, string>(StringComparer.Ordinal);
        var en = new Dictionary<string, string>(StringComparer.Ordinal);

        RegisterCoreAndLayoutStrings(th, en);
        RegisterHomeAndServiceStrings(th, en);
        RegisterUsersAndGroupsStrings(th, en);
        RegisterLogsAndAdminStrings(th, en);
        RegisterServiceLayerStrings(th, en);

        ThStrings = th.ToFrozenDictionary(StringComparer.Ordinal);
        EnStrings = en.ToFrozenDictionary(StringComparer.Ordinal);
    }

    public static string NormalizeLanguage(string? languageCode)
    {
        if (string.Equals(languageCode?.Trim(), English, StringComparison.OrdinalIgnoreCase))
        {
            return English;
        }

        return Thai;
    }

    public static string Get(string key, string? languageCode = null)
    {
        var lang = NormalizeLanguage(languageCode);
        var dict = lang == English ? EnStrings : ThStrings;
        return dict.TryGetValue(key, out var value) ? value : key;
    }

    public static string Format(string key, string? languageCode, params object[] args)
    {
        var template = Get(key, languageCode);
        if (args.Length == 0)
        {
            return template;
        }

        try
        {
            return string.Format(template, args);
        }
        catch (FormatException)
        {
            return template;
        }
    }

    public static IReadOnlyCollection<string> GetAllKeys(string languageCode)
    {
        var lang = NormalizeLanguage(languageCode);
        return lang == English ? EnStrings.Keys : ThStrings.Keys;
    }

    private static void Add(Dictionary<string, string> th, Dictionary<string, string> en, string key, string thValue, string enValue)
    {
        th[key] = thValue;
        en[key] = enValue;
    }

    private static void RegisterCoreAndLayoutStrings(Dictionary<string, string> th, Dictionary<string, string> en)
    {
        // Common
        Add(th, en, "Common.Save", "บันทึก", "Save");
        Add(th, en, "Common.Saving", "กำลังบันทึก...", "Saving...");
        Add(th, en, "Common.Cancel", "ยกเลิก", "Cancel");
        Add(th, en, "Common.Close", "ปิด", "Close");
        Add(th, en, "Common.Delete", "ลบ", "Delete");
        Add(th, en, "Common.Edit", "แก้ไข", "Edit");
        Add(th, en, "Common.Refresh", "รีเฟรช", "Refresh");
        Add(th, en, "Common.Search", "ค้นหา", "Search");
        Add(th, en, "Common.Loading", "กำลังโหลดข้อมูล...", "Loading...");
        Add(th, en, "Common.Active", "ใช้งานอยู่", "Active");
        Add(th, en, "Common.Inactive", "ระงับการใช้งาน", "Inactive");
        Add(th, en, "Common.Enabled", "เปิดใช้งาน", "Enabled");
        Add(th, en, "Common.Disabled", "ปิดใช้งาน", "Disabled");
        Add(th, en, "Common.Yes", "ใช่", "Yes");
        Add(th, en, "Common.No", "ไม่", "No");
        Add(th, en, "Common.Confirm", "ยืนยัน", "Confirm");
        Add(th, en, "Common.Actions", "จัดการ", "Actions");
        Add(th, en, "Common.Status", "สถานะ", "Status");
        Add(th, en, "Common.ShowPassword", "แสดงรหัสผ่าน", "Show password");
        Add(th, en, "Common.HidePassword", "ซ่อนรหัสผ่าน", "Hide password");
        Add(th, en, "Common.ReadOnly", "อ่านอย่างเดียว", "Read-Only");
        Add(th, en, "Common.ErrorPrefix", "ข้อผิดพลาด: {0}", "Error: {0}");
        Add(th, en, "Common.All", "ทั้งหมด", "All");
        Add(th, en, "Common.Copy", "คัดลอก", "Copy");
        Add(th, en, "Common.Copied", "คัดลอกแล้ว", "Copied");

        // Layout & Login
        Add(th, en, "Layout.BrandSubtitle", "ระบบบริหารจัดการ SFTP และ Windows Host", "SFTP & Windows Host Administration");
        Add(th, en, "Layout.SecurityNotice", "ระบบมีสิทธิ์ระดับระบบปฏิบัติการ กรุณายืนยันตัวตนก่อนเข้าใช้งาน", "OS-level privileges required. Please authenticate to continue.");
        Add(th, en, "Layout.Username", "Username", "Username");
        Add(th, en, "Layout.UsernamePlaceholder", "admin หรือ domain\\user", "admin or domain\\user");
        Add(th, en, "Layout.Password", "Password", "Password");
        Add(th, en, "Layout.TogglePassword", "แสดง/ซ่อนรหัสผ่าน", "Show/Hide password");
        Add(th, en, "Layout.LoggingIn", "กำลังยืนยันตัวตน...", "Authenticating...");
        Add(th, en, "Layout.LoginSubmit", "เข้าสู่ระบบจัดการ SFTP", "Sign in to SFTP Admin");
        Add(th, en, "Layout.LoginFooterInfo", "รองรับทั้งบัญชี Active Directory และ Fallback Local Admin", "Supports Active Directory and Fallback Local Admin");
        Add(th, en, "Layout.ManageServiceTooltip", "คลิกเพื่อจัดการ OpenSSH Service", "Click to manage OpenSSH Service");
        Add(th, en, "Layout.RefreshServiceTooltip", "รีเฟรชสถานะ Service", "Refresh service status");
        Add(th, en, "Layout.LogoutTooltip", "ออกจากระบบผู้ดูแล", "Sign out");
        Add(th, en, "Layout.Logout", "ออกจากระบบ", "Sign out");
        Add(th, en, "Layout.UnhandledError", "เกิดข้อผิดพลาดที่ไม่คาดคิดในระบบ", "An unhandled error has occurred.");
        Add(th, en, "Layout.ReloadPage", "โหลดหน้านี้ใหม่", "Reload");
        Add(th, en, "Layout.DismissAlert", "ปิดข้อความแจ้งเตือน", "Dismiss");
        Add(th, en, "Layout.MissingCredentials", "กรุณากรอก Username และ Password", "Please enter both Username and Password.");
        Add(th, en, "Layout.AuthFailed", "การยืนยันตัวตนล้มเหลว ตรวจสอบชื่อผู้ใช้หรือรหัสผ่าน", "Authentication failed. Please check your username or password.");
        Add(th, en, "Layout.SwitchLanguageTooltip", "สลับภาษา (ไทย / English)", "Switch language (Thai / English)");

        // NavMenu
        Add(th, en, "Nav.SectionOverview", "ภาพรวมระบบ", "Overview");
        Add(th, en, "Nav.Dashboard", "แดชบอร์ด", "Dashboard");
        Add(th, en, "Nav.SectionAccess", "สิทธิ์และไฟล์", "Access & Storage");
        Add(th, en, "Nav.Users", "ผู้ใช้งาน (SFTP Users)", "SFTP Users");
        Add(th, en, "Nav.Groups", "กลุ่มผู้ใช้ (SFTP Groups)", "SFTP Groups");
        Add(th, en, "Nav.Files", "สำรวจไฟล์ (File Browser)", "File Browser");
        Add(th, en, "Nav.SectionSystem", "ระบบและความปลอดภัย", "System & Security");
        Add(th, en, "Nav.Service", "บริการ OpenSSH", "OpenSSH Service");
        Add(th, en, "Nav.Sessions", "เซสชันสด (Live Sessions)", "Live Sessions");
        Add(th, en, "Nav.SshLogs", "บันทึกเซิร์ฟเวอร์", "OpenSSH Logs");
        Add(th, en, "Nav.AuditLogs", "ประวัติกิจกรรม", "Audit Logs");
        Add(th, en, "Nav.WebAdmins", "ผู้ดูแลระบบ", "Web Admins");
        Add(th, en, "Nav.Settings", "ตั้งค่าระบบ (AD/LDAP)", "Settings (AD/LDAP)");

        // LoginModal
        Add(th, en, "LoginModal.Subtitle", "เข้าสู่ระบบด้วยบัญชี Active Directory (Domain) หรือ Local Admin เพื่อจัดการ SFTP Server", "Sign in with an Active Directory (Domain) or Local Admin account to manage the SFTP Server.");
        Add(th, en, "LoginModal.AccountHint", "AD หรือ Local", "AD or Local");
        Add(th, en, "LoginModal.UsernamePlaceholder", "เช่น admin หรือ domain\\sftp_admin", "e.g. admin or domain\\sftp_admin");
        Add(th, en, "LoginModal.PasswordPlaceholder", "รหัสผ่านผู้ดูแลระบบ", "Administrator password");
        Add(th, en, "LoginModal.Ready", "พร้อมตรวจสอบสิทธิ์", "Ready to authenticate");
        Add(th, en, "LoginModal.FillRequired", "กรอกข้อมูลให้ครบเพื่อเข้าสู่ระบบ", "Fill in required fields to sign in");
        Add(th, en, "LoginModal.Checking", "กำลังตรวจสอบ...", "Verifying...");
        Add(th, en, "LoginModal.SignIn", "เข้าสู่ระบบ", "Sign In");

        // Error Page
        Add(th, en, "Error.Title", "เกิดข้อผิดพลาดในระบบ (System Error)", "System Error");
        Add(th, en, "Error.Subtitle", "ไม่สามารถประมวลผลคำขอของคุณได้ในขณะนี้", "An error occurred while processing your request.");
        Add(th, en, "Error.DevAdviceTitle", "คำแนะนำสำหรับผู้ดูแลระบบ (Development Mode):", "Administrator Note (Development Mode):");
        Add(th, en, "Error.DevAdviceBody", "การสลับไปใช้โหมด Development จะแสดงรายละเอียดของข้อผิดพลาดที่ชัดเจนยิ่งขึ้นสำหรับการตรวจสอบปัญหา ทั้งนี้ไม่ควรเปิดโหมด Development ทิ้งไว้บนเซิร์ฟเวอร์ใช้งานจริง (Production)", "Switching to Development mode displays detailed error information for troubleshooting. Do not leave Development mode enabled on production servers.");

        // FolderPickerModal
        Add(th, en, "FolderPicker.Title", "เลือกโฟลเดอร์ (Select Folder / Path)", "Select Folder / Path");
        Add(th, en, "FolderPicker.Step1", "1. โฟลเดอร์เป้าหมายที่เลือก (Selected Path)", "1. Selected Target Path");
        Add(th, en, "FolderPicker.PathHint", "พิมพ์ Path หรือคลิกเลือกด้านล่าง", "Type path or select below");
        Add(th, en, "FolderPicker.PathPlaceholder", "เช่น D:\\SFTPShare\\Marketing", "e.g. D:\\SFTPShare\\Marketing");
        Add(th, en, "FolderPicker.OpenPathTooltip", "เปิดดูโฟลเดอร์ตาม Path ที่ระบุ", "Open the specified path");
        Add(th, en, "FolderPicker.OpenPathBtn", "เปิดดู Path นี้", "Open Path");
        Add(th, en, "FolderPicker.Step2", "2. เลือกไดรฟ์และสำรวจโฟลเดอร์ย่อย (Browse Drives & Folders)", "2. Browse Drives & Subfolders");
        Add(th, en, "FolderPicker.SubfoldersCount", "โฟลเดอร์ย่อยภายใน ({0})", "Subfolders ({0})");
        Add(th, en, "FolderPicker.NewFolderPlaceholder", "ชื่อโฟลเดอร์ย่อยใหม่ (เช่น Data, Inbound)...", "New subfolder name (e.g. Data, Inbound)...");
        Add(th, en, "FolderPicker.CreateFolder", "สร้างโฟลเดอร์", "Create Folder");
        Add(th, en, "FolderPicker.EmptyFolder", "ไม่มีโฟลเดอร์ย่อยภายในไดเรกทอรีนี้ (สามารถพิมพ์ชื่อเพื่อสร้างโฟลเดอร์ใหม่ที่มุมขวาบน)", "No subfolders in this directory (you can create a new folder above)");
        Add(th, en, "FolderPicker.ParentDir", ".. (ย้อนกลับขึ้นหนึ่งระดับ)", ".. (Parent Directory)");
        Add(th, en, "FolderPicker.WillSelect", "จะเลือก:", "Selected:");
        Add(th, en, "FolderPicker.PromptSelect", "กรุณาเลือกไดรฟ์หรือโฟลเดอร์", "Please select a drive or folder");
        Add(th, en, "FolderPicker.ConfirmBtn", "ยืนยันเลือกโฟลเดอร์นี้", "Confirm Folder");
        Add(th, en, "FolderPicker.NotFound", "ไม่พบโฟลเดอร์ที่ระบุ: {0}", "Folder not found: {0}");
        Add(th, en, "FolderPicker.UnsafeName", "ชื่อโฟลเดอร์ไม่ปลอดภัย: {0}", "Unsafe folder name: {0}");
        Add(th, en, "FolderPicker.CreateFailedSecurity", "ไม่สามารถสร้างโฟลเดอร์ได้ โฟลเดอร์ปลายทางอาจถูกจำกัดสิทธิ์โดยระบบรักษาความปลอดภัย", "Cannot create folder. Destination may be restricted by security policy.");
        Add(th, en, "FolderPicker.CreateFailed", "ไม่สามารถสร้างโฟลเดอร์ได้: {0}", "Failed to create folder: {0}");
        Add(th, en, "FolderPicker.UnsafePath", "ไม่สามารถเลือกโฟลเดอร์นี้ได้: {0}", "Cannot select this folder: {0}");
    }
}
