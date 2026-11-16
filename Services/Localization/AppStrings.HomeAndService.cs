namespace OpensshUI.Services.Localization;

public static partial class AppStrings
{
    private static void RegisterHomeAndServiceStrings(Dictionary<string, string> th, Dictionary<string, string> en)
    {
        // Home (Dashboard)
        Add(th, en, "Home.Title", "ภาพรวมระบบ (SFTP Server Dashboard)", "System Overview (SFTP Server Dashboard)");
        Add(th, en, "Home.Subtitle", "บริหารจัดการผู้ใช้, กลุ่มแชร์ไฟล์, สิทธิ์ NTFS ACL และสถานะบริการ Windows OpenSSH", "Manage SFTP users, shared groups, NTFS ACL permissions, and Windows OpenSSH services");
        Add(th, en, "Home.RefreshBtn", "รีเฟรชข้อมูล", "Refresh Data");
        Add(th, en, "Home.ManageUsersBtn", "จัดการผู้ใช้งาน SFTP", "Manage SFTP Users");
        Add(th, en, "Home.ActiveAccounts", "{0} บัญชีใช้งานอยู่", "{0} active accounts");
        Add(th, en, "Home.LiveConnections", "กำลังเชื่อมต่อสด", "Live connections active");
        Add(th, en, "Home.NoConnections", "ไม่มีการเชื่อมต่อ", "No active connections");
        Add(th, en, "Home.ZeroConfigReady", "Zero-Config พร้อม", "Zero-Config Ready");
        Add(th, en, "Home.ZeroConfigNotInstalled", "ยังไม่ลง Zero-Config", "Zero-Config Not Installed");
        Add(th, en, "Home.ZeroConfigAlertTitle", "ยังไม่พบ Zero-Config Block ใน sshd_config", "Zero-Config Block Not Found in sshd_config");
        Add(th, en, "Home.ZeroConfigAlertDesc", "ติดตั้งบล็อก Match Group SFTP-Users ลงใน {0} เพื่อให้สามารถเพิ่ม/ลดผู้ใช้ได้ทันทีโดยไม่ต้อง Restart Service", "Install Match Group SFTP-Users block into {0} to add/remove users immediately without restarting the service");
        Add(th, en, "Home.InstallZeroConfigBtn", "ติดตั้ง Zero-Config ทันที", "Install Zero-Config Now");
        Add(th, en, "Home.QuickActions", "เมนูจัดการด่วน (Quick Actions)", "Quick Actions");
        Add(th, en, "Home.QuickUsersTitle", "จัดการผู้ใช้งาน (SFTP Users)", "Manage SFTP Users");
        Add(th, en, "Home.QuickUsersDesc", "สร้างบัญชี, ตั้งรหัสผ่าน และจัดการ SSH Keys", "Create accounts, set passwords, and manage SSH keys");
        Add(th, en, "Home.QuickGroupsTitle", "จัดการกลุ่มผู้ใช้ (SFTP Groups)", "Manage SFTP Groups");
        Add(th, en, "Home.QuickGroupsDesc", "กำหนด Shared Folder และ NTFS Junctions", "Configure shared folders and NTFS Junctions");
        Add(th, en, "Home.QuickFilesTitle", "สำรวจไฟล์ (Web File Browser)", "Web File Browser");
        Add(th, en, "Home.QuickFilesDesc", "อัปโหลด ดาวน์โหลด และตรวจสอบไฟล์ใน Chroot", "Upload, download, and inspect files inside Chroot");
        Add(th, en, "Home.QuickServiceTitle", "บริการ OpenSSH & Syntax Check", "OpenSSH Service & Syntax Check");
        Add(th, en, "Home.QuickServiceDesc", "ตรวจสอบ sshd.exe -t และควบคุมบริการ", "Run sshd.exe -t syntax check and control services");
        Add(th, en, "Home.QuickSettingsTitle", "ตั้งค่า Active Directory / LDAP", "Active Directory / LDAP Settings");
        Add(th, en, "Home.QuickSettingsDesc", "เชื่อมต่อ Domain Controller และรหัสผ่านฉุกเฉิน", "Configure Domain Controller and fallback password");
        Add(th, en, "Home.RecentAudits", "ประวัติกิจกรรมล่าสุด (Recent Audit Logs)", "Recent Audit Logs");
        Add(th, en, "Home.ViewAll", "ดูทั้งหมด", "View All");
        Add(th, en, "Home.NoAudits", "ยังไม่มีบันทึกประวัติกิจกรรม (Audit Log)", "No audit log records yet");
        Add(th, en, "Home.ColTime", "เวลา", "Time");
        Add(th, en, "Home.ColOperator", "ผู้ดำเนินการ", "Operator");
        Add(th, en, "Home.ColDetails", "รายละเอียด", "Details");
        Add(th, en, "Home.Success", "สำเร็จ", "Success");
        Add(th, en, "Home.Failed", "ล้มเหลว", "Failed");
        Add(th, en, "Home.LoadError", "เกิดข้อผิดพลาดในการโหลดข้อมูล: {0}", "Error loading dashboard data: {0}");

        // Service Control Page
        Add(th, en, "Service.Title", "บริการ OpenSSH (Service Controller)", "OpenSSH Service Controller");
        Add(th, en, "Service.Subtitle", "ควบคุมและตรวจสอบสถานะ Windows OpenSSH (sshd) พร้อมระบบตรวจสอบไวยากรณ์ sshd.exe -t", "Control and monitor Windows OpenSSH (sshd) with sshd.exe -t syntax validation");
        Add(th, en, "Service.RefreshStatus", "รีเฟรชสถานะ", "Refresh Status");
        Add(th, en, "Service.ReadOnlyNotice", "โหมดอ่านอย่างเดียว (Read-Only): เฉพาะผู้ดูแลระบบระดับ SuperAdmin เท่านั้นที่สามารถสั่งควบคุมบริการ Windows Service หรือแก้ไขไฟล์ sshd_config ได้ (สิทธิ์ปัจจุบันของคุณ: {0})", "Read-Only Mode: Only SuperAdmin can control Windows Services or modify sshd_config (Your current role: {0})");
        Add(th, en, "Service.SshdStatusTitle", "สถานะ Windows Service (sshd)", "Windows Service Status (sshd)");
        Add(th, en, "Service.SyntaxTitle", "ตรวจสอบไวยากรณ์ Config (sshd.exe -t)", "Config Syntax Check (sshd.exe -t)");
        Add(th, en, "Service.Checking", "กำลังตรวจสอบ...", "Checking...");
        Add(th, en, "Service.CheckNow", "ตรวจสอบเดี๋ยวนี้", "Check Now");
        Add(th, en, "Service.SyntaxDesc", "การใช้คำสั่ง sshd.exe -t จะตรวจสอบความถูกต้องของไฟล์ sshd_config โดยระบบจะรันการตรวจสอบนี้ทุกครั้งก่อนสั่ง Restart Service เสมอเพื่อป้องกันไม่ให้บริการล่ม", "Running sshd.exe -t validates sshd_config syntax. The system automatically runs this check before every service restart to prevent downtime.");
        Add(th, en, "Service.SyntaxValid", "Syntax Valid (ไวยากรณ์ถูกต้อง ปลอดภัย)", "Syntax Valid (No errors detected)");
        Add(th, en, "Service.SyntaxError", "Syntax Error (พบข้อผิดพลาดในไฟล์ config)", "Syntax Error (Configuration error detected)");
        Add(th, en, "Service.SyntaxEmpty", "คลิกปุ่ม \"ตรวจสอบเดี๋ยวนี้\" เพื่อรันคำสั่ง sshd.exe -t", "Click \"Check Now\" to run sshd.exe -t");
        Add(th, en, "Service.AgentStatusTitle", "สถานะ Windows Service (ssh-agent)", "Windows Service Status (ssh-agent)");
        Add(th, en, "Service.ConcurrencyTitle", "การปรับแต่งประสิทธิภาพและการเชื่อมต่อ", "Concurrency & Connection Limits");
        Add(th, en, "Service.ConcurrencyDesc", "กำหนดขีดจำกัดการเชื่อมต่อพร้อมกันใน sshd_config เพื่อป้องกัน Connection reset by peer เมื่อมีทราฟฟิกสูง", "Configure concurrent connection limits in sshd_config to prevent Connection reset by peer under high traffic.");
        Add(th, en, "Service.PresetsLabel", "พรีเซ็ตแนะนำ:", "Recommended Presets:");
        Add(th, en, "Service.PresetStandard", "Standard (ไม่เกิน 50 ผู้ใช้)", "Standard (Up to 50 users)");
        Add(th, en, "Service.PresetHighTraffic", "High Traffic (100-300 ผู้ใช้)", "High Traffic (100-300 users)");
        Add(th, en, "Service.PresetDefault", "ค่าเริ่มต้น OpenSSH", "OpenSSH Default");
        Add(th, en, "Service.MaxStartupsLabel", "MaxStartups", "MaxStartups");
        Add(th, en, "Service.MaxStartupsPlaceholder", "10:30:100 หรือ 100:30:300", "10:30:100 or 100:30:300");
        Add(th, en, "Service.MaxStartupsHelp", "จำนวนการเชื่อมต่อพร้อมกันช่วง Handshake เช่น 100:30:300 (เริ่มสุ่มดร็อปที่ 100 ดร็อป 100% ที่ 300)", "Concurrent handshake connections, e.g. 100:30:300 (start random drop at 100, drop 100% at 300)");
        Add(th, en, "Service.MaxSessionsLabel", "MaxSessions", "MaxSessions");
        Add(th, en, "Service.MaxSessionsHelp", "จำนวนช่องสัญญาณต่อการเชื่อมต่อ (ค่าเริ่มต้น 10 แนะนำ 20-50 หากเปิดหลายเธรด)", "Multiplexed channels per connection (Default 10, recommended 20-50 for multi-threaded clients)");
        Add(th, en, "Service.ClientAliveIntervalLabel", "ClientAliveInterval", "ClientAliveInterval");
        Add(th, en, "Service.ClientAliveIntervalHelp", "ระยะเวลาตรวจสอบการเชื่อมต่อ (0 = ปิด, แนะนำ 30 หรือ 60 วินาทีเพื่อเคลียร์เซสชันค้าง)", "Keepalive interval in seconds (0 = disabled, recommended 30 or 60s to clear stale sessions)");
        Add(th, en, "Service.ClientAliveCountMaxLabel", "ClientAliveCountMax", "ClientAliveCountMax");
        Add(th, en, "Service.ClientAliveCountMaxHelp", "จำนวนครั้งที่ไม่ตอบกลับก่อนตัดการเชื่อมต่อ (ค่าเริ่มต้น 3 ครั้ง)", "Max missed keepalive probes before disconnecting (Default 3)");
        Add(th, en, "Service.LoginGraceTimeLabel", "LoginGraceTime", "LoginGraceTime");
        Add(th, en, "Service.LoginGraceTimeHelp", "เวลารอการยืนยันตัวตน (ค่าเริ่มต้น 120 วินาที แนะนำ 30-60 เมื่อทราฟฟิกสูง)", "Authentication timeout in seconds (Default 120s, recommended 30-60s under high traffic)");
        Add(th, en, "Service.SecondsUnit", "วินาที", "sec");
        Add(th, en, "Service.TimesUnit", "ครั้ง", "probes");
        Add(th, en, "Service.ApplyRestartNote", "การปรับค่าจะมีผลสมบูรณ์เมื่อสั่ง Restart Service (sshd) ด้านบน", "Changes take full effect after restarting the sshd service above.");
        Add(th, en, "Service.ValidatingSaving", "กำลังตรวจสอบและบันทึก...", "Validating & Saving...");
        Add(th, en, "Service.ApplyAndValidate", "ตรวจสอบและบันทึกค่า", "Apply & Validate");
        Add(th, en, "Service.ZeroConfigTitle", "โครงสร้าง Zero-Config Reload", "Zero-Config Reload Structure");
        Add(th, en, "Service.ZeroConfigInstalled", "ติดตั้งแล้ว", "Installed");
        Add(th, en, "Service.ZeroConfigInstallBtn", "ติดตั้งลง sshd_config", "Install to sshd_config");
        Add(th, en, "Service.ZeroConfigDesc", "ด้วยบล็อกการตั้งค่านี้ เมื่อผู้ใช้ใหม่อยู่ใน Windows Local Group SFTP-Users ระบบ OpenSSH จะบังคับ Chroot และอ่าน Public Key จากโฟลเดอร์กลาง C:\\ProgramData\\ssh\\keys\\%u โดยอัตโนมัติ ทำให้ไม่ต้องเปิดไฟล์ config แก้ไข หรือ Restart Service อีกเลย", "With this block, users in the Windows Local Group SFTP-Users are automatically Chrooted and authenticated via C:\\ProgramData\\ssh\\keys\\%u without editing sshd_config or restarting the service.");
    }
}
