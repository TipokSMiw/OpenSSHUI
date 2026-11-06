# OpensshUI

**OpensshUI** เป็นเว็บแอปพลิเคชันสำหรับบริหารจัดการ Windows OpenSSH SFTP Server บนระบบปฏิบัติการ Windows พัฒนาด้วย **ASP.NET Core (.NET 8)** และ **Blazor Interactive Server**

---

## ฟีเจอร์หลัก (Key Features)

* **User Management:** จัดการ Local Windows Users, กำหนด Home Directory, Chroot Directory, Quota และเปิด/ปิดการใช้งานบัญชีผ่านคำสั่ง OS ที่ปลอดภัย
* **SSH Key Management:** อัปโหลดและแปลง Public Keys ได้หลากหลายฟอร์แมต (OpenSSH, RFC4716, PKCS#8/PEM, PuTTY `.ppk`) จัดเก็บแยกไฟล์ `%u` ต่อผู้ใช้เพื่อความปลอดภัย
* **Group & Directory Junctions:** บริหารกลุ่มผู้ใช้ SFTP พร้อมสร้าง NTFS Directory Junctions เชื่อมต่อแชร์โฟลเดอร์ระหว่างกลุ่มผู้ใช้โดยป้องกัน Symlink Attack
* **Strict Chroot NTFS ACL Engine (`INtfsAclService`):** จัดสรรสิทธิ์โฟลเดอร์ตามมาตรฐานความปลอดภัยสูงสุดของ OpenSSH Chroot โดย Chroot Root จะมีเพียง `SYSTEM` และ `Administrators` เท่านั้นที่มีสิทธิ์เขียน ส่วนโฟลเดอร์ทำงานของผู้ใช้จะได้รับสิทธิ์ Modify/Read-Only อย่างเข้มงวด พร้อมระบบ Path Safety Validation ป้องกัน Path Traversal
* **Atomic `sshd_config` Engine (`ISshdConfigService`):**
  * แยกโครงสร้างไฟล์เป็น Global Directives และ Match Blocks อย่างเป็นระบบ ป้องกันปัญหา Directive Bleeding
  * มีระบบตรวจสอบความถูกต้องของไวยากรณ์ด้วย `sshd.exe -t` ทั้งในระดับ Content และไฟล์จริงก่อนบันทึก
  * เขียนไฟล์แบบ Atomic ผ่าน Temporary File และแทนที่ด้วยความปลอดภัยสูง
  * ระบบ Rolling Backup อัตโนมัติ (เก็บไฟล์ `.bak` ย้อนหลังสูงสุด 5 ชุด)
  * รองรับการซิงค์บล็อกการตั้งค่าเฉพาะ (`# BEGIN MANAGED OPENSSH-UI BLOCKS`) โดยไม่กระทบการตั้งค่าเดิมของแอดมิน
* **Dual Service Controller (`sshd` & `ssh-agent`):** ตรวจสอบและสั่ง Start / Stop / Restart ทั้งบริการ `sshd` และ `ssh-agent` จากหน้าเว็บ พร้อมปุ่มทดสอบไวยากรณ์ (`sshd.exe -t`) แบบ On-demand ก่อน Restart
* **Zero-Config Reload Architecture:** รองรับโครงสร้าง `Match Group SFTP-Users` ร่วมกับ `%u` token ช่วยให้เพิ่มผู้ใช้ใหม่หรืออัปเดต SSH Key ได้ทันทีโดยไม่ต้องแก้ไขไฟล์ config และไม่ต้อง Restart Service
* **High-Performance Event Log Engine (`ISshEventLogService`):** เชื่อมต่อและดึงข้อมูลจาก Windows Event Log (`OpenSSH/Operational`) ผ่าน Optimized Regex Parser แยกข้อมูล Username, IP Address, Port, Authentication Method, Event Type และความรุนแรง พร้อมตัวกรองเวลาด่วน, Auto-Refresh, ระบบ Export รายงาน CSV และโหมดจำลองข้อมูล (Demo Mock Mode)
* **Secure Web File Browser:** สำรวจและจัดการไฟล์ใน SFTP Root ผ่านเว็บอินเทอร์เฟซ จำกัดขอบเขตอย่างเข้มงวด ป้องกัน Directory Traversal
* **Web Admin Management & Role-Based Access Control (RBAC):**
  * บริหารจัดการบัญชีผู้ดูแลหน้าเว็บแยกรายบุคคล ทั้ง Local Web Admin (รหัสผ่าน PBKDF2 SHA-256) และ Active Directory Users
  * ระบบ Live Search ค้นหาและดึงบัญชีผู้ใช้จากโดเมน Active Directory มาให้สิทธิ์ได้ทันที
  * กำหนดบทบาทสิทธิ์ 3 ระดับ: `SuperAdmin` (จัดการได้ทุกระบบ), `Operator` (จัดการ SFTP Users/Groups/Files ได้ แต่แก้ไขระบบไม่ได้), และ `Auditor` (อ่านอย่างเดียว Read-Only)
  * มาตรการความปลอดภัยขั้นสูง (Guardrails): ป้องกันการลบหรือระงับบัญชีตนเอง, ป้องกันการลบหรือลดสิทธิ์ Super Admin คนสุดท้าย, และป้องกันการลบบัญชี Local Admin ฉุกเฉินหลัก
  * การบันทึก Audit Accountability: ระบุตัวตนของผู้ดูแลที่เป็นผู้กระทำการจริงในทุกกิจกรรมของหน้า Audit Logs
* **Authentication & Security Audit:** รองรับการยืนยันตัวตนผ่าน Active Directory / LDAP พร้อม Fallback Local Admin และเก็บบันทึก Web Audit Logs ทุกกิจกรรมลง SQLite (WAL Mode)

---

## เอกสารที่เกี่ยวข้อง

* [DEPLOYMENT_IIS.md](DEPLOYMENT_IIS.md): คู่มือการติดตั้งบน Windows Server โดยรันผ่าน IIS อย่างละเอียด พร้อมสคริปต์ PowerShell ติดตั้งอัตโนมัติ และขั้นตอนการอัปเกรดเวอร์ชัน
* [AGENT.md](AGENT.md): คู่มือมาตรฐานสถาปัตยกรรม, Security Guardrails, และแนวปฏิบัติสำหรับนักพัฒนาและ AI Agent

---

## คำสั่งเริ่มต้นสำหรับการพัฒนา

```powershell
# Restore & Build Project
dotnet build OpensshUI.csproj

# Run Automated Test Suite (210+ Tests)
dotnet test OpensshUI.Tests\OpensshUI.Tests.csproj

# Run Web Application (Development Mode)
dotnet run --project OpensshUI.csproj

# Publish สำหรับนำไปติดตั้งหรืออัปเกรดบน Server
dotnet publish OpensshUI.csproj -c Release -o ./publish
```
