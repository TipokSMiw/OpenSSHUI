# OpensshUI

**OpensshUI** เป็นเว็บแอปพลิเคชันสำหรับบริหารจัดการ Windows OpenSSH SFTP Server บนระบบปฏิบัติการ Windows พัฒนาด้วย **ASP.NET Core (.NET 8)** และ **Blazor Interactive Server**

## ฟีเจอร์หลัก
* **User Management:** จัดการ Local Windows Users, Home Directory, Chroot Directory, Quota และสถานะบัญชี
* **SSH Key Management:** อัปโหลดและแปลง Public Keys (OpenSSH, RFC4716, PKCS#8/PEM, PuTTY `.ppk`)
* **Group & Junction Management:** รวมกลุ่มผู้ใช้และสร้าง NTFS Directory Junctions สำหรับการแชร์โฟลเดอร์
* **NTFS ACL Provisioning:** จัดสรรสิทธิ์โฟลเดอร์ตามมาตรฐานความปลอดภัยของ OpenSSH Chroot
* **Secure Web File Browser:** สำรวจและจัดการไฟล์ใน SFTP Root ผ่านเว็บ
* **OpenSSH Service Controller:** ตรวจสอบและสั่ง Start / Stop / Restart Service `sshd`
* **OpenSSH Windows Event Log Viewer:** ตรวจสอบบันทึกการเชื่อมต่อและกิจกรรมระดับระบบของ OpenSSH จาก Windows Event Log (`OpenSSH/Operational`) พร้อมระบบ Smart Parsing (แยก User, IP, Port, ประเภทเหตุการณ์), ตัวกรองช่วงเวลาด่วน, Auto-Refresh, ส่งออกรายงาน CSV และโหมดจำลองข้อมูล (Demo Mode) สำหรับเครื่องพัฒนา
* **Authentication & Audit:** รองรับ Active Directory / LDAP พร้อม Fallback Local Admin และ Web Audit Logs (SQLite)

---

## เอกสารที่เกี่ยวข้อง

* [DEPLOYMENT_IIS.md](DEPLOYMENT_IIS.md): คู่มือการติดตั้งบน Windows Server โดยรันผ่าน IIS อย่างละเอียด พร้อมสคริปต์ PowerShell ติดตั้งอัตโนมัติ และขั้นตอนการอัปเกรดเวอร์ชัน
* [AGENT.md](AGENT.md): คู่มือมาตรฐานสถาปัตยกรรมและแนวปฏิบัติสำหรับนักพัฒนาและ AI Agent

---

## คำสั่งเริ่มต้นสำหรับการพัฒนา

```powershell
# Restore & Build Project
dotnet build OpensshUI.csproj

# Run Tests
dotnet test OpensshUI.Tests\OpensshUI.Tests.csproj

# Run Web Application (Development)
dotnet run --project OpensshUI.csproj

# Publish สำหรับนำไปติดตั้งหรืออัปเกรดบน Server
dotnet publish OpensshUI.csproj -c Release -o ./publish
```
