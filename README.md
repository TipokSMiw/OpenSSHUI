# OpensshUI

> **Language / ภาษา:** [English](#english) | [ภาษาไทย](#thai)

---

<a id="english"></a>

## English

**OpensshUI** is a web administration portal for **Windows OpenSSH SFTP Server**, built with **ASP.NET Core (.NET 8)** and **Blazor Interactive Server**.

### Key Features

* **Bilingual UI (TH / EN):** Instant live switching between Thai and English across all management pages, modals, and login screens with browser `localStorage` persistence.
* **User Management:** Manage Local Windows Users and Active Directory (LDAP) accounts, Home/Chroot directories, custom root overrides, and account activation status via safe OS commands.
* **SSH Key Management:** Import and convert Public Keys across multiple formats (OpenSSH, RFC4716, PKCS#8/PEM, PuTTY `.ppk`) with RFC 4251 wire-format verification, stored in isolated `%u` key files, plus one-time Zero-Knowledge Automation Key Pair generation (`Ed25519` / `RSA 4096`).
* **Group & Directory Junctions:** Manage SFTP user groups and create idempotent NTFS Directory Junctions to share folders across groups while defending against symlink attacks.
* **Strict Chroot NTFS ACL Engine (`INtfsAclService`):** Enforces OpenSSH Chroot ownership rules (`SYSTEM` and `Administrators` write-only on Chroot root; `Modify`/`Read-Only` on user subdirectories) with full-spectrum path traversal validation.
* **Atomic `sshd_config` Engine (`ISshdConfigService`):**
  * Separates Global Directives from Match Blocks to prevent directive bleeding.
  * Runs `sshd.exe -t` pre-flight syntax checks before applying changes.
  * Uses atomic file replacement and keeps up to 5 rolling `.bak` backups.
  * Manages `# BEGIN MANAGED OPENSSH-UI BLOCKS` without disturbing existing admin rules.
* **Dual Service Controller (`sshd` & `ssh-agent`):** Start, Stop, Restart, and run on-demand `sshd.exe -t` syntax checks for both `sshd` and `ssh-agent` services.
* **Zero-Config Reload Architecture:** Uses `Match Group SFTP-Users` with `%u` tokens so new users and SSH keys take effect immediately without editing `sshd_config` or restarting `sshd`.
* **Real-Time SFTP Live Session Monitor & Termination (`ISftpSessionService`):** Inspects live TCP/process sessions via Win32 P/Invoke (`iphlpapi.dll`), detects excessive connections (> 5 sessions), and supports single/user-wide disconnect with Demo Mock Mode.
* **Concurrency & High-Traffic Performance Tuning:** Configure `MaxStartups`, `MaxSessions`, `ClientAliveInterval`, `ClientAliveCountMax`, and `LoginGraceTime` with built-in presets (`Standard`, `HighTraffic`, `Default`) and atomic validation.
* **High-Performance Event Log Engine (`ISshEventLogService`):** Queries `OpenSSH/Operational` via XPath time filtering and compiled Regex parsing, with quick presets, auto-refresh, Demo Mode, and CSV export (with formula-injection protection).
* **Secure Web File Browser:** Browse, upload, download, and manage files strictly confined to user Chroot or group share roots.
* **Web Admin Management & RBAC:**
  * Manage individual Local Web Admins (PBKDF2 SHA-256) and Active Directory admins with live AD search.
  * Three strict roles: `SuperAdmin`, `Operator`, and `Auditor` (Read-Only), enforced at both UI and handler levels.
  * Built-in guardrails: Self-Lockout Prevention, Last SuperAdmin Protection, and Fallback `admin` deletion protection.
* **Authentication & Security Audit:** Active Directory / LDAP authentication with Fallback Local Admin and SQLite WAL-mode audit logging.

### Related Documentation

* [DEPLOYMENT_IIS.md](DEPLOYMENT_IIS.md): Step-by-step Windows Server & IIS deployment guide, automated PowerShell setup scripts, and upgrade instructions.
* [AGENT.md](AGENT.md): Architecture standards, OWASP & Security Guardrails (`[C1]`–`[C8]`), localization rules, and AI Agent development playbook.

### Development & Build Commands

```powershell
# Restore & Build Project
dotnet build OpensshUI.csproj

# Build with Roslyn Analyzers & Code Style Verification
dotnet build OpensshUI.csproj --no-restore /p:EnforceCodeStyleInBuild=true

# Run Automated Test Suite
dotnet test OpensshUI.Tests\OpensshUI.Tests.csproj

# Run Web Application (Development Mode)
dotnet run --project OpensshUI.csproj

# Publish for Production
dotnet publish OpensshUI.csproj -c Release -o ./publish
```

---

<a id="thai"></a>

## ภาษาไทย

**OpensshUI** เป็นเว็บแอปพลิเคชันสำหรับบริหารจัดการ Windows OpenSSH SFTP Server บนระบบปฏิบัติการ Windows พัฒนาด้วย **ASP.NET Core (.NET 8)** และ **Blazor Interactive Server**

### ฟีเจอร์หลัก (Key Features)

* **ระบบรองรับ 2 ภาษา (TH / EN):** สลับภาษาไทยและภาษาอังกฤษได้ทันทีแบบ Real-time ทั้งหน้าเข้าสู่ระบบ เมนู และทุกหน้าจัดการ พร้อมบันทึกค่าที่เลือกไว้ในเบราว์เซอร์ (`localStorage`)
* **User Management:** จัดการ Local Windows Users และ Active Directory (LDAP), กำหนด Home Directory, Chroot Directory, Custom Root Override และเปิด/ปิดการใช้งานบัญชีผ่านคำสั่ง OS ที่ปลอดภัย
* **SSH Key Management:** อัปโหลดและแปลง Public Keys ได้หลากหลายฟอร์แมต (OpenSSH, RFC4716, PKCS#8/PEM, PuTTY `.ppk`) พร้อมตรวจสอบ RFC 4251 Wire-Format จัดเก็บแยกไฟล์ `%u` ต่อผู้ใช้ และมีระบบสร้าง Automation Key Pair (`Ed25519` / `RSA 4096`) แบบ Zero-Knowledge ดาวน์โหลด Private Key ครั้งเดียว
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
* **Real-Time SFTP Live Session Monitor & Termination (`ISftpSessionService`):** ตรวจสอบสถานะการเชื่อมต่อ SFTP แบบสดผ่าน Win32 P/Invoke (`iphlpapi.dll`) ความเร็วสูง ตรวจจับ Session ซ้ำซ้อน (> 5 connections) สั่งตัดการเชื่อมต่อ (Disconnect) รายเซสชันหรือรายยูสเซอร์ทันที พร้อมโหมดจำลองข้อมูล (Demo Mock Mode) และ Modal ป้องกันความผิดพลาด
* **Concurrency & High-Traffic Performance Tuning Engine:** แผงควบคุมและปรับแต่งพารามิเตอร์ Concurrency ใน `sshd_config` (`MaxStartups`, `MaxSessions`, `ClientAliveInterval`, `ClientAliveCountMax`, `LoginGraceTime`) พร้อม Presets สำหรับรองรับผู้ใช้พร้อมกันปริมาณมาก ป้องกันปัญหา Connection Reset และเขียนไฟล์แบบ Atomic ร่วมกับ `sshd.exe -t` syntax guard
* **High-Performance Event Log Engine (`ISshEventLogService`):** เชื่อมต่อและดึงข้อมูลจาก Windows Event Log (`OpenSSH/Operational`) ผ่าน Optimized Regex Parser แยกข้อมูล Username, IP Address, Port, Authentication Method, Event Type และความรุนแรง พร้อมตัวกรองเวลาด่วน, Auto-Refresh, ระบบ Export รายงาน CSV และโหมดจำลองข้อมูล (Demo Mock Mode)
* **Secure Web File Browser:** สำรวจและจัดการไฟล์ใน SFTP Root ผ่านเว็บอินเทอร์เฟซ จำกัดขอบเขตอย่างเข้มงวด ป้องกัน Directory Traversal
* **Web Admin Management & Role-Based Access Control (RBAC):**
  * บริหารจัดการบัญชีผู้ดูแลหน้าเว็บแยกรายบุคคล ทั้ง Local Web Admin (รหัสผ่าน PBKDF2 SHA-256) และ Active Directory Users
  * ระบบ Live Search ค้นหาและดึงบัญชีผู้ใช้จากโดเมน Active Directory มาให้สิทธิ์ได้ทันที
  * กำหนดบทบาทสิทธิ์ 3 ระดับ: `SuperAdmin` (จัดการได้ทุกระบบ), `Operator` (จัดการ SFTP Users/Groups/Files ได้ แต่แก้ไขระบบไม่ได้), และ `Auditor` (อ่านอย่างเดียว Read-Only)
  * มาตรการความปลอดภัยขั้นสูง (Guardrails): ป้องกันการลบหรือระงับบัญชีตนเอง, ป้องกันการลบหรือลดสิทธิ์ Super Admin คนสุดท้าย, และป้องกันการลบบัญชี Local Admin ฉุกเฉินหลัก
  * การบันทึก Audit Accountability: ระบุตัวตนของผู้ดูแลที่เป็นผู้กระทำการจริงในทุกกิจกรรมของหน้า Audit Logs
* **Authentication & Security Audit:** รองรับการยืนยันตัวตนผ่าน Active Directory / LDAP พร้อม Fallback Local Admin และเก็บบันทึก Web Audit Logs ทุกกิจกรรมลง SQLite (WAL Mode)

### เอกสารที่เกี่ยวข้อง

* [DEPLOYMENT_IIS.md](DEPLOYMENT_IIS.md): คู่มือการติดตั้งบน Windows Server โดยรันผ่าน IIS อย่างละเอียด พร้อมสคริปต์ PowerShell ติดตั้งอัตโนมัติ และขั้นตอนการอัปเกรดเวอร์ชัน
* [AGENT.md](AGENT.md): คู่มือมาตรฐานสถาปัตยกรรม, Security Guardrails, มาตรฐานระบบ 2 ภาษา และแนวปฏิบัติสำหรับนักพัฒนาและ AI Agent

### คำสั่งเริ่มต้นสำหรับการพัฒนา

```powershell
# Restore & Build Project
dotnet build OpensshUI.csproj

# Build with Roslyn Analyzers & Code Style Verification
dotnet build OpensshUI.csproj --no-restore /p:EnforceCodeStyleInBuild=true

# Run Automated Test Suite
dotnet test OpensshUI.Tests\OpensshUI.Tests.csproj

# Run Web Application (Development Mode)
dotnet run --project OpensshUI.csproj

# Publish สำหรับนำไปติดตั้งหรืออัปเกรดบน Server
dotnet publish OpensshUI.csproj -c Release -o ./publish
```
