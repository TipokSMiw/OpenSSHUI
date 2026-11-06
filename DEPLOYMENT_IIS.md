# คู่มือการติดตั้ง OpensshUI บน Windows Server ผ่าน IIS (รองรับ Drive D:)

คู่มือฉบับนี้อธิบายขั้นตอนการนำ **OpensshUI** ไปติดตั้งและเปิดให้บริการบน **Windows Server** โดยกำหนดค่าให้ติดตั้งและเก็บข้อมูลไว้ที่ **Drive D:** (เช่น `D:\inetpub\OpensshUI` และ `D:\SFTPRoot`) เพื่อทำหน้าที่เป็น Web Management Console สำหรับควบคุมและบริหารจัดการ Windows OpenSSH SFTP Server โดยรันอยู่ภายใต้ **Internet Information Services (IIS)**

---

## สารบัญ
1. [ภาพรวมสถาปัตยกรรมและโครงสร้าง Drive D:](#1-ภาพรวมสถาปัตยกรรมและโครงสร้าง-drive-d)
2. [Checklist สิ่งที่ต้องเตรียมล่วงหน้า](#2-checklist-สิ่งที่ต้องเตรียมล่วงหน้า)
3. [ขั้นตอนที่ 1: ติดตั้งและตั้งค่า Windows OpenSSH Server & ssh-agent](#ขั้นตอนที่-1-ติดตั้งและตั้งค่า-windows-openssh-server--ssh-agent)
4. [ขั้นตอนที่ 2: ติดตั้ง IIS และ WebSocket Protocol](#ขั้นตอนที่-2-ติดตั้ง-iis-และ-websocket-protocol)
5. [ขั้นตอนที่ 3: ติดตั้ง .NET 8 Hosting Bundle](#ขั้นตอนที่-3-ติดตั้ง-net-8-hosting-bundle)
6. [ขั้นตอนที่ 4: Publish แอปพลิเคชัน OpensshUI ลง Drive D:](#ขั้นตอนที่-4-publish-แอปพลิเคชัน-opensshui-ลง-drive-d)
7. [ขั้นตอนที่ 5: ติดตั้ง Website และ Application Pool บน IIS](#ขั้นตอนที่-5-ติดตั้ง-website-และ-application-pool-บน-iis)
8. [ขั้นตอนที่ 6: กำหนดสิทธิ์ NTFS Permissions บน Drive D:](#ขั้นตอนที่-6-กำหนดสิทธิ์-ntfs-permissions-บน-drive-d)
9. [ขั้นตอนที่ 7: การเข้าสู่ระบบและการตั้งค่าเริ่มต้น](#ขั้นตอนที่-7-การเข้าสู่ระบบและการตั้งค่าเริ่มต้น)
10. [การแก้ไขปัญหาที่พบบ่อย (Troubleshooting)](#10-การแก้ไขปัญหาที่พบบ่อย-troubleshooting)
11. [ภาคผนวก: สคริปต์ PowerShell สำหรับเตรียมระบบ Drive D: อัตโนมัติ](#11-ภาคผนวก-สคริปต์-powershell-สำหรับเตรียมระบบ-drive-d-อัตโนมัติ)

---

## 1. ภาพรวมสถาปัตยกรรมและโครงสร้าง Drive D:

การแยกโฟลเดอร์แอปพลิเคชันและพื้นที่จัดเก็บไฟล์ SFTP ไปไว้ที่ **Drive D:** เป็น Best Practice สำหรับงาน Production เพื่อป้องกันไม่ให้ข้อมูล SFTP หรือ Logs โตจนกินพื้นที่ของ Drive C: (OS Drive)

### โครงสร้างไดเรกทอรีที่แนะนำ:
* **Web Application:** `D:\inetpub\OpensshUI` (ตัวโค้ดเว็บและ SQLite Database ใน `app_data/`)
* **SFTP Storage Root:** `D:\SFTPRoot` (โฟลเดอร์ Chroot และไฟล์ของผู้ใช้ SFTP ทั้งหมด)
* **OpenSSH System Config:** `C:\ProgramData\ssh` (ตำแหน่ง Config, Backup `.bak`, และ Service มาตรฐานของ Windows OpenSSH)

```
[Web Browser / Admin]
        │
    (HTTPS / Port 443 หรือ HTTP / Port 8080)
        ▼
[IIS 10.0+ Web Server]
  └── Application Pool (Identity: LocalSystem หรือ Local Admin Account)
        └── ASP.NET Core Module v2 (.NET 8 Runtime)
              └── OpensshUI (Path: D:\inetpub\OpensshUI)
                    ├── จัดการ Local Windows Users (net.exe / AD)
                    ├── ควบคุม Windows Services (sshd, ssh-agent)
                    ├── ตรวจสอบไวยากรณ์และเขียนคอนฟิกแบบ Atomic (sshd.exe -t, rolling backups)
                    ├── จัดการสิทธิ์ NTFS ACLs บน D:\SFTPRoot (Strict Chroot)
                    └── SQLite DB (D:\inetpub\OpensshUI\app_data\sftp_admin.db)
```

> [!IMPORTANT]
> **ทำไม Application Pool Identity ต้องมีสิทธิ์ระดับ Local Administrator?**
> เนื่องจาก OpensshUI มีการโต้ตอบกับระบบปฏิบัติการโดยตรง ได้แก่ การสร้างและลบ Local Windows Users (`net user`), การจัดสรรสิทธิ์โฟลเดอร์ NTFS (`icacls`), และการสั่ง Start/Stop/Restart Service `sshd` และ `ssh-agent` หาก AppPool ไม่มีสิทธิ์ Admin ระบบจะไม่สามารถทำงานดังกล่าวได้

---

## 2. Checklist สิ่งที่ต้องเตรียมล่วงหน้า

- [ ] บัญชี Administrator บนเครื่อง Windows Server
- [ ] มี Drive `D:` พร้อมใช้งานและมีพื้นที่ว่างเพียงพอ
- [ ] ไฟล์ติดตั้ง [.NET 8.0 Hosting Bundle](https://dotnet.microsoft.com/download/dotnet/8.0)
- [ ] ติดตั้ง OpenSSH Server Feature บน Windows Server
- [ ] ติดตั้ง IIS และเปิด Feature WebSocket Protocol
- [ ] ไฟล์ Publish ของ OpensshUI

---

## ขั้นตอนที่ 1: ติดตั้งและตั้งค่า Windows OpenSSH Server & ssh-agent

เปิด **PowerShell ด้วยสิทธิ์ Administrator (Run as Administrator)** แล้วรันคำสั่ง:

```powershell
# 1. ตรวจสอบและติดตั้ง OpenSSH Server Feature
$sshCapability = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
if ($sshCapability.State -ne 'Installed') {
    Write-Host "กำลังติดตั้ง OpenSSH Server..."
    Add-WindowsCapability -Online -Name $sshCapability.Name
}

# 2. เริ่มต้น Services (sshd และ ssh-agent) พร้อมตั้งให้รันอัตโนมัติทุกครั้งที่เปิดเครื่อง
Set-Service -Name sshd -StartupType 'Automatic'
Start-Service sshd

Set-Service -Name ssh-agent -StartupType 'Automatic'
Start-Service ssh-agent

# 3. เปิดการบันทึก Windows Event Log Channel (OpenSSH/Operational) และให้สิทธิ์อ่าน Log แก่ IIS
wevtutil sl "OpenSSH/Operational" /e:true
wevtutil sl "OpenSSH/Operational" /ca:"O:BAG:SYD:(A;;0x2;;;S-1-15-2-1)(A;;0x2;;;S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x7;;;SO)(A;;0x3;;;IU)(A;;0x3;;;SU)(A;;0x3;;;S-1-5-3)(A;;0x3;;;S-1-5-33)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;AU)"

# 4. ตรวจสอบ Firewall Rule สำหรับ Port 22 (SSH/SFTP)
$rule = Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue
if (-not $rule) {
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH SSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
}

# 5. สร้างโฟลเดอร์หลักสำหรับ SFTP บน Drive D:
New-Item -ItemType Directory -Path "D:\SFTPRoot" -Force
```

---

## ขั้นตอนที่ 2: ติดตั้ง IIS และ WebSocket Protocol

Blazor Server สื่อสารแบบ Two-way Real-time กับเบราว์เซอร์ผ่าน SignalR ซึ่งจำเป็นต้องเปิดใช้งาน **WebSocket Protocol** ใน IIS:

```powershell
# ติดตั้ง IIS พร้อม WebSocket Protocol และเครื่องมือจัดการ
Install-WindowsFeature -Name Web-Server, Web-WebSockets, Web-Mgmt-Tools -IncludeManagementTools
```

---

## ขั้นตอนที่ 3: ติดตั้ง .NET 8 Hosting Bundle

1. ดาวน์โหลด **.NET 8.0 Hosting Bundle** (เลือกเวอร์ชัน Windows Hosting Bundle เช่น `dotnet-hosting-8.0.x-win.exe`)
2. รันไฟล์ติดตั้งบน Windows Server แล้วกด Install จนเสร็จสมบูรณ์
3. สั่ง Restart IIS เพื่อให้ IIS โหลดโมดูล `AspNetCoreModuleV2`:
   ```powershell
   net stop was /y
   net start w3svc
   ```
4. ตรวจสอบความถูกต้องโดยรันคำสั่ง:
   ```powershell
   Get-ChildItem "$env:SystemRoot\system32\inetsrv" -Filter "aspnetcore*.dll"
   ```
   (จะต้องพบไฟล์ เช่น `aspnetcorev2.dll`)

---

## ขั้นตอนที่ 4: Publish แอปพลิเคชัน OpensshUI ลง Drive D:

ที่เครื่องสำหรับพัฒนา (หรือเครื่องที่ติดตั้ง .NET 8 SDK) รันคำสั่ง Publish เพื่อเตรียมชุดไฟล์สำหรับ Deploy:

```powershell
# รันคำสั่ง Publish ในระดับโฟลเดอร์โปรเจกต์ OpensshUI
dotnet publish OpensshUI.csproj -c Release -o D:\publish\OpensshUI
```

จากนั้น:
1. คัดลอกชุดไฟล์ที่ Publish ไปวางไว้ที่ปลายทางบน Windows Server:
   `D:\inetpub\OpensshUI`
2. เปิดไฟล์ `D:\inetpub\OpensshUI\appsettings.json` และกำหนดค่า Path ของ `SftpRoot` ให้ชี้ไปที่ `D:\SFTPRoot`:
   ```json
   {
     "Logging": {
       "LogLevel": {
         "Default": "Information",
         "Microsoft.AspNetCore": "Warning"
       }
     },
     "AllowedHosts": "*",
     "ConnectionStrings": {
       "DefaultConnection": "Data Source=app_data/sftp_admin.db"
     },
     "SftpSettings": {
       "SftpRoot": "D:\\SFTPRoot",
       "KeysPath": "C:\\ProgramData\\ssh\\keys",
       "SshdConfigPath": "C:\\ProgramData\\ssh\\sshd_config"
     }
   }
   ```
   *(หมายเหตุ: เครื่องหมาย Backslash ใน JSON ต้องใส่เป็นดับเบิ้ล `\\` เช่น `D:\\SFTPRoot`)*

### 4.2 ขั้นตอนการอัปเดตเวอร์ชันใหม่ (Upgrade / Patch Existing Deployment)

เมื่อมีการแก้ไขโค้ดหรือเพิ่มฟีเจอร์ใหม่บนเครื่องพัฒนา ให้ปฏิบัติตามขั้นตอนการอัปเดตบน Server ดังนี้:

1. **Publish โค้ดใหม่:**
   ```powershell
   dotnet publish OpensshUI.csproj -c Release -o ./publish
   ```
2. **หยุด IIS ชั่วคราว (เพื่อไม่ให้ไฟล์ DLL ถูกล็อกขณะคัดลอก):**
   ```powershell
   iisreset /stop
   ```
3. **คัดลอกไฟล์ไปวางทับ:**
   คัดลอกไฟล์ทั้งหมดจากโฟลเดอร์ `publish/` ไปวางทับใน `D:\inetpub\OpensshUI`
   > [!CAUTION]
   > **ห้ามลบหรือเขียนทับโฟลเดอร์ `app_data/`:**
   > ในไดเรกทอรี `D:\inetpub\OpensshUI\app_data/` จะมีฐานข้อมูล SQLite (`sftp_admin.db`) และคีย์ถอดรหัสของ ASP.NET Data Protection (`dp_keys/`) อยู่ หากเขียนทับ ข้อมูลผู้ใช้และรหัสผ่าน LDAP ที่บันทึกไว้จะสูญหาย
4. **เปิดการทำงานของ IIS อีกครั้ง:**
   ```powershell
   iisreset /start
   ```

---

## ขั้นตอนที่ 5: ติดตั้ง Website และ Application Pool บน IIS

### 5.1 สร้าง Application Pool

1. เปิด **IIS Manager** (`inetmgr`)
2. คลิกที่ **Application Pools** ในแถบซ้ายมือ
3. ในแถบ Actions ด้านขวา คลิก **Add Application Pool...**
   * **Name:** `OpensshUIPool`
   * **.NET CLR version:** เลือก **No Managed Code** *(สำคัญมาก)*
   * **Managed pipeline mode:** เลือก **Integrated**
   * คลิก **OK**

4. คลิกขวาที่ `OpensshUIPool` ที่เพิ่งสร้าง -> เลือก **Advanced Settings...**
   * **Process Model -> Identity:**
     * เลือก `Built-in account` เป็น **LocalSystem** *(แนะนำ)* 
     * หรือเลือก `Custom account` เป็น Service Account ที่เป็นสมาชิกของกลุ่ม **Administrators** บนเครื่อง
   * **Process Model -> Idle Time-out (minutes):** เปลี่ยนเป็น **`0`** (เพื่อไม่ให้ Blazor Server ถูกตัด Session เมื่อไม่มีผู้ใช้งานไประยะหนึ่ง)
   * **Process Model -> Load User Profile:** ตั้งค่าเป็น **`True`** (เพื่อให้ .NET Data Protection ใช้งานได้สมบูรณ์)
   * คลิก **OK**

### 5.2 สร้าง Website

1. ใน IIS Manager คลิกขวาที่ **Sites** -> เลือก **Add Website...**
   * **Site name:** `OpensshUI`
   * **Application pool:** เลือก `OpensshUIPool`
   * **Physical path:** ระบุ **`D:\inetpub\OpensshUI`**
   * **Binding:**
     * Type: `http` (หรือ `https` หากมี SSL Certificate)
     * Port: เช่น `8080` (หรือ `443` สำหรับ HTTPS)
     * IP Address: `All Unassigned` (หรือระบุตามต้องการ)
   * คลิก **OK**

2. เปิดการอนุญาตให้เชื่อมต่อผ่าน Windows Firewall สำหรับ Port ของ Web UI:
   ```powershell
   New-NetFirewallRule -Name 'OpensshUI-HTTP' -DisplayName 'OpensshUI Web Console' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080
   ```

---

## ขั้นตอนที่ 6: กำหนดสิทธิ์ NTFS Permissions บน Drive D:

เพื่อให้ Application Pool สามารถอ่านและเขียนฐานข้อมูล SQLite ใน `app_data/`, สร้าง Directory Junctions และจัดการไฟล์ของผู้ใช้ใน `D:\SFTPRoot` ได้ถูกต้อง ให้กำหนดสิทธิ์ดังนี้:

```powershell
# ให้สิทธิ์ Full Control แก่ SYSTEM และ Administrators บนโฟลเดอร์แอปพลิเคชันใน Drive D:
icacls "D:\inetpub\OpensshUI" /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F" /T

# ให้สิทธิ์ Full Control บนโฟลเดอร์ SFTP Root ใน Drive D:
icacls "D:\SFTPRoot" /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F" /T

# ตรวจสอบและให้สิทธิ์โฟลเดอร์ C:\ProgramData\ssh สำหรับ SSH Keys, Config และ Rolling Backups
if (-not (Test-Path "C:\ProgramData\ssh\keys")) {
    New-Item -ItemType Directory -Path "C:\ProgramData\ssh\keys" -Force
}
icacls "C:\ProgramData\ssh" /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F" /T
```

---

## ขั้นตอนที่ 7: การเข้าสู่ระบบและการตั้งค่าเริ่มต้น

1. เปิดเว็บเบราว์เซอร์ไปที่: `http://<IP-Address-ของ-Server>:8080`
2. ระบบจะแสดงหน้า Login
3. เข้าสู่ระบบด้วย **Default Fallback Administrator Credentials**:
   * **Username:** `admin`
   * **Password:** `Admin@123456`
4. เมื่อเข้าสู่ระบบสำเร็จ:
   * ไปที่เมนู **Settings**
   * ทำการเปลี่ยนรหัสผ่าน Fallback Admin เป็นรหัสผ่านที่ปลอดภัยตามนโยบายองค์กรทันที
   * หากต้องการเชื่อมต่อกับ Domain Controller / Active Directory สามารถเปิดใช้งาน **LDAP Authentication** และระบุค่า Domain, Base DN, Bind Account และ Admin Group ได้ที่หน้านี้
   * ไปที่เมนู **บริการ OpenSSH (Service Controller)**:
     * ตรวจสอบสถานะการทำงานของบริการทั้ง `sshd` และ `ssh-agent`
     * คลิกปุ่ม **"ตรวจสอบเดี๋ยวนี้"** เพื่อรันคำสั่ง `sshd.exe -t` ยืนยันว่าไวยากรณ์ของ `sshd_config` ถูกต้องสมบูรณ์
     * ตรวจสอบส่วน **"โครงสร้าง Zero-Config Reload"** หากยังไม่ได้ติดตั้ง ให้กดปุ่ม **"ติดตั้งลง sshd_config"** เพื่อเปิดใช้งาน Chroot และ Centralized Authorized Keys (`C:\ProgramData\ssh\keys\%u`) สำหรับผู้ใช้กลุ่ม `SFTP-Users` ทำให้การเพิ่มผู้ใช้หลังจากนี้ไม่ต้อง Restart Service อีก
   * ไปที่เมนู **ผู้ดูแลระบบ (Web Admins)**:
     * สร้างบัญชีผู้ดูแลระบบส่วนบุคคล (Local Web Admin) หรือดึงบัญชีจาก Active Directory ผ่าน Live Search
     * กำหนดระดับสิทธิ์ (Role): `SuperAdmin`, `Operator` (สำหรับเจ้าหน้าที่ดูแล SFTP Users/Files), หรือ `Auditor` (สำหรับผู้ตรวจสอบระบบ ดูอย่างเดียว)
     * หลีกเลี่ยงการใช้บัญชี `admin` กลางร่วมกัน เพื่อให้บันทึกในหน้า Audit Logs ตรวจสอบย้อนหลังได้ชัดเจนรายบุคคล
   * ไปที่เมนู **Users** ทดลองสร้าง User ใหม่ และสังเกตว่า Home Directory ของ User จะถูกสร้างขึ้นภายใต้ `D:\SFTPRoot\<username>` โดยอัตโนมัติ พร้อมการจัดสรรสิทธิ์ NTFS ACLs ที่เข้มงวดตามมาตรฐาน OpenSSH Chroot

---

## 10. การแก้ไขปัญหาที่พบบ่อย (Troubleshooting)

### ปัญหาที่ 1: HTTP Error 500.19 - Internal Server Error
* **สาเหตุ:** ยังไม่ได้ติดตั้ง .NET 8 Hosting Bundle ทำให้ IIS ไม่เข้าใจ Tag `<aspNetCore>` ในไฟล์ `web.config`
* **วิธีแก้:** ติดตั้ง [.NET 8 Hosting Bundle](https://dotnet.microsoft.com/download/dotnet/8.0) แล้วรัน `net stop was /y` และ `net start w3svc`

### ปัญหาที่ 2: HTTP Error 500.30 - ASP.NET Core App Failed to Start
* **สาเหตุ:** แอปพลิเคชันเริ่มทำงานไม่สำเร็จ มักเกิดจากสิทธิ์การเข้าถึงโฟลเดอร์ `app_data` บน Drive D: หรือขาดไฟล์ Dependencies
* **วิธีดู Log:**
  1. เปิดไฟล์ `D:\inetpub\OpensshUI\web.config`
  2. เปลี่ยน `stdoutLogEnabled="false"` เป็น `stdoutLogEnabled="true"`
  3. สร้างโฟลเดอร์ `D:\inetpub\OpensshUI\logs`
  4. ลองรีเฟรชหน้าเว็บอีกครั้ง แล้วอ่าน Error message ที่ระบุในไฟล์ `logs\stdout_xxx.log`
  5. หรือตรวจสอบใน Windows **Event Viewer** -> **Windows Logs** -> **Application**

### ปัญหาที่ 3: Blazor Server หลุดบ่อย หรือขึ้นว่า "Reconnecting to the server..."
* **สาเหตุ:** ยังไม่ได้ติดตั้ง Feature **WebSocket Protocol** ใน IIS ทำให้ SignalR ต้องถอยไปใช้ Server-Sent Events หรือ Long Polling
* **วิธีแก้:** รัน `Install-WindowsFeature -Name Web-WebSockets` ใน PowerShell แล้ว Restart IIS

### ปัญหาที่ 4: สร้าง User ไม่ผ่าน / สั่ง Restart SSH Service ไม่ได้ (Access Denied)
* **สาเหตุ:** Application Pool Identity ไม่มีสิทธิ์ระดับ Local Administrator บนเครื่อง Server
* **วิธีแก้:** ตรวจสอบใน IIS Manager -> Application Pools -> `OpensshUIPool` -> Advanced Settings -> **Identity** ให้เปลี่ยนเป็น **LocalSystem** หรือระบุ Service Account ที่เป็น Local Admin

### ปัญหาที่ 5: หน้า "บันทึกเซิร์ฟเวอร์ (OpenSSH Logs)" ไม่แสดงข้อมูล หรือขึ้นเตือน Access Denied
* **สาเหตุ:**
  1. ยังไม่ได้เปิดใช้งาน Event Log Channel `OpenSSH/Operational` (Windows ปิดการบันทึกไว้เป็นค่าเริ่มต้น)
  2. บัญชีที่รัน Application Pool หรือ User ไม่มีสิทธิ์อ่าน Event Log ของ OpenSSH
* **วิธีแก้:** รันคำสั่งเปิด Channel และกำหนดสิทธิ์ SDDL ใน PowerShell (Run as Administrator):
  ```powershell
  wevtutil sl "OpenSSH/Operational" /e:true
  wevtutil sl "OpenSSH/Operational" /ca:"O:BAG:SYD:(A;;0x2;;;S-1-15-2-1)(A;;0x2;;;S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x7;;;SO)(A;;0x3;;;IU)(A;;0x3;;;SU)(A;;0x3;;;S-1-5-3)(A;;0x3;;;S-1-5-33)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;AU)"
  ```
  *(หรือหากใช้งานบนเครื่องพัฒนา สามารถคลิกปุ่ม **"จำลองข้อมูล (Demo Mode)"** บนหน้าเว็บเพื่อทดสอบการทำงานของระบบได้ทันที)*

### ปัญหาที่ 6: Restart Service ไม่ผ่านเนื่องจาก Syntax Error ใน sshd_config
* **สาเหตุ:** ไฟล์ `sshd_config` มี Directive หรือไวยากรณ์ที่ไม่ถูกต้อง
* **วิธีแก้:** เข้าหน้า **บริการ OpenSSH (Service Controller)** แล้วคลิกปุ่ม **"ตรวจสอบเดี๋ยวนี้"** เพื่อดูรายละเอียดข้อผิดพลาดที่ `sshd.exe -t` แจ้งเตือน ระบบมีไฟล์สำรองอัตโนมัติ (`sshd_config.bak.<timestamp>`) สูงสุด 5 ชุดอยู่ใน `C:\ProgramData\ssh\` ซึ่งสามารถนำมาใช้งานย้อนกลับได้ทันที

---

## 11. ภาคผนวก: สคริปต์ PowerShell สำหรับเตรียมระบบ Drive D: อัตโนมัติ

ท่านสามารถคัดลอกสคริปต์ด้านล่างนี้ บันทึกเป็น `Setup-OpensshUI-Host.ps1` แล้วรันบน Windows Server เพื่อเตรียมความพร้อมของ Environment บน **Drive D:** ทั้งหมดในคำสั่งเดียว:

```powershell
<#
.SYNOPSIS
    Automated Host Setup for OpensshUI on Windows Server (Drive D:)
#>

#Requires -RunAsAdministrator

$TargetDrive = "D:"
$AppDirectory = "$TargetDrive\inetpub\OpensshUI"
$SftpRootDirectory = "$TargetDrive\SFTPRoot"
$SshKeyDirectory = "C:\ProgramData\ssh\keys"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  OpensshUI - Windows Server Setup Script (Target: $TargetDrive) " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# ตรวจสอบการมีอยู่ของ Drive D:
if (-not (Test-Path "$TargetDrive\")) {
    Write-Error "ไม่พบไดรฟ์ $TargetDrive บนเครื่องนี้ กรุณาตรวจสอบก่อนรันสคริปต์"
    exit 1
}

# 1. ติดตั้ง Features ที่จำเป็น
Write-Host "`n[1/6] ติดตั้ง IIS และ Web-WebSockets..." -ForegroundColor Yellow
Install-WindowsFeature -Name Web-Server, Web-WebSockets, Web-Mgmt-Tools -IncludeManagementTools | Out-Null

# 2. ติดตั้ง OpenSSH Server และเปิดใช้งาน Services
Write-Host "[2/6] ติดตั้ง OpenSSH Server และเปิด sshd, ssh-agent..." -ForegroundColor Yellow
$ssh = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
if ($ssh.State -ne 'Installed') {
    Add-WindowsCapability -Online -Name $ssh.Name | Out-Null
}
Set-Service -Name sshd -StartupType 'Automatic'
Start-Service sshd -ErrorAction SilentlyContinue

Set-Service -Name ssh-agent -StartupType 'Automatic'
Start-Service ssh-agent -ErrorAction SilentlyContinue

# 3. เปิด Event Log Channel OpenSSH/Operational และกำหนดสิทธิ์ให้อ่านได้
Write-Host "[3/6] เปิดใช้งาน Event Log Channel (OpenSSH/Operational)..." -ForegroundColor Yellow
wevtutil sl "OpenSSH/Operational" /e:true | Out-Null
wevtutil sl "OpenSSH/Operational" /ca:"O:BAG:SYD:(A;;0x2;;;S-1-15-2-1)(A;;0x2;;;S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x7;;;SO)(A;;0x3;;;IU)(A;;0x3;;;SU)(A;;0x3;;;S-1-5-3)(A;;0x3;;;S-1-5-33)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;AU)" | Out-Null

# 4. จัดเตรียมโฟลเดอร์หลักบน Drive D: และ C:\ProgramData\ssh
Write-Host "[4/6] จัดเตรียมไดเรกทอรี $AppDirectory, $SftpRootDirectory, $SshKeyDirectory..." -ForegroundColor Yellow
$dirs = @($AppDirectory, $SftpRootDirectory, $SshKeyDirectory)
foreach ($d in $dirs) {
    if (-not (Test-Path $d)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }
}

# 5. ตั้งค่า Permissions
Write-Host "[5/6] กำหนดสิทธิ์ NTFS Permissions..." -ForegroundColor Yellow
icacls $AppDirectory /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F" /T | Out-Null
icacls $SftpRootDirectory /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F" /T | Out-Null
icacls "C:\ProgramData\ssh" /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F" /T | Out-Null

# 6. เปิด Firewall Rules
Write-Host "[6/6] เปิด Firewall สำหรับ SSH (Port 22) และ Web UI (Port 8080)..." -ForegroundColor Yellow
if (-not (Get-NetFirewallRule -Name "OpensshUI-Web-TCP" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'OpensshUI-Web-TCP' -DisplayName 'OpensshUI Web Console' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080 | Out-Null
}

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "  เตรียมระบบเบื้องต้นบนไดรฟ์ $TargetDrive สำเร็จเรียบร้อย!   " -ForegroundColor Green
Write-Host "  ขั้นตอนต่อไป:                                              " -ForegroundColor White
Write-Host "  1. ติดตั้ง .NET 8.0 Hosting Bundle                         " -ForegroundColor White
Write-Host "  2. นำไฟล์ที่ Publish มาวางที่ $AppDirectory                   " -ForegroundColor White
Write-Host "  3. ตรวจสอบไฟล์ appsettings.json ให้ SftpRoot เป็น $SftpRootDirectory" -ForegroundColor White
Write-Host "  4. สร้าง Application Pool (LocalSystem) และ Website บน IIS " -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Green
```
