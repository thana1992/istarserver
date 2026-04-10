# iStar Class Management System - เอกสารประกอบระบบ

## 📋 สารบัญ
1. [ภาพรวมของระบบ](#ภาพรวมของระบบ)
2. [สถาปัตยกรรมระบบ](#สถาปัตยกรรมระบบ)
3. [ฟีเจอร์หลักของระบบ](#ฟีเจอร์หลักของระบบ)
4. [โครงสร้างฐานข้อมูล](#โครงสร้างฐานข้อมูล)
5. [API Endpoints](#api-endpoints)
6. [การตั้งค่าและติดตั้ง](#การตั้งค่าและติดตั้ง)
7. [การรักษาความปลอดภัย](#การรักษาความปลอดภัย)
8. [การทำงานของระบบ](#การทำงานของระบบ)

---

## 🎯 ภาพรวมของระบบ

### วัตถุประสงค์
ระบบ iStar Class Management System เป็นระบบจัดการคลาสเรียนแบบครบวงจร ที่ออกแบบมาเพื่อจัดการ:
- การลงทะเบียนและจัดการข้อมูลนักเรียน
- การจองและจัดการตารางเรียน
- การจัดการคอร์สเรียนและแพ็คเกจ
- การติดตามการเข้าเรียนและยอดคงเหลือ
- การอัปโหลดและจัดเก็บรูปภาพ

### ผู้ใช้งานหลัก
1. **Admin** - ผู้ดูแลระบบ (สิทธิ์เต็ม)
   - จัดการนักเรียน, คอร์ส, คลาส
   - อนุมัติการลงทะเบียนนักเรียนใหม่
   - จัดการการจองและยกเลิกการจอง
   - ตรวจสอบรายงานและสถิติ

2. **Customer** - ผู้ปกครอง/นักเรียน
   - จองคลาสเรียน
   - ดูข้อมูลนักเรียนในครอบครัว
   - ตรวจสอบคอร์สและยอดคงเหลือ
   - อัปโหลดรูปโปรไฟล์

### เทคโนโลยีที่ใช้
- **Backend Framework**: Express.js (Node.js)
- **Database**: MySQL (mysql2 with connection pool)
- **Authentication**: JWT (JSON Web Tokens)
- **File Storage**: DigitalOcean Spaces (S3-compatible)
- **Logging**: Winston + Morgan
- **Notification**: Discord Webhooks
- **OTP Service**: Twilio
- **Others**: 
  - Bcrypt (password hashing)
  - Moment.js (date/time handling)
  - Multer (file upload)
  - Node-cron (scheduled tasks)

---

## 🏗️ สถาปัตยกรรมระบบ

### System Architecture

```
┌─────────────────┐
│   Client Apps   │
│  (Web/Mobile)   │
└────────┬────────┘
         │ HTTP/HTTPS
         │ (REST API)
         ▼
┌─────────────────┐
│  Express.js     │
│  API Server     │
│  (Port 3000)    │
└────┬───┬────┬───┘
     │   │    │
     │   │    └──────────────┐
     │   │                   │
     ▼   ▼                   ▼
┌─────────┐  ┌──────────┐  ┌──────────────┐
│  MySQL  │  │   S3     │  │   Discord    │
│Database │  │ (Spaces) │  │   Webhooks   │
└─────────┘  └──────────┘  └──────────────┘
                              ▲
                              │
                         ┌────┴─────┐
                         │  Twilio  │
                         │   (OTP)  │
                         └──────────┘
```

### Database Connection Pool
- **Connection Limit**: 30 connections
- **Host**: ตามค่า environment variable
- **Port**: ตามค่า environment variable
- **Auto-reconnect**: Enabled

### File Storage Structure
```
istar (Bucket)
├── profile_images/
│   └── {studentid}_{timestamp}.{ext}
├── slip_customer_course/
│   └── {courserefer}.{ext}
└── logs/
    └── {SERVER_TYPE}-{date}.log
```

---

## ✨ ฟีเจอร์หลักของระบบ

### 1. 🔐 ระบบ Authentication & Authorization
- **Registration**
  - สมัครสมาชิกด้วย username, password, email, mobile
  - ระบบตรวจสอบรหัสลงทะเบียน (registercode)
  - เข้ารหัสรหัสผ่านด้วย bcrypt
  - สร้าง familyid อัตโนมัติ

- **Login/Logout**
  - ตรวจสอบ credentials
  - สร้าง JWT token (expires in 24h)
  - จัดการ active sessions
  - Blacklist tokens เมื่อ logout

- **Token Verification**
  - Middleware ตรวจสอบ JWT ทุก protected endpoints
  - ตรวจสอบ blacklist
  - Verify admin flag

### 2. 👨‍👩‍👧‍👦 ระบบจัดการครอบครัวและนักเรียน

#### การจัดการนักเรียน
- **เพิ่มนักเรียน** (Customer)
  - เก็บข้อมูลในตาราง `jstudent` (รอการอนุมัติ)
  - ส่ง notification ไป Discord

- **อนุมัตินักเรียน** (Admin)
  - ย้ายข้อมูลจาก `jstudent` ไป `tstudent`
  - สร้าง studentid อัตโนมัติ
  - เชื่อมโยงกับ familyid

- **แก้ไขข้อมูลนักเรียน** (Admin)
  - อัปเดตข้อมูลส่วนตัว
  - จัดการ courserefer (เปลี่ยนคอร์ส)
  - ระบบตรวจสอบ Course Sharing

- **ลบนักเรียน**
  - Soft delete (set delflag = 1)
  - ลบข้อมูลจาก journal table (hard delete)

#### ข้อมูลนักเรียน
- ชื่อ-นามสกุล (firstname, middlename, lastname)
- ชื่อเล่น (nickname)
- เพศ (gender)
- วันเกิด (dateofbirth)
- ระดับ (level)
- รูปโปรไฟล์ (profile_image, profile_image_url)
- Course reference (courserefer, courserefer2)

### 3. 📅 ระบบจัดการการจอง (Booking/Reservation)

#### การจองคลาส - Customer
```
Flow:
1. เลือกวันและคลาส
2. ตรวจสอบที่นั่งว่าง
3. ตรวจสอบการจองซ้ำ
4. ตรวจสอบยอดคงเหลือในคอร์ส
5. สร้างการจอง
6. หักยอดคงเหลือ
7. ส่ง notification
```

**Features:**
- ตรวจสอบ duplicate reservation
- ตรวจสอบ maxperson
- รองรับการเรียนฟรี (freeflag)
- Course Sharing (นักเรียนหลายคนใช้คอร์สร่วมกัน)

#### การจองคลาส - Admin
- สามารถจองได้แม้ที่นั่งเต็ม
- สามารถจองคลาสที่ปิดสำหรับ customer
- สามารถตั้งค่าเรียนฟรี

#### การแก้ไขการจอง
- แก้ไขวัน/เวลา/คลาส
- ตรวจสอบการจองซ้ำ
- ปรับยอดคงเหลือตามการเปลี่ยนแปลง
- คืนยอดเดิม + หักยอดใหม่

#### การยกเลิกการจอง
- ลบข้อมูลการจอง
- คืนยอดคงเหลือ (ถ้าไม่ใช่เรียนฟรี)
- บันทึก log

#### Check-in/Undo Check-in
- อัปเดต status checkin
- บันทึกเวลา check-in
- รองรับการยกเลิก check-in

### 4. 📚 ระบบจัดการคอร์สและคลาส

#### Course Management
- **เพิ่ม/แก้ไข/ลบคอร์ส**
- ข้อมูล:
  - courseid (Primary Key)
  - coursename
  - course_shortname
  - enableflag

#### Class Management  
- **เพิ่ม/แก้ไข/ลบคลาส**
- ข้อมูล:
  - classid (Primary Key)
  - courseid
  - classday (วันในสัปดาห์)
  - classtime (เวลา)
  - maxperson (จำนวนที่นั่ง)
  - adminflag (คลาสสำหรับ admin เท่านั้น)
  - startdate/enddate (ช่วงเวลาที่เปิดคลาส)

#### Class Time Availability
- ตรวจสอบที่นั่งว่าง
- คำนวณ available = maxperson - จำนวนที่จอง
- รองรับ Class Disable (ปิดคลาสชั่วคราว)

### 5. 💳 ระบบจัดการแพ็คเกจคอร์ส (Customer Course)

#### ข้อมูลแพ็คเกจ
- courserefer (Unique Reference)
- courseid
- total (จำนวนครั้งทั้งหมด)
- remaining (จำนวนครั้งคงเหลือ)
- expiredate (วันหมดอายุ)
- slip_image_url (รูปสลิปการชำระเงิน)
- share_amount (จำนวนคนที่แชร์)
- finish (สถานะจบแพ็คเกจ)

#### การเพิ่มแพ็คเกจ
1. สร้าง courserefer อัตโนมัติ
2. อัปโหลดสลิปชำระเงินไป S3
3. บันทึกข้อมูลลง database
4. ส่ง notification

#### การแก้ไขแพ็คเกจ
- แก้ไขข้อมูลทั่วไป
- เปลี่ยนสลิป (upload ใหม่)
- ป้องกันการลบถ้ามีการใช้งานแล้ว

#### การลบแพ็คเกจ
- ตรวจสอบการใช้งาน
- ลบรูปสลิปจาก S3
- ลบข้อมูลจาก database

#### การจบแพ็คเกจ
- ตั้งค่า finish = 1
- ย้ายนักเรียนออกจากแพ็คเกจ

### 6. 📸 ระบบจัดการรูปภาพ

#### Profile Image Upload
```
Flow:
1. รับไฟล์จาก client (multer)
2. ตรวจสอบนามสกุลไฟล์
3. สร้าง unique filename
4. อัปโหลดไป S3 (DigitalOcean Spaces)
5. บันทึก URL ลง database
6. ลบไฟล์ temporary
7. (Optional) ลบรูปเก่าจาก S3
```

**Supported Formats**: jpg, jpeg, png, gif
**Storage Path**: `profile_images/{studentid}_{timestamp}.{ext}`
**ACL**: public-read

#### Slip Image Upload
**Storage Path**: `slip_customer_course/{courserefer}.{ext}`
**Auto-rename**: ถ้าชื่อซ้ำจะเพิ่ม _{index}

### 7. 📱 ระบบ OTP (One-Time Password)

#### Twilio Integration
- ส่ง OTP ผ่าน SMS
- Verify OTP code
- Format phone number (รองรับรูปแบบไทย)

#### OTP Endpoints
- `POST /request-otp` - ขอรหัส OTP
- `POST /verify-otp` - ยืนยันรหัส OTP
- `POST /checkmobileno` - ตรวจสอบเบอร์โทรศัพท์

### 8. 🗓️ ระบบจัดการวันหยุด (Holiday Management)

#### Features
- เพิ่ม/แก้ไข/ลบวันหยุด
- ดึงข้อมูลวันหยุดจาก Google Calendar API
- ใช้ในการคำนวณวันจอง

### 9. 📊 Dashboard & Reports

#### Dashboard Cards
- จำนวนนักเรียนทั้งหมด
- จำนวนการจองวันนี้
- จำนวนการจองพรุ่งนี้
- จำนวนนักเรียนใหม่รออนุมัติ
- จำนวนการจองรอยกเลิก

#### Reports
- รายการนักเรียน (active/inactive)
- รายการการจอง
- รายการแพ็คเกจคอร์ส
- ประวัติการจอง

### 10. 🔔 ระบบ Notification (Discord Webhook)

#### การแจ้งเตือนแบ่งตาม Channel
- **System** - เหตุการณ์ระบบทั่วไป
- **Login** - การ login/logout
- **Booking** - การจอง/ยกเลิก/แก้ไข
- **Course** - การจัดการคอร์ส/แพ็คเกจ
- **Student** - การจัดการนักเรียน
- **Error** - ข้อผิดพลาด
- **API Call** - Log API calls

#### Queue System
- ป้องกัน rate limit ของ Discord
- จัดการคิวแยกตาม webhook URL
- ประมวลผลทีละข้อความ

### 11. 📝 ระบบ Logging

#### Winston Logger
- บันทึก log ลงไฟล์รายวัน
- Format: `{timestamp} {level}: {message}`
- Timezone: Asia/Bangkok
- Auto-rotate daily

#### Morgan HTTP Logger
- บันทึก HTTP requests/responses
- Combined format
- Append to log file

#### Log Upload to S3
- อัปโหลด log file ทุก 55 นาที
- Auto-delete logs > 1 เดือน (จาก S3)
- Auto-delete logs > 3 วัน (local)

### 12. ⚙️ Scheduled Tasks

#### Auto-restart Server
- กำหนดรีสตาร์ทเวลา 01:30 น. ทุกวัน
- ป้องกัน memory leak

#### Log Upload
- อัปโหลด log ทุก 55 นาที
- ลบ log เก่าจาก S3 ทุกเดือน

---

## 📊 โครงสร้างฐานข้อมูล

### ตารางหลัก

#### 1. `tuser` - ตารางผู้ใช้งาน
```sql
- username (PK)
- password (hashed with bcrypt)
- firstname, middlename, lastname
- address
- email
- mobileno
- registercode
- adminflag
- acceptPrivacyPolicy
```

#### 2. `tfamily` - ตารางครอบครัว
```sql
- familyid (PK, auto-generated)
- username (FK -> tuser)
- createdate
- createby
```

#### 3. `tstudent` - ตารางนักเรียน (approved)
```sql
- studentid (PK, auto-generated)
- familyid (FK -> tfamily)
- firstname, middlename, lastname, nickname
- gender
- dateofbirth
- level
- courserefer (FK -> tcustomer_course)
- courserefer2 (FK -> tcustomer_course)
- profile_image, profile_image_url
- delflag
- shortnote
- createdate, updatedate
- createby, updateby
```

#### 4. `jstudent` - ตารางนักเรียนรออนุมัติ (journal)
```sql
- (โครงสร้างเหมือน tstudent)
- ใช้เก็บข้อมูลก่อนอนุมัติ
```

#### 5. `tcourseinfo` - ตารางข้อมูลคอร์ส
```sql
- courseid (PK, auto-increment)
- coursename
- course_shortname
- enableflag
```

#### 6. `tclassinfo` - ตารางข้อมูลคลาส
```sql
- classid (PK, auto-increment)
- courseid (FK -> tcourseinfo)
- classday (วันในสัปดาห์: Monday, Tuesday, ...)
- classtime (เวลา: HH:MM)
- maxperson
- adminflag
- startdate, enddate
- enableflag
```

#### 7. `tclassdisable` - ตารางปิดคลาสชั่วคราว
```sql
- classid (FK -> tclassinfo)
- classdate
- courseid
- description
```

#### 8. `tcustomer_course` - ตารางแพ็คเกจคอร์ส
```sql
- courserefer (PK, auto-generated: YYYYMMDD-HHMMSS-RANDOM)
- courseid (FK -> tcourseinfo)
- coursename
- total (จำนวนครั้งทั้งหมด)
- remaining (จำนวนครั้งคงเหลือ)
- expiredate
- slip_image, slip_image_url
- share_amount
- finish
- createdate, updatedate
- createby, updateby
```

#### 9. `treservation` - ตารางการจอง
```sql
- reservationid (PK, auto-increment)
- studentid (FK -> tstudent)
- classid (FK -> tclassinfo)
- classdate
- classtime
- courseid (FK -> tcourseinfo)
- courserefer (FK -> tcustomer_course)
- freeflag
- checkin
- checkin_datetime
- createdate, updatedate
- createby, updateby
```

#### 10. `jreservation` - ตารางการจองรอยกเลิก
```sql
- (โครงสร้างเหมือน treservation)
- ใช้เก็บรายการที่รอการยกเลิก
```

#### 11. `tholidays` - ตารางวันหยุด
```sql
- id (PK, auto-increment)
- date
- description
- type
```

### Relationships

```
tuser (1) ----< (M) tfamily
tfamily (1) ----< (M) tstudent
tcourseinfo (1) ----< (M) tclassinfo
tcourseinfo (1) ----< (M) tcustomer_course
tcustomer_course (1) ----< (M) tstudent (via courserefer)
tstudent (1) ----< (M) treservation
tclassinfo (1) ----< (M) treservation
```

---

## 🔌 API Endpoints

### Authentication & User Management

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/login` | เข้าสู่ระบบ | ❌ |
| POST | `/logout` | ออกจากระบบ | ✅ |
| POST | `/register` | ลงทะเบียนผู้ใช้ใหม่ | ❌ |
| POST | `/verifyToken` | ตรวจสอบ token | ✅ |
| GET | `/checkToken` | ตรวจสอบ active sessions | ❌ |
| POST | `/change-password` | เปลี่ยนรหัสผ่าน | ✅ |

### Family & Student Management

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/getFamilyMember` | ดูสมาชิกในครอบครัว | ✅ |
| POST | `/getFamilyList` | ดูรายชื่อครอบครัว | ✅ |
| GET | `/getNewStudentList` | ดูนักเรียนใหม่รออนุมัติ | ✅ Admin |
| GET | `/getStudentList` | ดูรายชื่อนักเรียนทั้งหมด | ✅ |
| GET | `/getStudentInfo/:studentid` | ดูข้อมูลนักเรียน | ✅ |
| POST | `/addStudent` | เพิ่มนักเรียน (Customer) | ✅ |
| POST | `/approveNewStudent` | อนุมัตินักเรียนใหม่ | ✅ Admin |
| POST | `/addStudentByAdmin` | เพิ่มนักเรียน (Admin) | ✅ Admin |
| POST | `/updateStudentByAdmin` | แก้ไขข้อมูลนักเรียน | ✅ Admin |
| POST | `/deleteStudent` | ลบนักเรียน | ✅ |
| POST | `/uploadProfileImage` | อัปโหลดรูปโปรไฟล์ | ✅ |
| GET | `/student/:studentid/profile-image` | ดูรูปโปรไฟล์ | ✅ |

### Booking & Reservation Management

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/addBookingByCustomer` | จองคลาส (Customer) | ✅ |
| POST | `/addBookingByAdmin` | จองคลาส (Admin) | ✅ Admin |
| POST | `/updateBookingByAdmin` | แก้ไขการจอง | ✅ Admin |
| POST | `/cancelBookingByAdmin` | ยกเลิกการจอง | ✅ Admin |
| POST | `/deleteReservation` | ลบการจอง | ✅ |
| POST | `/checkDuplicateReservation` | ตรวจสอบการจองซ้ำ | ✅ |
| POST | `/getReservationList` | ดูรายการจอง | ✅ |
| POST | `/getBookingList` | ดูรายการจอง (Customer) | ✅ |
| POST | `/getBookingListAdmin` | ดูรายการจอง (Admin) | ✅ Admin |
| POST | `/checkinByAdmin` | Check-in | ✅ Admin |
| POST | `/undoCheckinByAdmin` | Undo Check-in | ✅ Admin |

### Course Management

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/getAllCourses` | ดูคอร์สทั้งหมด | ✅ |
| GET | `/courseLookup` | ค้นหาคอร์ส (active) | ✅ |
| POST | `/addCourse` | เพิ่มคอร์ส | ✅ Admin |
| POST | `/updateCourse` | แก้ไขคอร์ส | ✅ Admin |
| POST | `/deleteCourse` | ลบคอร์ส | ✅ Admin |

### Class Management

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/getAllClasses` | ดูคลาสทั้งหมด | ✅ |
| POST | `/getClassTime` | ดูเวลาคลาสที่ว่าง | ✅ |
| POST | `/addClass` | เพิ่มคลาส | ✅ Admin |
| POST | `/updateClass` | แก้ไขคลาส | ✅ Admin |
| POST | `/deleteClass` | ลบคลาส | ✅ Admin |

### Customer Course (Package) Management

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/customerCourseLookup` | ค้นหาแพ็คเกจ (active) | ✅ |
| GET | `/getCustomerCourseLookup` | ดูแพ็คเกจทั้งหมด | ✅ |
| POST | `/getCustomerCourseList` | ดูรายการแพ็คเกจ | ✅ |
| POST | `/getFinishedCustomerCourseList` | ดูแพ็คเกจที่จบแล้ว | ✅ |
| GET | `/getFinishedCourse` | ดูคอร์สที่จบแล้ว | ✅ |
| POST | `/getCustomerCourseInfo` | ดูข้อมูลแพ็คเกจ | ✅ |
| GET | `/getStudentCourseDetail/:courserefer` | ดูรายละเอียดแพ็คเกจ | ✅ |
| POST | `/addCustomerCourse` | เพิ่มแพ็คเกจ | ✅ Admin |
| POST | `/updateCustomerCourse` | แก้ไขแพ็คเกจ | ✅ Admin |
| POST | `/deleteCustomerCourse` | ลบแพ็คเกจ | ✅ Admin |
| POST | `/checkBeforeDeleteCustomerCourse` | ตรวจสอบก่อนลบแพ็คเกจ | ✅ Admin |
| POST | `/finishCustomerCourse` | จบแพ็คเกจ | ✅ Admin |
| POST | `/uploadSlipImage` | อัปโหลดสลิปชำระเงิน | ✅ |
| GET | `/customer_course/:courserefer/slip-image` | ดูสลิปชำระเงิน | ✅ |

### Lookups & Utilities

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/familyLookup` | ค้นหาครอบครัว | ✅ |
| POST | `/studentLookup` | ค้นหานักเรียน | ✅ |
| POST | `/getMemberInfo` | ดูข้อมูลสมาชิก | ✅ |
| POST | `/getMemberReservationDetail` | ดูรายละเอียดการจอง | ✅ |
| POST | `/refreshCardDashboard` | รีเฟรช dashboard | ✅ |

### Holiday Management

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/collectHolidays` | ดึงข้อมูลวันหยุดจาก Google | ✅ Admin |
| GET | `/holidaysList` | ดูรายการวันหยุด | ✅ |
| POST | `/getHolidayInformation` | ดูข้อมูลวันหยุด | ✅ |
| POST | `/holidays` | เพิ่มวันหยุด | ✅ Admin |
| PUT | `/holidays/:id` | แก้ไขวันหยุด | ✅ Admin |
| DELETE | `/holidays/:id` | ลบวันหยุด | ✅ Admin |

### OTP & Phone Verification

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/request-otp` | ขอรหัส OTP | ❌ |
| POST | `/verify-otp` | ยืนยันรหัส OTP | ❌ |
| POST | `/checkmobileno` | ตรวจสอบเบอร์โทรศัพท์ | ❌ |

---

## ⚙️ การตั้งค่าและติดตั้ง

### Environment Variables (.env)

```env
# Server Configuration
SERVER_TYPE=v1-server
PORT=3000

# Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_NAME=istar_db
DB_USER=root
DB_PASSWORD=your_password

# JWT Secret
SECRET_KEY=your_secret_key_here

# DigitalOcean Spaces (S3)
DO_SPACES_KEY=your_spaces_key
DO_SPACES_SECRET=your_spaces_secret

# Twilio (OTP)
TWILIO_ACCOUNT_SID=your_twilio_sid
TWILIO_AUTH_TOKEN=your_twilio_token

# Discord Webhooks
DISCORD_INFO_WEBHOOK_URL=https://discord.com/api/webhooks/...
DISCORD_ERROR_WEBHOOK_URL=https://discord.com/api/webhooks/...
DISCORD_BOOKING_WEBHOOK_URL=https://discord.com/api/webhooks/...
DISCORD_COURSE_WEBHOOK_URL=https://discord.com/api/webhooks/...
DISCORD_LOGIN_WEBHOOK_URL=https://discord.com/api/webhooks/...
DISCORD_STUDENT_WEBHOOK_URL=https://discord.com/api/webhooks/...
DISCORD_APICALL_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

### ติดตั้ง Dependencies

```bash
npm install
```

### สร้างฐานข้อมูล

```sql
-- สร้างฐานข้อมูล
CREATE DATABASE istar_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- สร้างตารางตาม schema ที่กำหนด (ดูในส่วน Database Structure)
```

### รันระบบ

```bash
# Development
node server.js

# Production (with PM2)
pm2 start server.js --name istar-api
```

---

## 🔒 การรักษาความปลอดภัย

### 1. Password Security
- ใช้ **bcrypt** เข้ารหัสรหัสผ่าน (salt rounds: 10)
- ไม่เก็บ plain text password

### 2. JWT Authentication
- Token expires: 24 ชั่วโมง
- Secret key จาก environment variable
- Blacklist system สำหรับ logout

### 3. Authorization Middleware
- ตรวจสอบ token ทุก protected endpoints
- แยก admin endpoints ด้วย adminflag

### 4. Input Validation
- ตรวจสอบ required fields
- ป้องกัน SQL injection ด้วย parameterized queries
- Sanitize user input

### 5. CORS Configuration
- อนุญาต origin ที่กำหนด
- กำหนด methods ที่อนุญาต
- รองรับ credentials

### 6. File Upload Security
- จำกัดประเภทไฟล์ (jpg, jpeg, png, gif)
- ใช้ unique filename
- เก็บไฟล์บน cloud storage (S3)
- ลบ temporary files

### 7. Rate Limiting
- Discord webhook ใช้ queue system
- ป้องกัน DoS

### 8. Error Handling
- ไม่ expose sensitive information
- Log errors ไป Discord
- Return generic error messages

---

## 🔄 การทำงานของระบบ

### Flow: การจองคลาส (Customer)

```
1. Customer login ด้วย username/password
   ├─> ระบบตรวจสอบ credentials
   ├─> สร้าง JWT token
   └─> Return token + user info

2. ดูรายชื่อนักเรียนในครอบครัว (getFamilyMember)
   ├─> ดูข้อมูลนักเรียน + คอร์สที่มี
   └─> เลือกนักเรียนที่จะจอง

3. เลือกวันที่และดูเวลาที่ว่าง (getClassTime)
   ├─> ระบบคำนวณที่นั่งว่าง
   ├─> ตรวจสอบ class disable
   └─> Return รายการเวลาที่ว่าง

4. จองคลาส (addBookingByCustomer)
   ├─> ตรวจสอบการจองซ้ำ
   ├─> ตรวจสอบที่นั่งว่าง
   ├─> ตรวจสอบยอดคงเหลือในคอร์ส
   ├─> ตรวจสอบวันหมดอายุ
   ├─> สร้างการจอง
   ├─> หักยอดคงเหลือ
   ├─> ส่ง notification ไป Discord
   └─> Return success

5. ดูรายการจอง (getBookingList)
   └─> แสดงรายการจองที่กำลังจะมาถึง
```

### Flow: การอนุมัตินักเรียนใหม่ (Admin)

```
1. Customer เพิ่มนักเรียน (addStudent)
   ├─> บันทึกข้อมูลลง jstudent
   ├─> ส่ง notification ไป Discord
   └─> Return success

2. Admin ดูรายการนักเรียนรออนุมัติ (getNewStudentList)
   └─> แสดงรายการจาก jstudent

3. Admin อนุมัตินักเรียน (approveNewStudent)
   ├─> สร้าง studentid ใหม่
   ├─> Copy ข้อมูลจาก jstudent ไป tstudent
   ├─> ลบข้อมูลจาก jstudent
   ├─> ส่ง notification ไป Discord
   └─> Return success
```

### Flow: การจัดการแพ็คเกจคอร์ส

```
1. Admin เพิ่มแพ็คเกจ (addCustomerCourse)
   ├─> สร้าง courserefer อัตโนมัติ
   ├─> อัปโหลดสลิปไป S3
   ├─> บันทึกข้อมูลลง tcustomer_course
   ├─> ส่ง notification ไป Discord
   └─> Return courserefer

2. Customer เลือกแพ็คเกจให้นักเรียน
   └─> Admin update tstudent.courserefer

3. นักเรียนเรียนครบแพ็คเกจหรือหมดอายุ
   ├─> Admin finish แพ็คเกจ (finishCustomerCourse)
   ├─> Set finish = 1
   ├─> Clear courserefer ในตาราง tstudent
   └─> ส่ง notification ไป Discord
```

---

## 📈 Performance & Optimization

### Database
- ใช้ Connection Pool (30 connections)
- Parameterized queries (ป้องกัน SQL injection + faster)
- Index on foreign keys

### File Storage
- ใช้ S3 แทนการเก็บบน server
- Auto-delete old files
- CDN-ready (public-read ACL)

### Logging
- Daily log rotation
- Auto-upload to S3
- Auto-delete old logs

### Cron Jobs
- Upload logs ทุก 55 นาที
- Auto-restart server เวลา 01:30 (ป้องกัน memory leak)

### Error Handling
- Try-catch ทุก async operations
- Graceful error messages
- Log to Discord for monitoring

---

## 🐛 Troubleshooting

### ปัญหาเชื่อมต่อฐานข้อมูล
```
Error: connect ECONNREFUSED
```
**แก้ไข**: ตรวจสอบ DB_HOST, DB_PORT, DB_USER, DB_PASSWORD

### ปัญหา JWT Token
```
Error: jwt malformed
```
**แก้ไข**: ตรวจสอบ SECRET_KEY, ตรวจสอบ token format

### ปัญหาอัปโหลดไฟล์
```
Error: The specified bucket does not exist
```
**แก้ไข**: ตรวจสอบ DO_SPACES_KEY, DO_SPACES_SECRET

### ปัญหา OTP
```
Error: Authentication failed
```
**แก้ไข**: ตรวจสอบ TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN

### ปัญหา Discord Notification
```
Error: 429 Too Many Requests
```
**แก้ไข**: Queue system จะจัดการอัตโนมัติ

---

## 📞 การติดต่อและสนับสนุน

สำหรับข้อสอบถามเพิ่มเติมหรือรายงานปัญหา กรุณาติดต่อทีมพัฒนา

---

## 📝 License

Copyright © 2026 iStar. All rights reserved.

---

**เอกสารนี้สร้างจากการวิเคราะห์ source code และอาจมีการเปลี่ยนแปลงได้ตามการพัฒนาระบบ**
**อัปเดตล่าสุด**: วันที่ 10 เมษายน 2026
