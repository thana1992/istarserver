# iStar Class Management System - System Requirements Document

## 📋 สารบัญ
1. [ภาพรวม](#ภาพรวม)
2. [Functional Requirements](#functional-requirements)
3. [Non-Functional Requirements](#non-functional-requirements)
4. [Technical Requirements](#technical-requirements)
5. [User Requirements](#user-requirements)
6. [System Constraints](#system-constraints)
7. [Acceptance Criteria](#acceptance-criteria)

---

## 🎯 ภาพรวม

### วัตถุประสงค์ของเอกสาร
เอกสารนี้อธิบายข้อกำหนดทั้งหมดของระบบ iStar Class Management System เพื่อใช้เป็นแนวทางในการพัฒนา ทดสอบ และบำรุงรักษาระบบ

### ขอบเขตของระบบ
ระบบจัดการคลาสเรียนแบบครบวงจร สำหรับสถาบันการสอน ครอบคลุม:
- การจัดการข้อมูลนักเรียนและครอบครัว
- การจองและจัดการตารางเรียน
- การจัดการคอร์สและแพ็คเกจ
- การติดตามการเข้าเรียนและยอดคงเหลือ

### ผู้มีส่วนเกี่ยวข้อง (Stakeholders)
1. **ผู้ดูแลระบบ (Admin)** - จัดการระบบทั้งหมด
2. **ผู้ปกครอง/ลูกค้า (Customer)** - จองคลาสและดูข้อมูล
3. **เจ้าของสถาบัน (Owner)** - ตรวจสอบรายงานและสถิติ
4. **ทีมพัฒนา (Developers)** - พัฒนาและบำรุงรักษาระบบ

---

## 📌 Functional Requirements

### FR-1: ระบบ Authentication & Authorization

#### FR-1.1: การลงทะเบียนผู้ใช้ใหม่ (User Registration)
**Priority**: Must Have  
**Description**: ผู้ใช้สามารถลงทะเบียนเข้าใช้งานระบบได้

**Requirements**:
- REQ-1.1.1: ระบบต้องรองรับการลงทะเบียนด้วยข้อมูล:
  - Username (unique, required)
  - Password (min 6 characters, required)
  - Firstname, Middlename, Lastname (required)
  - Email (valid format, required)
  - Mobile Number (valid format, required)
  - Register Code (required, ตรวจสอบกับระบบ)
  - Accept Privacy Policy (required, checkbox)

- REQ-1.1.2: ระบบต้องตรวจสอบ username ซ้ำก่อนลงทะเบียน
- REQ-1.1.3: ระบบต้องเข้ารหัสรหัสผ่านด้วย bcrypt (salt rounds: 10)
- REQ-1.1.4: ระบบต้องสร้าง familyid อัตโนมัติเมื่อลงทะเบียนสำเร็จ
- REQ-1.1.5: ระบบต้องส่ง notification ไป Discord เมื่อมีการลงทะเบียนใหม่

**Acceptance Criteria**:
- ผู้ใช้สามารถลงทะเบียนสำเร็จด้วยข้อมูลที่ถูกต้อง
- ระบบแสดง error message เมื่อข้อมูลไม่ถูกต้อง
- ระบบป้องกันการลงทะเบียน username ซ้ำ

#### FR-1.2: การเข้าสู่ระบบ (Login)
**Priority**: Must Have  
**Description**: ผู้ใช้สามารถเข้าสู่ระบบด้วย username และ password

**Requirements**:
- REQ-1.2.1: ระบบต้องตรวจสอบ username และ password
- REQ-1.2.2: ระบบต้องสร้าง JWT token เมื่อ login สำเร็จ (expires: 24h)
- REQ-1.2.3: ระบบต้อง return ข้อมูลผู้ใช้พร้อม token: username, familyid, adminflag
- REQ-1.2.4: ระบบต้องบันทึก session ใน activeSessions
- REQ-1.2.5: ระบบต้องส่ง notification ไป Discord เมื่อ login สำเร็จ
- REQ-1.2.6: ระบบต้องแสดง error message เมื่อ credentials ไม่ถูกต้อง

**Acceptance Criteria**:
- ผู้ใช้สามารถ login สำเร็จด้วย credentials ที่ถูกต้อง
- ระบบ return JWT token ที่สามารถใช้งานได้
- ระบบป้องกันการ login ด้วย credentials ที่ไม่ถูกต้อง

#### FR-1.3: การออกจากระบบ (Logout)
**Priority**: Must Have  
**Description**: ผู้ใช้สามารถออกจากระบบได้

**Requirements**:
- REQ-1.3.1: ระบบต้องลบ session จาก activeSessions
- REQ-1.3.2: ระบบต้องเพิ่ม token เข้า blacklist
- REQ-1.3.3: ระบบต้องส่ง notification ไป Discord เมื่อ logout
- REQ-1.3.4: Token ที่ถูก blacklist ต้องไม่สามารถใช้งานได้อีก

**Acceptance Criteria**:
- ผู้ใช้สามารถ logout สำเร็จ
- Token เก่าไม่สามารถใช้งานได้หลัง logout

#### FR-1.4: การตรวจสอบสิทธิ์ (Authorization)
**Priority**: Must Have  
**Description**: ระบบต้องตรวจสอบสิทธิ์การเข้าถึง endpoints

**Requirements**:
- REQ-1.4.1: ทุก protected endpoints ต้องมี token verification
- REQ-1.4.2: Admin endpoints ต้องตรวจสอบ adminflag = '1'
- REQ-1.4.3: ระบบต้องตรวจสอบ token blacklist
- REQ-1.4.4: ระบบต้อง return 401 Unauthorized เมื่อไม่มี token
- REQ-1.4.5: ระบบต้อง return 403 Forbidden เมื่อไม่มีสิทธิ์

#### FR-1.5: การเปลี่ยนรหัสผ่าน (Change Password)
**Priority**: Should Have  
**Description**: ผู้ใช้สามารถเปลี่ยนรหัสผ่านได้

**Requirements**:
- REQ-1.5.1: ระบบต้องตรวจสอบรหัสผ่านเก่าก่อนเปลี่ยน
- REQ-1.5.2: ระบบต้องเข้ารหัสรหัสผ่านใหม่ด้วย bcrypt
- REQ-1.5.3: รหัสผ่านใหม่ต้องมีความยาวอย่างน้อย 6 ตัวอักษร

---

### FR-2: ระบบจัดการนักเรียน (Student Management)

#### FR-2.1: การเพิ่มนักเรียน (Add Student)
**Priority**: Must Have  
**Description**: Customer สามารถเพิ่มนักเรียนในครอบครัวได้

**Requirements**:
- REQ-2.1.1: ระบบต้องรองรับการเพิ่มนักเรียนด้วยข้อมูล:
  - Firstname, Middlename, Lastname (required)
  - Nickname (required)
  - Gender (required: M/F)
  - Date of Birth (required)
  - Level (optional)

- REQ-2.1.2: ระบบต้องบันทึกข้อมูลลง `jstudent` (รอการอนุมัติ)
- REQ-2.1.3: ระบบต้องเชื่อมโยงกับ familyid ของผู้ใช้
- REQ-2.1.4: ระบบต้องส่ง notification ไป Discord

**Acceptance Criteria**:
- Customer สามารถเพิ่มนักเรียนได้สำเร็จ
- ข้อมูลถูกบันทึกในตาราง jstudent
- Admin เห็นรายการรออนุมัติ

#### FR-2.2: การอนุมัตินักเรียน (Approve Student)
**Priority**: Must Have  
**Description**: Admin สามารถอนุมัตินักเรียนใหม่ได้

**Requirements**:
- REQ-2.2.1: ระบบต้องสร้าง studentid อัตโนมัติ (format: YYYYMMDDHHMMSS)
- REQ-2.2.2: ระบบต้อง copy ข้อมูลจาก `jstudent` ไป `tstudent`
- REQ-2.2.3: ระบบต้องลบข้อมูลจาก `jstudent` หลังอนุมัติ
- REQ-2.2.4: ระบบต้องส่ง notification ไป Discord

**Acceptance Criteria**:
- Admin สามารถอนุมัตินักเรียนได้สำเร็จ
- ข้อมูลถูกย้ายไป tstudent พร้อม studentid ใหม่
- Customer เห็นนักเรียนในระบบ

#### FR-2.3: การแก้ไขข้อมูลนักเรียน (Update Student)
**Priority**: Must Have  
**Description**: Admin สามารถแก้ไขข้อมูลนักเรียนได้

**Requirements**:
- REQ-2.3.1: ระบบต้องรองรับการแก้ไขข้อมูลทั้งหมดของนักเรียน
- REQ-2.3.2: ระบบต้องรองรับการเปลี่ยน courserefer
- REQ-2.3.3: เมื่อเปลี่ยน courserefer ระบบต้องตรวจสอบ:
  - Course sharing (ถ้ามีนักเรียนคนอื่นใช้ courserefer เดียวกัน)
  - ยืนยันก่อนเปลี่ยน

- REQ-2.3.4: ระบบต้องบันทึก updateby และ updatedate
- REQ-2.3.5: ระบบต้องส่ง notification ไป Discord

#### FR-2.4: การลบนักเรียน (Delete Student)
**Priority**: Must Have  
**Description**: Admin/Customer สามารถลบนักเรียนได้

**Requirements**:
- REQ-2.4.1: ระบบต้องทำ soft delete (set delflag = 1)
- REQ-2.4.2: ระบบต้อง clear courserefer
- REQ-2.4.3: สำหรับข้อมูลใน jstudent ให้ทำ hard delete
- REQ-2.4.4: ระบบต้องส่ง notification ไป Discord

**Acceptance Criteria**:
- นักเรียนที่ลบไม่แสดงในระบบ
- ข้อมูลยังคงอยู่ในฐานข้อมูล (soft delete)

#### FR-2.5: การดูข้อมูลนักเรียน (View Student)
**Priority**: Must Have  
**Description**: ผู้ใช้สามารถดูข้อมูลนักเรียนได้

**Requirements**:
- REQ-2.5.1: Customer สามารถดูนักเรียนในครอบครัวตัวเองเท่านั้น
- REQ-2.5.2: Admin สามารถดูนักเรียนทั้งหมดได้
- REQ-2.5.3: ระบบต้องแสดงข้อมูล:
  - ข้อมูลส่วนตัว
  - คอร์สที่ลงทะเบียน
  - ยอดคงเหลือ
  - วันหมดอายุ
  - อายุ (คำนวณจาก dateofbirth)

#### FR-2.6: การอัปโหลดรูปโปรไฟล์ (Upload Profile Image)
**Priority**: Should Have  
**Description**: ผู้ใช้สามารถอัปโหลดรูปโปรไฟล์นักเรียนได้

**Requirements**:
- REQ-2.6.1: ระบบต้องรองรับไฟล์ประเภท: jpg, jpeg, png, gif
- REQ-2.6.2: ระบบต้องสร้าง unique filename: `{studentid}_{timestamp}.{ext}`
- REQ-2.6.3: ระบบต้องอัปโหลดไป S3 (DigitalOcean Spaces)
- REQ-2.6.4: ระบบต้องบันทึก URL ลงฐานข้อมูล
- REQ-2.6.5: ระบบควรลบรูปเก่าจาก S3 (optional)
- REQ-2.6.6: ระบบต้องลบ temporary file หลังอัปโหลดสำเร็จ

**Acceptance Criteria**:
- ผู้ใช้สามารถอัปโหลดรูปได้สำเร็จ
- รูปแสดงผลในระบบ
- ไฟล์ถูกเก็บบน S3

---

### FR-3: ระบบจัดการการจอง (Booking/Reservation Management)

#### FR-3.1: การจองคลาส - Customer
**Priority**: Must Have  
**Description**: Customer สามารถจองคลาสเรียนได้

**Requirements**:
- REQ-3.1.1: ระบบต้องตรวจสอบการจองซ้ำ (studentid + classdate + classtime)
- REQ-3.1.2: ระบบต้องตรวจสอบที่นั่งว่าง (available > 0)
- REQ-3.1.3: ระบบต้องตรวจสอบยอดคงเหลือในคอร์ส (remaining > 0)
- REQ-3.1.4: ระบบต้องตรวจสอบวันหมดอายุ (expiredate > today)
- REQ-3.1.5: Customer ไม่สามารถจองคลาสที่มี adminflag = 1
- REQ-3.1.6: เมื่อจองสำเร็จ ระบบต้อง:
  - สร้างข้อมูลใน treservation
  - หัก remaining ใน tcustomer_course
  - ส่ง notification ไป Discord

**Business Rules**:
- BR-3.1.1: ไม่สามารถจองคลาสซ้ำในช่วงเวลาเดียวกัน
- BR-3.1.2: ต้องมียอดคงเหลือในคอร์สเพียงพอ
- BR-3.1.3: Course Sharing: ถ้านักเรียนหลายคนใช้ courserefer เดียวกัน ต้องหักยอดครั้งเดียวต่อ 1 การจอง

**Acceptance Criteria**:
- Customer สามารถจองคลาสได้สำเร็จเมื่อเงื่อนไขครบ
- ระบบแสดง error message เมื่อไม่สามารถจองได้
- ยอดคงเหลือถูกหักอัตโนมัติ

#### FR-3.2: การจองคลาส - Admin
**Priority**: Must Have  
**Description**: Admin สามารถจองคลาสได้โดยไม่จำกัด

**Requirements**:
- REQ-3.2.1: Admin สามารถจองได้แม้ที่นั่งเต็ม
- REQ-3.2.2: Admin สามารถจองคลาสที่มี adminflag = 1
- REQ-3.2.3: Admin สามารถตั้งค่าเรียนฟรี (freeflag = 1)
- REQ-3.2.4: เมื่อ freeflag = 1 ระบบไม่ต้องหักยอดคงเหลือ
- REQ-3.2.5: ระบบยังคงต้องตรวจสอบการจองซ้ำ

**Acceptance Criteria**:
- Admin สามารถจองคลาสได้ในทุกสถานการณ์
- การเรียนฟรีไม่หักยอด

#### FR-3.3: การแก้ไขการจอง
**Priority**: Must Have  
**Description**: Admin สามารถแก้ไขการจองได้

**Requirements**:
- REQ-3.3.1: ระบบต้องรองรับการแก้ไข: classid, classdate, classtime, courseid
- REQ-3.3.2: ระบบต้องตรวจสอบการจองซ้ำ (exclude reservationid ปัจจุบัน)
- REQ-3.3.3: เมื่อแก้ไข ระบบต้อง:
  - คืนยอดเดิม (ถ้าไม่ใช่ freeflag)
  - หักยอดใหม่ (ถ้าคอร์สเปลี่ยน)
  - ส่ง notification ไป Discord

- REQ-3.3.4: รองรับการเปลี่ยนสถานะเรียนฟรี

**Acceptance Criteria**:
- Admin สามารถแก้ไขการจองได้สำเร็จ
- ยอดคงเหลือถูกปรับอัตโนมัติ

#### FR-3.4: การยกเลิกการจอง
**Priority**: Must Have  
**Description**: Admin สามารถยกเลิกการจองได้

**Requirements**:
- REQ-3.4.1: ระบบต้องลบข้อมูลจาก treservation
- REQ-3.4.2: ระบบต้องคืนยอดคงเหลือ (ถ้าไม่ใช่ freeflag)
- REQ-3.4.3: ระบบต้องส่ง notification ไป Discord
- REQ-3.4.4: Course Sharing: คืนยอดตาม share_amount

**Acceptance Criteria**:
- การจองถูกยกเลิกสำเร็จ
- ยอดคงเหลือถูกคืนอัตโนมัติ

#### FR-3.5: Check-in/Undo Check-in
**Priority**: Should Have  
**Description**: Admin สามารถ check-in นักเรียนได้

**Requirements**:
- REQ-3.5.1: ระบบต้อง update checkin = 1
- REQ-3.5.2: ระบบต้องบันทึก checkin_datetime
- REQ-3.5.3: ระบบต้องรองรับการยกเลิก check-in (undo)
- REQ-3.5.4: ระบบต้องส่ง notification ไป Discord

#### FR-3.6: การดูรายการจอง
**Priority**: Must Have  
**Description**: ผู้ใช้สามารถดูรายการจองได้

**Requirements**:
- REQ-3.6.1: Customer สามารถดูการจองของนักเรียนในครอบครัวเท่านั้น
- REQ-3.6.2: Admin สามารถดูการจองทั้งหมด พร้อม filter:
  - วันที่ (startdate - enddate)
  - คอร์ส (courseid)
  - นักเรียน (studentid)
  - สถานะ check-in

- REQ-3.6.3: ระบบต้องแสดงข้อมูล:
  - ข้อมูลนักเรียน
  - ข้อมูลคลาส
  - วันที่และเวลา
  - สถานะ check-in
  - freeflag

**Acceptance Criteria**:
- ผู้ใช้สามารถดูรายการจองได้ตามสิทธิ์
- ระบบแสดงข้อมูลครบถ้วน

---

### FR-4: ระบบจัดการคอร์สและคลาส

#### FR-4.1: การจัดการคอร์ส (Course Management)
**Priority**: Must Have  
**Description**: Admin สามารถจัดการคอร์สได้

**Requirements**:
- REQ-4.1.1: เพิ่มคอร์ส (coursename, course_shortname)
- REQ-4.1.2: แก้ไขคอร์ส
- REQ-4.1.3: ลบคอร์ส (soft delete: enableflag = 0)
- REQ-4.1.4: เมื่อลบคอร์ส ต้องลบคลาสที่เกี่ยวข้องด้วย
- REQ-4.1.5: ส่ง notification ไป Discord

#### FR-4.2: การจัดการคลาส (Class Management)
**Priority**: Must Have  
**Description**: Admin สามารถจัดการคลาสได้

**Requirements**:
- REQ-4.2.1: เพิ่มคลาส:
  - courseid (FK)
  - classday (Monday, Tuesday, ...)
  - classtime (HH:MM)
  - maxperson
  - adminflag
  - startdate, enddate

- REQ-4.2.2: แก้ไขคลาส
- REQ-4.2.3: ลบคลาส (hard delete)
- REQ-4.2.4: เมื่อลบคลาส ต้องลบการจองที่เกี่ยวข้องด้วย
- REQ-4.2.5: ส่ง notification ไป Discord

#### FR-4.3: การดูเวลาคลาสที่ว่าง
**Priority**: Must Have  
**Description**: ผู้ใช้สามารถดูเวลาคลาสที่ว่างได้

**Requirements**:
- REQ-4.3.1: ระบบต้องคำนวณที่นั่งว่าง:
  - available = maxperson - จำนวนที่จองแล้ว

- REQ-4.3.2: ระบบต้องตรวจสอบ class disable (tclassdisable)
- REQ-4.3.3: ถ้า class ถูก disable, available = 0
- REQ-4.3.4: Customer เห็นเฉพาะคลาสที่ adminflag = 0
- REQ-4.3.5: Admin เห็นคลาสทั้งหมด
- REQ-4.3.6: ระบบต้องตรวจสอบ startdate/enddate ของคลาส

**Acceptance Criteria**:
- ผู้ใช้สามารถดูเวลาที่ว่างได้ถูกต้อง
- ระบบคำนวณที่นั่งว่างถูกต้อง

---

### FR-5: ระบบจัดการแพ็คเกจคอร์ส (Customer Course/Package)

#### FR-5.1: การเพิ่มแพ็คเกจ
**Priority**: Must Have  
**Description**: Admin สามารถเพิ่มแพ็คเกจคอร์สได้

**Requirements**:
- REQ-5.1.1: ระบบต้องสร้าง courserefer อัตโนมัติ (format: YYYYMMDD-HHMMSS-RANDOM)
- REQ-5.1.2: ระบบต้องรองรับการอัปโหลดสลิปชำระเงิน
- REQ-5.1.3: ระบบต้องบันทึกข้อมูล:
  - courseid
  - coursename
  - total (จำนวนครั้งทั้งหมด)
  - remaining (= total เริ่มต้น)
  - expiredate
  - slip_image_url
  - share_amount (จำนวนคนที่แชร์)

- REQ-5.1.4: ระบบต้อง upload slip ไป S3
- REQ-5.1.5: ส่ง notification ไป Discord

**Business Rules**:
- BR-5.1.1: courserefer ต้อง unique
- BR-5.1.2: total และ remaining ต้อง >= 0
- BR-5.1.3: ถ้า coursename มีคำว่า "รายครั้ง" ให้ total = remaining = 1

#### FR-5.2: การแก้ไขแพ็คเกจ
**Priority**: Must Have  
**Description**: Admin สามารถแก้ไขแพ็คเกจได้

**Requirements**:
- REQ-5.2.1: ระบบต้องรองรับการแก้ไขทุกฟิลด์
- REQ-5.2.2: ถ้าอัปโหลดสลิปใหม่ ต้องลบสลิปเก่าจาก S3
- REQ-5.2.3: การเปลี่ยน total ไม่ต้องเปลี่ยน remaining อัตโนมัติ
- REQ-5.2.4: ส่ง notification ไป Discord

#### FR-5.3: การลบแพ็คเกจ
**Priority**: Must Have  
**Description**: Admin สามารถลบแพ็คเกจได้

**Requirements**:
- REQ-5.3.1: ระบบต้องตรวจสอบก่อนลบ:
  - มีการจองที่ใช้แพ็คเกจนี้หรือไม่
  - มีนักเรียนที่เชื่อมโยงหรือไม่

- REQ-5.3.2: ถ้ามีการใช้งาน ต้องแสดง warning และรายละเอียด
- REQ-5.3.3: เมื่อยืนยันลบ ระบบต้อง:
  - ลบสลิปจาก S3
  - ลบข้อมูลจาก tcustomer_course
  - Clear courserefer ใน tstudent

- REQ-5.3.4: ส่ง notification ไป Discord

#### FR-5.4: การจบแพ็คเกจ (Finish Package)
**Priority**: Must Have  
**Description**: Admin สามารถจบแพ็คเกจได้

**Requirements**:
- REQ-5.4.1: ระบบต้อง set finish = 1
- REQ-5.4.2: ระบบต้อง clear courserefer ใน tstudent
- REQ-5.4.3: ถ้า coursename มีคำว่า "รายครั้ง" ให้ลบข้อมูลเลย (ไม่ต้อง finish)
- REQ-5.4.4: ส่ง notification ไป Discord

#### FR-5.5: การดูข้อมูลแพ็คเกจ
**Priority**: Must Have  
**Description**: ผู้ใช้สามารถดูข้อมูลแพ็คเกจได้

**Requirements**:
- REQ-5.5.1: Admin เห็นทุกแพ็คเกจ
- REQ-5.5.2: Customer เห็นเฉพาะแพ็คเกจที่เกี่ยวข้อง
- REQ-5.5.3: ระบบต้องแสดง:
  - ข้อมูลแพ็คเกจ
  - รายชื่อนักเรียนที่ใช้แพ็คเกจนี้
  - ประวัติการจอง (10 ครั้งล่าสุด)
  - สถานะหมดอายุ

- REQ-5.5.4: ระบบต้องคำนวณอายุนักเรียน

**Acceptance Criteria**:
- ผู้ใช้สามารถดูข้อมูลแพ็คเกจได้ครบถ้วน
- ข้อมูลแสดงผลถูกต้อง

---

### FR-6: ระบบจัดการไฟล์และรูปภาพ

#### FR-6.1: การอัปโหลดรูปโปรไฟล์นักเรียน
**Priority**: Should Have  
**Description**: อธิบายไว้ใน FR-2.6

#### FR-6.2: การอัปโหลดสลิปชำระเงิน
**Priority**: Should Have  
**Description**: อธิบายไว้ใน FR-5.1, FR-5.2

**Additional Requirements**:
- REQ-6.2.1: ถ้าชื่อไฟล์ซ้ำ ให้เพิ่ม _{index} ต่อท้าย
- REQ-6.2.2: อัปโหลดเป็น public-read
- REQ-6.2.3: Return URL สำหรับเข้าถึงไฟล์

#### FR-6.3: การลบไฟล์จาก S3
**Priority**: Must Have  
**Description**: ระบบต้องลบไฟล์เก่าเมื่อไม่ใช้งานแล้ว

**Requirements**:
- REQ-6.3.1: ลบรูปเก่าเมื่ออัปโหลดรูปใหม่
- REQ-6.3.2: ลบสลิปเมื่อลบแพ็คเกจ

---

### FR-7: ระบบ OTP (One-Time Password)

#### FR-7.1: การขอรหัส OTP
**Priority**: Should Have  
**Description**: ผู้ใช้สามารถขอรหัส OTP เพื่อยืนยันตัวตนได้

**Requirements**:
- REQ-7.1.1: ระบบต้องรองรับการส่ง OTP ผ่าน SMS (Twilio)
- REQ-7.1.2: Format เบอร์โทรศัพท์: +66XXXXXXXXX
- REQ-7.1.3: OTP มีอายุตามที่ Twilio กำหนด
- REQ-7.1.4: ระบบต้อง return serviceSid สำหรับตรวจสอบ

#### FR-7.2: การยืนยันรหัส OTP
**Priority**: Should Have  
**Description**: ผู้ใช้สามารถยืนยันรหัส OTP ได้

**Requirements**:
- REQ-7.2.1: ระบบต้องตรวจสอบ OTP กับ Twilio
- REQ-7.2.2: Return status: approved/pending

#### FR-7.3: การตรวจสอบเบอร์โทรศัพท์
**Priority**: Should Have  
**Description**: ตรวจสอบว่าเบอร์โทรศัพท์มีในระบบหรือไม่

**Requirements**:
- REQ-7.3.1: ค้นหาใน tuser.mobileno
- REQ-7.3.2: Return ข้อมูลผู้ใช้ถ้าพบ

---

### FR-8: ระบบจัดการวันหยุด (Holiday Management)

#### FR-8.1: การจัดการวันหยุด
**Priority**: Should Have  
**Description**: Admin สามารถจัดการวันหยุดได้

**Requirements**:
- REQ-8.1.1: เพิ่มวันหยุด (date, description, type)
- REQ-8.1.2: แก้ไขวันหยุด
- REQ-8.1.3: ลบวันหยุด

#### FR-8.2: การดึงข้อมูลวันหยุดจาก Google Calendar
**Priority**: Could Have  
**Description**: ระบบดึงวันหยุดจาก Google Calendar API

**Requirements**:
- REQ-8.2.1: เชื่อมต่อ Google Calendar API
- REQ-8.2.2: ดึงข้อมูลวันหยุดราชการไทย
- REQ-8.2.3: บันทึกลงฐานข้อมูล

---

### FR-9: ระบบรายงานและ Dashboard

#### FR-9.1: Dashboard สำหรับ Admin
**Priority**: Must Have  
**Description**: แสดงภาพรวมของระบบ

**Requirements**:
- REQ-9.1.1: Card แสดงข้อมูล:
  - จำนวนนักเรียนทั้งหมด (active)
  - จำนวนการจองวันนี้
  - จำนวนการจองพรุ่งนี้
  - จำนวนนักเรียนใหม่รออนุมัติ
  - จำนวนการจองรอยกเลิก

- REQ-9.1.2: ข้อมูล real-time (refresh on demand)

#### FR-9.2: รายงานการจอง
**Priority**: Should Have  
**Description**: แสดงรายงานการจองตามช่วงเวลา

**Requirements**:
- REQ-9.2.1: Filter: startdate, enddate, courseid, studentid
- REQ-9.2.2: แสดงข้อมูล: วันที่, เวลา, นักเรียน, คอร์ส, check-in

#### FR-9.3: รายงานนักเรียน
**Priority**: Should Have  
**Description**: แสดงรายชื่อนักเรียนทั้งหมด

**Requirements**:
- REQ-9.3.1: Filter: active/inactive
- REQ-9.3.2: แสดงข้อมูล: ข้อมูลส่วนตัว, คอร์ส, ยอดคงเหลือ

---

### FR-10: ระบบ Notification

#### FR-10.1: Discord Webhook Notification
**Priority**: Should Have  
**Description**: ส่ง notification ไป Discord

**Requirements**:
- REQ-10.1.1: แยก channel ตามประเภท:
  - System
  - Login/Logout
  - Booking
  - Course
  - Student
  - Error
  - API Call

- REQ-10.1.2: ใช้ Queue System ป้องกัน rate limit
- REQ-10.1.3: รองรับ embed format
- REQ-10.1.4: Truncate message ที่ยาวเกินไป

---

## 🚀 Non-Functional Requirements

### NFR-1: Performance

#### NFR-1.1: Response Time
**Priority**: Must Have  
- API response time < 2 วินาที (median)
- Database query time < 1 วินาที
- File upload time < 10 วินาที (ขึ้นอยู่กับขนาดไฟล์)

#### NFR-1.2: Throughput
**Priority**: Should Have  
- รองรับ concurrent users: 50 users
- รองรับ API requests: 100 requests/min

#### NFR-1.3: Database Connection Pool
**Priority**: Must Have  
- Connection limit: 30 connections
- Auto-reconnect on failure
- Connection timeout: 10 seconds

### NFR-2: Scalability

#### NFR-2.1: Horizontal Scaling
**Priority**: Could Have  
- รองรับการขยาย server (multi-instance)
- Stateless API design

#### NFR-2.2: Database Scaling
**Priority**: Should Have  
- รองรับ read replica
- ปรับ connection pool ได้

### NFR-3: Reliability

#### NFR-3.1: Availability
**Priority**: Must Have  
- Uptime: 99% (8.76 ชั่วโมง downtime/ปี)
- Auto-restart on crash

#### NFR-3.2: Error Handling
**Priority**: Must Have  
- Graceful error handling
- Error logging to Discord
- User-friendly error messages

#### NFR-3.3: Data Backup
**Priority**: Must Have  
- Database backup: daily
- Log backup: monthly (to S3)

### NFR-4: Security

#### NFR-4.1: Authentication
**Priority**: Must Have  
- Password hashing: bcrypt (salt rounds: 10)
- JWT token: 24-hour expiration
- Token blacklist on logout

#### NFR-4.2: Authorization
**Priority**: Must Have  
- Role-based access control (Admin/Customer)
- Token verification on protected endpoints

#### NFR-4.3: Data Protection
**Priority**: Must Have  
- SQL injection prevention (parameterized queries)
- XSS prevention
- CORS configuration

#### NFR-4.4: File Upload Security
**Priority**: Must Have  
- Whitelist file types
- Max file size: 5MB
- Unique file naming

#### NFR-4.5: Sensitive Data
**Priority**: Must Have  
- Mask password in logs
- Environment variables for secrets
- HTTPS for production

### NFR-5: Usability

#### NFR-5.1: API Design
**Priority**: Must Have  
- RESTful API
- Consistent response format
- Clear error messages

#### NFR-5.2: Documentation
**Priority**: Should Have  
- API documentation
- System documentation
- Database schema

### NFR-6: Maintainability

#### NFR-6.1: Code Quality
**Priority**: Should Have  
- Modular code structure
- Consistent naming conventions
- Comments for complex logic

#### NFR-6.2: Logging
**Priority**: Must Have  
- Winston logger (daily rotation)
- Morgan HTTP logger
- Log levels: info, warn, error

#### NFR-6.3: Monitoring
**Priority**: Should Have  
- Discord notifications
- Error tracking
- Active session tracking

### NFR-7: Compatibility

#### NFR-7.1: Browser Support
**Priority**: Should Have  
- Modern browsers (Chrome, Firefox, Safari, Edge)
- Mobile browsers

#### NFR-7.2: API Versioning
**Priority**: Could Have  
- Support for API versioning

### NFR-8: Portability

#### NFR-8.1: Environment
**Priority**: Must Have  
- Run on Windows/Linux/Mac
- Docker support (optional)

#### NFR-8.2: Configuration
**Priority**: Must Have  
- Environment-based configuration (.env)
- Separate dev/prod settings

---

## 💻 Technical Requirements

### TR-1: Technology Stack

#### TR-1.1: Backend
- **Runtime**: Node.js (v14+)
- **Framework**: Express.js (v4+)
- **Language**: JavaScript (ES6+)

#### TR-1.2: Database
- **RDBMS**: MySQL (v8+)
- **Driver**: mysql2 (with Promise support)
- **Connection**: Connection Pool (30 connections)

#### TR-1.3: Authentication
- **JWT**: jsonwebtoken
- **Password**: bcrypt (salt rounds: 10)

#### TR-1.4: File Storage
- **Cloud**: DigitalOcean Spaces (S3-compatible)
- **SDK**: @aws-sdk/client-s3 (v3+)
- **Upload**: Multer

#### TR-1.5: External Services
- **OTP**: Twilio SMS
- **Notification**: Discord Webhooks
- **Calendar**: Google Calendar API (optional)

#### TR-1.6: Utilities
- **Logging**: Winston + Morgan
- **Date/Time**: Moment.js (timezone: Asia/Bangkok)
- **Cron**: node-cron
- **CORS**: cors
- **Body Parser**: body-parser

### TR-2: Development Requirements

#### TR-2.1: Development Tools
- Node.js v14+ installed
- npm or yarn package manager
- MySQL client/server
- Git version control
- Code editor (VS Code recommended)

#### TR-2.2: Environment Setup
- .env file with all required variables
- MySQL database created
- DigitalOcean Spaces bucket created
- Twilio account (for OTP)
- Discord webhooks created

### TR-3: Deployment Requirements

#### TR-3.1: Server Requirements
- **OS**: Windows/Linux
- **RAM**: 2GB minimum, 4GB recommended
- **CPU**: 2 cores minimum
- **Disk**: 20GB (for logs and temporary files)

#### TR-3.2: Network Requirements
- **Port**: 3000 (configurable)
- **Outbound**: Access to:
  - MySQL server
  - DigitalOcean Spaces
  - Twilio API
  - Discord API
  - Google Calendar API (optional)

#### TR-3.3: SSL/TLS
- HTTPS recommended for production
- SSL certificate

### TR-4: Database Requirements

#### TR-4.1: MySQL Configuration
- Character set: utf8mb4
- Collation: utf8mb4_unicode_ci
- InnoDB engine
- Max connections: 100+

#### TR-4.2: Database Size
- Initial: < 10MB
- Growth: ~100MB/year (estimated)

#### TR-4.3: Indexes
- Primary keys on all tables
- Foreign keys where applicable
- Indexes on frequently queried columns:
  - username, familyid, studentid, courserefer
  - classdate, classtime
  - expiredate

### TR-5: File Storage Requirements

#### TR-5.1: S3 Bucket
- Region: sgp1 (or nearest)
- ACL: public-read for uploaded files
- CORS configured
- Lifecycle rules for old logs

#### TR-5.2: Storage Size
- Profile images: ~10MB/100 students
- Slip images: ~5MB/100 packages
- Logs: ~100MB/month

---

## 👥 User Requirements

### UR-1: Admin User

#### UR-1.1: Capabilities
- จัดการนักเรียนทั้งหมด
- อนุมัตินักเรียนใหม่
- จัดการคอร์สและคลาส
- จัดการแพ็คเกจคอร์ส
- จองและยกเลิกการจองได้ทุกกรณี
- ดูรายงานและสถิติ
- Check-in นักเรียน
- จัดการวันหยุด

#### UR-1.2: Permissions
- adminflag = '1' in tuser table
- Access to all endpoints
- Can see all data

### UR-2: Customer User

#### UR-2.1: Capabilities
- จัดการนักเรียนในครอบครัว (เพิ่ม/ลบ)
- จองคลาสเรียน
- ดูรายการจองของตัวเอง
- อัปโหลดรูปโปรไฟล์
- เปลี่ยนรหัสผ่าน
- ดูข้อมูลแพ็คเกจของตัวเอง

#### UR-2.2: Restrictions
- adminflag = '0' in tuser table
- Can only see own family data
- Cannot access admin endpoints
- Cannot see other families' data

### UR-3: User Roles Summary

| Feature | Admin | Customer |
|---------|:-----:|:--------:|
| ลงทะเบียน | ✅ | ✅ |
| Login/Logout | ✅ | ✅ |
| เพิ่มนักเรียน | ✅ | ✅* |
| อนุมัตินักเรียน | ✅ | ❌ |
| แก้ไขนักเรียน | ✅ | ❌ |
| ลบนักเรียน | ✅ | ✅* |
| จองคลาส | ✅ | ✅ |
| ยกเลิกการจอง | ✅ | ❌ |
| จัดการคอร์ส | ✅ | ❌ |
| จัดการคลาส | ✅ | ❌ |
| จัดการแพ็คเกจ | ✅ | ❌ |
| Check-in | ✅ | ❌ |
| ดูรายงาน | ✅ | ✅* |
| จัดการวันหยุด | ✅ | ❌ |

*จำกัดเฉพาะข้อมูลของตัวเอง

---

## ⚠️ System Constraints

### SC-1: Business Constraints

#### SC-1.1: Course Sharing
- นักเรียนหลายคนสามารถใช้ courserefer เดียวกันได้
- หักยอดตาม share_amount
- ต้องแจ้งเตือนเมื่อเปลี่ยน courserefer ที่มีการแชร์

#### SC-1.2: Booking Rules
- ไม่สามารถจองซ้ำในช่วงเวลาเดียวกัน
- ต้องมียอดคงเหลือเพียงพอ
- ต้องไม่หมดอายุ
- Customer ไม่สามารถจองคลาส admin

#### SC-1.3: Package Rules
- courserefer ต้อง unique
- ไม่สามารถลบแพ็คเกจที่มีการใช้งาน (ต้องยืนยัน)
- Package "รายครั้ง" มี total = remaining = 1

### SC-2: Technical Constraints

#### SC-2.1: Database
- MySQL only (no NoSQL)
- Character set: utf8mb4

#### SC-2.2: File Upload
- Max size: 5MB
- Allowed types: jpg, jpeg, png, gif
- Storage: S3 only

#### SC-2.3: Authentication
- JWT only
- Token expires: 24 hours
- No refresh token

#### SC-2.4: Timezone
- Fixed timezone: Asia/Bangkok
- No multi-timezone support

### SC-3: Integration Constraints

#### SC-3.1: Third-party Services
- Dependent on:
  - DigitalOcean Spaces (S3)
  - Twilio SMS
  - Discord Webhooks
  - Google Calendar API (optional)

#### SC-3.2: API Rate Limits
- Discord: managed by queue system
- Twilio: as per Twilio limits
- Google Calendar: as per Google limits

---

## ✅ Acceptance Criteria

### AC-1: Authentication

✅ ผู้ใช้สามารถลงทะเบียนและ login ได้สำเร็จ  
✅ ระบบตรวจสอบ token ทุก protected endpoints  
✅ ผู้ใช้สามารถ logout ได้และ token ไม่สามารถใช้งานได้อีก  
✅ ระบบแยกสิทธิ์ Admin/Customer ได้ถูกต้อง  

### AC-2: Student Management

✅ Customer สามารถเพิ่มนักเรียนและรออนุมัติได้  
✅ Admin สามารถอนุมัตินักเรียนได้สำเร็จ  
✅ Admin สามารถแก้ไขข้อมูลนักเรียนได้  
✅ ระบบทำ soft delete เมื่อลบนักเรียน  
✅ ผู้ใช้สามารถอัปโหลดรูปโปรไฟล์ได้  

### AC-3: Booking Management

✅ Customer สามารถจองคลาสได้เมื่อมีที่นั่งว่างและยอดเพียงพอ  
✅ ระบบป้องกันการจองซ้ำ  
✅ ระบบหักยอดคงเหลืออัตโนมัติ  
✅ Admin สามารถจอง/แก้ไข/ยกเลิกได้ในทุกสถานการณ์  
✅ ระบบคืนยอดเมื่อยกเลิกการจอง  
✅ Admin สามารถ check-in นักเรียนได้  

### AC-4: Course & Class Management

✅ Admin สามารถเพิ่ม/แก้ไข/ลบคอร์สได้  
✅ Admin สามารถเพิ่ม/แก้ไข/ลบคลาสได้  
✅ ระบบคำนวณที่นั่งว่างได้ถูกต้อง  
✅ Customer เห็นเฉพาะคลาสที่ไม่ใช่ admin  

### AC-5: Package Management

✅ Admin สามารถเพิ่มแพ็คเกจพร้อมอัปโหลดสลิปได้  
✅ Admin สามารถแก้ไข/ลบแพ็คเกจได้  
✅ ระบบตรวจสอบก่อนลบแพ็คเกจที่มีการใช้งาน  
✅ Admin สามารถจบแพ็คเกจได้  
✅ ระบบแสดงข้อมูลแพ็คเกจครบถ้วน  

### AC-6: File Management

✅ ผู้ใช้สามารถอัปโหลดรูปโปรไฟล์ได้  
✅ Admin สามารถอัปโหลดสลิปชำระเงินได้  
✅ ไฟล์ถูกเก็บบน S3 และเข้าถึงได้  
✅ ระบบลบไฟล์เก่าเมื่อไม่ใช้งาน  

### AC-7: Reporting & Dashboard

✅ Dashboard แสดงข้อมูลสรุปได้ถูกต้อง  
✅ รายงานการจองแสดงข้อมูลตาม filter  
✅ รายงานนักเรียนแสดงข้อมูลครบถ้วน  

### AC-8: Security

✅ รหัสผ่านถูกเข้ารหัสด้วย bcrypt  
✅ ระบบตรวจสอบ JWT token ทุก protected endpoints  
✅ ระบบป้องกัน SQL injection  
✅ ไฟล์ที่อัปโหลดถูก validate  

### AC-9: Performance

✅ API response time < 2 วินาที  
✅ Database query time < 1 วินาที  
✅ ระบบรองรับ concurrent users ได้  

### AC-10: Monitoring & Logging

✅ ระบบบันทึก log ทุก API calls  
✅ ระบบส่ง notification ไป Discord  
✅ Log files ถูกอัปโหลดไป S3 อัตโนมัติ  
✅ ระบบลบ log เก่าอัตโนมัติ  

---

## 📊 Metrics & KPIs

### Success Metrics

1. **User Adoption**
   - จำนวนผู้ใช้ active: target 50+ users
   - จำนวนนักเรียนในระบบ: target 100+ students

2. **System Usage**
   - จำนวนการจองต่อเดือน: target 500+ bookings
   - จำนวน API calls ต่อวัน: target 1,000+ requests

3. **Performance**
   - API response time (p95): < 2 วินาที
   - System uptime: > 99%
   - Error rate: < 1%

4. **User Satisfaction**
   - จำนวน error reports: minimize
   - System downtime: < 8.76 ชั่วโมง/ปี

---

## 🔄 Future Enhancements (Out of Scope)

1. **Mobile App** - iOS/Android native apps
2. **Email Notifications** - แจ้งเตือนผ่าน email
3. **Payment Gateway** - ชำระเงินออนไลน์
4. **Multi-language** - รองรับหลายภาษา
5. **Multi-timezone** - รองรับหลายเขตเวลา
6. **Advanced Analytics** - รายงานเชิงลึก, charts
7. **Waiting List** - ระบบรอคิว
8. **Group Classes** - คลาสแบบกลุ่ม
9. **Attendance Tracking** - ติดตามการเข้าเรียนแบบละเอียด
10. **Teacher Management** - จัดการข้อมูลครู

---

## 📝 Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-04-10 | System Analyst | Initial version created from source code analysis |

---

## 📞 Approval & Sign-off

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Project Owner | | | |
| System Analyst | | | |
| Lead Developer | | | |
| QA Lead | | | |

---

**หมายเหตุ**: เอกสารนี้สร้างจากการวิเคราะห์ source code และอาจมีการเปลี่ยนแปลงได้ตามการพัฒนาระบบ

**อัปเดตล่าสุด**: วันที่ 10 เมษายน 2026
