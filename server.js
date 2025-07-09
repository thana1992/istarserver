require('dotenv').config()

const express = require('express');
const axios = require('axios');
const qs = require('qs');
//const moment = require('moment');
const moment = require('moment-timezone');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const pad = require('pad')
const crypto = require('crypto');
const app = express();
const port = 3000;
const jwt = require('jsonwebtoken');
const SECRET_KEY = process.env.SECRET_KEY;
const activeSessions = [];
const blacklistSessions = [];
const { logToQueue, logSystemToDiscord, logLoginToDiscord, logBookingToDiscord, logCourseToDiscord, logStudentToDiscord } = require('./logToDiscord'); // import function ที่แยกไว้
const mysql2 = require('mysql2/promise');
const { stringify } = require('querystring');
const SERVER_TYPE = process.env.SERVER_TYPE;
// Create a connection pool
const DB_HOST = process.env.DB_HOST;
const DB_PORT = process.env.DB_PORT;
const DB_NAME = process.env.DB_NAME;
const DB_USER = process.env.DB_USER;
const DB_PASSWORD = process.env.DB_PASSWORD;
const pool = mysql2.createPool({
  host: DB_HOST,
  port: DB_PORT,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  waitForConnections: true,
  connectionLimit: 30,
  queueLimit: 0,
});

// ติดตั้ง package สำหรับ S3 v3
const { S3Client, PutObjectCommand, HeadObjectCommand } = require('@aws-sdk/client-s3');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' }); // กำหนดที่เก็บไฟล์ชั่วคราว

// สร้าง S3 Client
const s3Client = new S3Client({
  region: 'sgp1', // เปลี่ยนเป็น region ของคุณ
  endpoint: 'https://sgp1.digitaloceanspaces.com', // ตั้งค่า endpoint ของ DigitalOcean Space
  credentials: {
    accessKeyId: process.env.DO_SPACES_KEY,
    secretAccessKey: process.env.DO_SPACES_SECRET,
  }
});

function momentTH(input) {
  return input ? moment(input).tz('Asia/Bangkok') : moment().tz('Asia/Bangkok');
}

async function queryPromise(query, params, showlog) {
  let connection;
  try {
    console.log("Query : " + query);
    
    // Prepare log data for Discord
    let logData = {
      query: query.replace(/\n/g, ' '),  // เอา \n ออกก่อนเพื่อให้ query ดูสะอาด
      params: null,
      result: null
    };
    
    logData.params = maskSensitiveData(params);

    connection = await pool.getConnection();
    await connection.query("SET time_zone = '+07:00';"); // ตั้งค่าเขตเวลาเป็นเวลาของไทย (UTC+7)
    const [results] = await connection.query(query, params);
    
    // Mask results if showlog is true
    logData.result = Array.isArray(results) ? results.map(maskSensitiveData) : maskSensitiveData(results);

    // Log the data to Discord only once
    if (showlog) {
      console.log("Params : " + JSON.stringify(logData.params));
      console.log("Results : " + JSON.stringify(logData.result));
    }

    return results;
  } catch (error) {
    console.error('Error in queryPromise:', error);
    throw error;
  } finally {
    if (connection) connection.release();
  }
}


function maskSensitiveData(data) {
  const maskedData = { ...data };
  for (const key in maskedData) {
    if (key.includes('image') || key.includes('password')) {
      maskedData[key] = '[HIDDEN]';
    }
  }
  return maskedData;
}

// for save file log
const morgan = require('morgan');
const winston = require('winston');
const fs = require('fs');
const path = require('path');

// สร้าง timestamp สำหรับชื่อไฟล์ log
const { format } = require('date-fns/format');
const timeZone = 'Asia/Bangkok';
const timestamp = format(new Date(), 'yyyy-MM-dd\'T\'HH-mm-ssXXX', { timeZone });
console.log('timestamp : ' + timestamp);
const logFileName = `${SERVER_TYPE}-${timestamp}.log`;
const logPath = './logs/';
if (!fs.existsSync(logPath)) {
  fs.mkdirSync(logPath, { recursive: true });
}

// สร้าง winston logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({
      format: () => {
        const formattedDate = momentTH().format('YYYY-MM-DD HH:mm:ss.SSS');
        return `${formattedDate}`;
      }
    }),
    winston.format.printf(({ timestamp, level, message }) => `${timestamp} ${level}: ${message}`)
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: logPath+logFileName })
  ]
});

// เริ่มด้วย bodyParser
app.use(bodyParser.json({ limit: '5mb' }));
// ใช้ morgan เพื่อบันทึก log

// ตั้งค่า CORS (เลือกใช้ `cors` หรือ `res.header`)
app.use(cors({
  origin: '*', // ปรับ origin ตามความเหมาะสม
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true
}));

// เพิ่ม middleware logging (request/response)
app.use(morgan('combined', { stream: fs.createWriteStream(path.join(__dirname, logPath+logFileName), { flags: 'a' }) }));
app.use((req, res, next) => {
  //logger.info(`REQUEST: ${req.method} ${req.url}`);
  const originalSend = res.send;
  res.send = function (body) {
    let logBody = body;

    // Check if the body is JSON and can be parsed
    try {
      const jsonBody = JSON.parse(body);

      // Function to mask image keys for logging
      const maskImageKeys = (obj) => {
        if (typeof obj !== 'object' || obj === null) return obj;
        if (Array.isArray(obj)) return obj.map(maskImageKeys);

        return Object.keys(obj).reduce((acc, key) => {
          if (key.includes('image') || key.includes('password') || key.includes('token')) {
            // Mask the value for logging
            const value = obj[key];
            acc[key] = typeof value === 'string' && value.length > 10 
              ? value.substring(0, 10) + '...[HIDDEN]'
              : '...[HIDDEN]';
          } else {
            acc[key] = maskImageKeys(obj[key]);
          }
          return acc;
        }, {});
      };

      // Mask the keys containing 'image' for logging
      const maskedJsonBody = maskImageKeys(jsonBody);
      logBody = JSON.stringify(maskedJsonBody);
    } catch (error) {
      // If body is not JSON or parsing fails, log the error and use the original body for logging
      logger.warn('Unable to parse response body as JSON', error);
    }

    //logger.info(`-----> RESPONSE : ${req.url} : ---> ${logBody}`);
    const timestamp = new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' });
    const username = req.user && req.user.username ? req.user.username : 'Unknown User';
    logToQueue('apicall', `[${timestamp}] [${username}] Request[${req.method}] ${req.url}`);
    // Send the original body to the client
    originalSend.call(res, body);
  };
  next();
});

// เพิ่ม header สำหรับ response (หากจำเป็น)
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*'); // ถ้าจำเป็นต้องใช้
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  next();
});

// Middleware for verifying the token
const verifyToken = (req, res, next) => {
  try {
    const token = req.headers.authorization.split(' ')[1];
    //console.log('Received token:'+ token);
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    if (blacklistSessions.includes(token)) {
      return res.status(401).json({ message: 'Token has been revoked' });
    }

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: 'Session expried please login again' });
      }

      // Check if the user is already in activeSessions
      const existingUser = activeSessions.find((user) => user.username === decoded.username);

      if (!existingUser) {
        // Add the decoded user information to the activeSessions array
        activeSessions.push(decoded);
      }
      // Attach the decoded user information to the request for use in route handlers
      req.user = decoded;
      next();
    });
  } catch (error) {
    console.error('Error in verifyToken', error.stack);
    res.status(500).json({ message: 'Internal server error' });
  };
};

app.get('/', function (req, res, next) {
  console.log("API called : " + req.path);
  res.send('Hello World from Istar API :) ');
  next();
});

app.post('/verifyToken', verifyToken, (req, res) => {
  // The token has been successfully verified, and you can access the user information in req.user
  // Perform actions related to creating the component

  res.json({ success: true, message: 'verifyToken successfully' });
});

app.get('/checkToken', (req, res) => {
  // Token is valid, return information about the token
  activeSessions.forEach(item => {
    let iat = new Date(item.iat * 1000)
    let exp = new Date(item.exp * 1000)
    console.log(item.username + " : " + iat.toISOString + " : " + exp.toISOString() + "\n")
  });
  res.json({ activeSessions });
  uploadOrUpdateLogFile();
});

app.post('/login', async (req, res) => {
  console.log("login : " + JSON.stringify(req.body));
  const { username, password } = req.body;
  const query = 'SELECT * FROM tuser WHERE LOWER(username) = ?';
  try {
    const results = await queryPromise(query, [username.toLowerCase()]);
    if (results.length > 0) {
      const storedPassword = results[0].userpassword;
      //console.log("storedPassword : " + storedPassword);
      if (storedPassword === password) {
        //res.status(200).json({ message: "Login successful" });
        const user = results[0];
        const userdata = {
          username: user.username,
          firstname: user.firstname,
          email: user.email,
          mobileno: user.mobileno,
          usertype: user.usertype,
          familyid: user.familyid,
        }
        const logquery = 'INSERT INTO llogin (username) VALUES (?)';
        await queryPromise(logquery, [user.username]);
        console.log("username : " + user.username);
        logLoginToDiscord('info', '✅ [Login]', `User ${username} logged in successfully.`);
        if (userdata.usertype != '10') {
          const token = jwt.sign({ username: user.username ,adminflag: 1 }, SECRET_KEY, { expiresIn: '5h' });
          return res.json({ success: true, message: 'Login successful', token, userdata });
        } else {
          const token = jwt.sign({ username: user.username ,adminflag: 0 }, SECRET_KEY, { expiresIn: '10m' });
          return res.json({ success: true, message: 'Login successful', token, userdata });
        }

      } else {
        logLoginToDiscord('error', '❌ [Login]', `User ${username} failed to log in. Invalid password.`);
        return res.json({ success: false, message: 'password is invalid' });
      }
    } else {
      logLoginToDiscord('error', '❌ [Login]', `User ${username} failed to log in. Invalid username.`);
      return res.json({ success: false, message: 'username invalid' });
    }
  } catch (error) {
    logLoginToDiscord('error', '❌ [Login]', `User ${username} failed to log in. Error: ${error.message}`);
    console.error("Error logging in", error.stack);
    return res.status(500).send(error);
  }
});

app.post('/logout', verifyToken, (req, res) => {
  // Remove the user from activeSessions
  const userIndex = activeSessions.findIndex((user) => user.username === req.user.username);
  if (userIndex !== -1) {
    activeSessions.splice(userIndex, 1);
  }
  
  const token = req.headers.authorization.split(' ')[1];
  console.log("token : " + token);
  // เพิ่ม token เข้าไปใน blacklist
  blacklistSessions.push(token);

  // Optionally, you can add more cleanup logic here
  logLoginToDiscord('info', '✅ [Logout]', `User ${req.user.username} logged out successfully.`);
  res.json({ success: true, message: 'Logout successful' });
});

app.post('/register', async (req, res) => {
  logSystemToDiscord('info', '✅ [Register]', `User is registering.\n${JSON.stringify(req.body)}`);
  console.log("register : " + JSON.stringify(req.body));
  const { username, password, firstname, middlename, lastname, address, email, mobileno, registercode, acceptPrivacyPolicy } = req.body;

  try {
    // Check if the username is already taken
    const checkUsernameQuery = 'SELECT * FROM tuser WHERE username = ?';
    const existingUser = await queryPromise(checkUsernameQuery, [username]);

    if (existingUser.length > 0) {
      return res.json({ success: false, message: 'Username is already taken' });
    } else {
      let usertype = '10';
      if (registercode && registercode.toLowerCase() === 'manager') {
        usertype = '0';
      } else if (registercode && registercode.toLowerCase() === 'admin') {
        usertype = '1';
      } else if (registercode && registercode.toLowerCase() === 'coach') {
        usertype = '2';
      } else if (registercode && registercode.toLowerCase() === 'student') {
        usertype = '10';
      } else {
        return res.json({ success: false, message: 'Invalid register code' });
      }
      // Insert new user
      const insertUserQuery = 'INSERT INTO tuser (username, userpassword, firstname, middlename, lastname, address, email, mobileno, usertype, acceptPrivacyPolicy) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
      await queryPromise(insertUserQuery, [username, password, firstname, middlename, lastname, address, email, mobileno, usertype, acceptPrivacyPolicy]);

      // Create associated family
      const createFamilyQuery = 'INSERT INTO tfamily (username) VALUES (?)';
      await queryPromise(createFamilyQuery, [username]);

      return res.json({ success: true, message: 'User registered successfully' });
    }
  } catch (error) {
    console.error("Error registering user", error.stack);
    return res.status(500).send(error);
  }
});

app.post("/getFamilyMember", verifyToken, async (req, res) => {
  const { familyid } = req.body;
  const query = 'select a.studentid, a.familyid, a.firstname, a.middlename, a.lastname, a.nickname, a.gender, a.dateofbirth, ' +
    ' b.courserefer, c.coursename, c.course_shortname, b.courseid, ' +
    ' b.coursetype, b.remaining, b.expiredate, ' +
    ' CONCAT(IFNULL(a.firstname, \'\'), \' \', IFNULL(a.middlename, \'\'), IF( a.middlename<>\'\', \' \', \'\'), IFNULL( a.lastname, \'\'), \' (\', a.nickname,\')\') fullname ' +
    ' from tstudent a ' +
    ' left join tcustomer_course b ' +
    ' on a.courserefer = b.courserefer ' +
    ' and b.finish = 0' +
    ' left join tcourseinfo c ' +
    ' on b.courseid = c.courseid ' +
    ' where a.familyid = ? ' +
    ' and a.delflag = 0';
  try {
    const results = await queryPromise(query, [familyid]);
    if (results.length > 0) {
      res.json({ success: true, message: 'Get FamilyMember successful', results });
    } else {
      res.json({ success: true, message: 'Not found FamilyMember', results });
    }
  } catch (error) {
    console.error("Error in getFamilyMember", error.stack);
    res.status(500).send(error);
  }
});

app.post("/getFamilyList", verifyToken, async (req, res) => {
  const { familyid } = req.body;
  const query = 'select a.studentid, a.familyid, a.firstname, a.middlename, a.lastname, a.nickname, a.gender, a.dateofbirth, ' +
    ' CONCAT(IFNULL(firstname, \'\'), \' \', IFNULL(a.middlename, \'\'), IF(a.middlename<>\'\', \' \', \'\'), IFNULL( a.lastname, \'\'), \' (\', a.nickname,\')\') fullname, \'0\' journal ' +
    ' from tstudent a ' +
    ' where a.familyid = ? ' +
    ' and delflag = 0 '+
    ' UNION ALL ' +
    ' select a.studentid, a.familyid, a.firstname, a.middlename, a.lastname, a.nickname, a.gender, a.dateofbirth, ' +
    ' CONCAT(IFNULL(firstname, \'\'), \' \', IFNULL(a.middlename, \'\'), IF(a.middlename<>\'\', \' \', \'\'), IFNULL( a.lastname, \'\'), \' (\', a.nickname,\')\') fullname, \'1\' journal ' +
    ' from jstudent a ' +
    ' where a.familyid = ? ';

  try {
    const results = await queryPromise(query, [familyid, familyid]);
    if (results.length > 0) {
      res.json({ success: true, message: 'Get Family Member successful', results });
    } else {
      res.json({ success: true, message: 'No Family Member', results });
    }
  } catch (error) {
    console.error("Error in getFamilyList", error.stack);
    res.status(500).send(error);
  }
});

app.post('/addStudent', verifyToken, async (req, res) => {
  try {
    const studentid = await generateRefer('TMP');
    const { familyid, firstname, middlename, lastname, nickname, gender, dateofbirth, school } = req.body;
    let query = 'INSERT INTO jstudent (studentid, familyid';
      if(firstname) query += ', firstname';
      if(middlename) query += ', middlename';
      if(lastname) query += ', lastname';
      if(nickname) query += ', nickname';
      if(gender) query += ', gender';
      if(dateofbirth) query += ', dateofbirth';
      if(school) query += ', school';
    query += ') VALUES (?, ?';
      if(firstname) query += ', ?';
      if(middlename) query += ', ?';
      if(lastname) query += ', ?';
      if(nickname) query += ', ?';
      if(gender) query += ', ?';
      if(dateofbirth) query += ', ?';
      if(school) query += ', ?';
    query += ')';

    let params = [studentid, familyid];
      if(firstname) params.push(firstname);
      if(middlename) params.push(middlename); 
      if(lastname) params.push(lastname); 
      if(nickname) params.push(nickname); 
      if(gender) params.push(gender);
      if(dateofbirth) params.push(dateofbirth);
      if(school) params.push(school);
    await queryPromise(query, params);
    logStudentToDiscord('info', `✅ [Add Student][${req.user.username}]`, `Body : ${JSON.stringify(req.body)}\n Successfully.`);
    res.json({ success: true, message: 'Family member was successfully added. Please wait for approval from the admin.' });
  } catch (error) {
    logStudentToDiscord('error', `❌ [Add Student][${req.user.username}]`, `Body : ${JSON.stringify(req.body)}\n❌ Error adding family member: ${error.message}`);
    console.error("Error in addStudent", error.stack);
    res.status(500).send(error);
    throw error; // Throw the error to be caught by the outer catch block
  }
});

app.post('/approveNewStudent', verifyToken, async (req, res) => {
  try {
    const { apprObj } = req.body;
    console.log("apprObj : " + JSON.stringify(apprObj));

    const studentIds = apprObj.map(item => item.studentid);
    const getQuery = 'SELECT * FROM jstudent WHERE studentid IN (?)';
    const results = await queryPromise(getQuery, [studentIds]);

    if (results.length > 0) {
      const insertStudentQueries = [];
      const deleteStudentQueries = [];

      for (const result of results) {
        const studentid = await generateRefer('S');
        const insertStudentQuery = `
          INSERT INTO tstudent (studentid, familyid, firstname, middlename, lastname, nickname, gender, dateofbirth, school, createby) 
          SELECT ?, jstudent.familyid, firstname, middlename, lastname, nickname, gender, dateofbirth, school, a.username as createby 
          FROM jstudent 
          LEFT JOIN tfamily a ON a.familyid = jstudent.familyid 
          WHERE jstudent.studentid = ?
        `;
        insertStudentQueries.push(queryPromise(insertStudentQuery, [studentid, result.studentid]));

        const deleteStudentQuery = 'DELETE FROM jstudent WHERE studentid = ?';
        deleteStudentQueries.push(queryPromise(deleteStudentQuery, [result.studentid]));
      }

      await Promise.all(insertStudentQueries);
      await Promise.all(deleteStudentQueries);
      logStudentToDiscord('info', `✅ [Approve Student][${req.user.username}]`, `Body : ${JSON.stringify(req.body)}\n Successfully approved new student(s): ${JSON.stringify(studentIds)}`);
      res.json({ success: true, message: 'Family member approve successfully' });
    } else {
      logStudentToDiscord('error', `❌ [Approve Student][${req.user.username}]`, `Body : ${JSON.stringify(req.body)}\n ❌ No student found for approval.`);
      res.json({ success: false, message: 'No students found for approval' });
    }
  } catch (error) {
    console.error('Error in approveNewStudent', error.stack);
    logStudentToDiscord('error', `❌ [Approve Student][${req.user.username}]`, `Body : ${JSON.stringify(req.body)}\n ❌ Error approving new student(s): ${error.message}`);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

app.post('/addStudentByAdmin', verifyToken, async (req, res) => {
  const { firstname, middlename, lastname, nickname, gender, dateofbirth, level, familyid, courserefer, courserefer2, shortnote } = req.body;
  try {
    // ตรวจสอบการใช้งานคอร์ส
    if (courserefer) {
      const checkCourseUsing1 = await checkCourseShare(courserefer);
      console.log("checkCourseUsing1 : " + JSON.stringify(checkCourseUsing1));
      if (!checkCourseUsing1.results) {
        return res.json({ success: false, message: checkCourseUsing1.message });
      }
    }
    if (courserefer2) {
      const checkCourseUsing2 = await checkCourseShare(courserefer2);
      console.log("checkCourseUsing2 : " + JSON.stringify(checkCourseUsing2));
      if (!checkCourseUsing2.results) {
        return res.json({ success: false, message: checkCourseUsing2.message });
      }
    }

    const studentid = await generateRefer('S');
    const insertStudentQuery = `
      INSERT INTO tstudent (studentid, firstname, middlename, lastname, nickname, gender, dateofbirth, level, familyid, courserefer, courserefer2, shortnote, createby) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const insertStudentParams = [studentid, firstname, middlename, lastname, nickname, gender, dateofbirth, level, familyid, courserefer, courserefer2, shortnote, req.user.username];
    await queryPromise(insertStudentQuery, insertStudentParams);

    // อัปเดตเจ้าของคอร์สหลัก
    if (courserefer) {
      const checkCourseOwnerQuery1 = 'SELECT * FROM tcustomer_course WHERE courserefer = ?';
      const courseOwnerResult1 = await queryPromise(checkCourseOwnerQuery1, [courserefer]);
      if (courseOwnerResult1.length > 0) {
        let owner1 = courseOwnerResult1[0].owner;
        if (owner1 !== 'trial') {
          let ownerList1 = owner1 ? owner1.split(',') : [];
          if (!ownerList1.includes(studentid)) {
            ownerList1.push(studentid);
            let newOwner1 = ownerList1.join(',');
            const updateOwnerQuery1 = 'UPDATE tcustomer_course SET owner = ? WHERE courserefer = ?';
            await queryPromise(updateOwnerQuery1, [newOwner1, courserefer]);
          }
        }
      }
    }

    // อัปเดตเจ้าของคอร์สรอง
    if (courserefer2) {
      const checkCourseOwnerQuery2 = 'SELECT * FROM tcustomer_course WHERE courserefer = ?';
      const courseOwnerResult2 = await queryPromise(checkCourseOwnerQuery2, [courserefer2]);
      if (courseOwnerResult2.length > 0) {
        let owner2 = courseOwnerResult2[0].owner;
        if (owner2 !== 'trial') {
          let ownerList2 = owner2 ? owner2.split(',') : [];
          if (!ownerList2.includes(studentid)) {
            ownerList2.push(studentid);
            let newOwner2 = ownerList2.join(',');
            const updateOwnerQuery2 = 'UPDATE tcustomer_course SET owner = ? WHERE courserefer = ?';
            await queryPromise(updateOwnerQuery2, [newOwner2, courserefer2]);
          }
        }
      }
    }
    logStudentToDiscord('info', `✅ [Add Student][${req.user.username}]`, `Body : ${JSON.stringify(req.body)}\n Successfully added new student: ${studentid}`);
    res.json({ success: true, message: 'Family member added successfully', studentid });
  } catch (error) {
    logStudentToDiscord('error', `❌ [Add Student][${req.user.username}]`, `Body : ${JSON.stringify(req.body)}\n ❌ Error adding new student: ${error.message}`);
    console.error('Error in addStudentByAdmin', error.stack);
    res.status(500).send(error);
  }
});

app.post('/updateStudentByAdmin', verifyToken, async (req, res) => {
  try {
    const { studentid, firstname, middlename, lastname, nickname, gender, dateofbirth, level, familyid, courserefer, courserefer2, shortnote } = req.body;

    const queryData = 'SELECT * FROM tstudent WHERE studentid = ?';
    const oldData = await queryPromise(queryData, [studentid]);
    // ตรวจสอบการใช้งานคอร์ส
    if (courserefer) {
      const checkCourseUsing1 = await checkCourseShare(courserefer, studentid);
      console.log("checkCourseUsing1 : " + JSON.stringify(checkCourseUsing1));
      if (!checkCourseUsing1.results) {
        return res.json({ success: false, message: checkCourseUsing1.message });
      }
    }
    if (courserefer2) {
      const checkCourseUsing2 = await checkCourseShare(courserefer2, studentid);
      console.log("checkCourseUsing2 : " + JSON.stringify(checkCourseUsing2));
      if (!checkCourseUsing2.results) {
        return res.json({ success: false, message: checkCourseUsing2.message });
      }
    }

    // อัปเดตข้อมูลนักเรียน
    const updateStudentQuery = `
      UPDATE tstudent 
      SET firstname = ?, middlename = ?, lastname = ?, nickname = ?, gender = ?, dateofbirth = ?, level = ?, familyid = ?, shortnote = ?, updateby = ? 
      WHERE studentid = ?
    `;
    const updateStudentParams = [firstname, middlename, lastname, nickname, gender, dateofbirth, level, familyid, shortnote, req.user.username, studentid];
    const updateStudentResult = await queryPromise(updateStudentQuery, updateStudentParams);

    if (updateStudentResult.affectedRows > 0) {
      // อัปเดตคอร์สหลัก
      if (courserefer) {
        const updateCourseQuery1 = 'UPDATE tstudent SET courserefer = ? WHERE studentid = ?';
        await queryPromise(updateCourseQuery1, [courserefer, studentid]);

        const checkCourseOwnerQuery1 = 'SELECT * FROM tcustomer_course WHERE courserefer = ?';
        const courseOwnerResult1 = await queryPromise(checkCourseOwnerQuery1, [courserefer]);
        if (courseOwnerResult1.length > 0) {
          let owner1 = courseOwnerResult1[0].owner;
          if (owner1 !== 'trial') {
            let ownerList1 = owner1 ? owner1.split(',') : [];
            if (!ownerList1.includes(studentid)) {
              ownerList1.push(studentid);
              let newOwner1 = ownerList1.join(',');
              const updateOwnerQuery1 = 'UPDATE tcustomer_course SET owner = ? WHERE courserefer = ?';
              await queryPromise(updateOwnerQuery1, [newOwner1, courserefer]);
            }
          }
        }
      }

      // อัปเดตคอร์สรอง
      if (courserefer2) {
        const updateCourseQuery2 = 'UPDATE tstudent SET courserefer2 = ? WHERE studentid = ?';
        await queryPromise(updateCourseQuery2, [courserefer2, studentid]);

        const checkCourseOwnerQuery2 = 'SELECT * FROM tcustomer_course WHERE courserefer = ?';
        const courseOwnerResult2 = await queryPromise(checkCourseOwnerQuery2, [courserefer2]);
        if (courseOwnerResult2.length > 0) {
          let owner2 = courseOwnerResult2[0].owner;
          if (owner2 !== 'trial') {
            let ownerList2 = owner2 ? owner2.split(',') : [];
            if (!ownerList2.includes(studentid)) {
              ownerList2.push(studentid);
              let newOwner2 = ownerList2.join(',');
              const updateOwnerQuery2 = 'UPDATE tcustomer_course SET owner = ? WHERE courserefer = ?';
              await queryPromise(updateOwnerQuery2, [newOwner2, courserefer2]);
            }
          }
        }
      }
      //เปรียบเทียบข้อมูลที่มีการเปลี่ยนแปลง ระหว่าง oldData และ newData เพื่อ log เฉพาะข้อมูลที่มีการเปลี่ยนแปลง ค่าที่เป็น datetime จะเปรียบเทียบแค่วันที่ ไม่เปรียบเทียบเวลา
      let logData = {
        studentid: studentid,
        oldData: {},
        newData: {},
        changedFields: {}
      };
      for (const key in req.body) {
        if (req.body.hasOwnProperty(key)) {
          const newValue = req.body[key];
          const oldValue = oldData[0][key];
          if (key === 'dateofbirth' || key === 'editdate' || key === 'createdate') {
            const oldDate = new Date(oldValue).setHours(0, 0, 0, 0);
            const newDate = new Date(newValue).setHours(0, 0, 0, 0);
            if (oldDate !== newDate) {
              // แปลง format วันที่ให้เป็น YYYY-MM-DD
              const oldDateString = new Date(oldDate).toISOString().split('T')[0];
              const newDateString = new Date(newDate).toISOString().split('T')[0];
              logData.changedFields[key] = { old: oldDateString, new: newDateString };
            }
          } else if (newValue !== oldValue) {
            logData.oldData[key] = oldValue;
            logData.newData[key] = newValue;
            logData.changedFields[key] = { old: oldValue, new: newValue };
          }
        }
      }
      // Log ข้อมูลที่มีการเปลี่ยนแปลง
      if (Object.keys(logData.changedFields).length > 0) {
        const beautifulChangedFields = JSON.stringify(logData.changedFields, null, 2); // <--- เพิ่ม null, 2 ตรงนี้
        logStudentToDiscord('info', `✅ [Update Student][${req.user.username}]`, `Successfully updated student : ${studentid}\nChanged Fields :\n\`\`\`json\n${beautifulChangedFields}\n\`\`\``);
      } else {
        logStudentToDiscord('info', `✅ [Update Student][${req.user.username}]`, `No changes detected for student : ${studentid}\nBody : ${JSON.stringify(req.body)}`);
      }
      
      return res.json({ success: true, message: 'แก้ไขข้อมูลสำเร็จ' });
    } else {
      return res.json({ success: false, message: 'แก้ไขข้อมูลไม่สำเร็จ' });
    }
  } catch (error) {
    logStudentToDiscord('error', `❌ [updateStudentByAdmin][${req.user.username}]`, `Body : ${JSON.stringify(req.body)}\n ❌ Error updating student : ${error.message}`);
    console.log("updateStudentByAdmin error : " + JSON.stringify(error));
    res.status(500).send(error);
  }
});

async function checkCourseShare(courserefer, studentid) {
  const query = 'SELECT * FROM tcustomer_course WHERE courserefer = ?';
  try {
    const results = await queryPromise(query, [courserefer]);
    if (results.length > 0) {
      if(results[0].coursetype == 'Monthly') {
        let params = [courserefer, courserefer];
        let queryCheckUserd = 'SELECT count(*) as count FROM tstudent WHERE (courserefer = ? OR courserefer2 = ?)'
        if(studentid!=null && studentid !='') {
          queryCheckUserd += 'AND studentid <> ?';
          params.push(studentid);
        }
        const resCheckUserd = await queryPromise(queryCheckUserd, params);
        if (resCheckUserd.length > 0) {
          const count = resCheckUserd[0].count;
          if (count > 0) {
            return { results: false, message: 'คอร์สรายเดือนไม่สามารถแชร์ได้, '+courserefer+' มีผู้ใช้งานแล้ว!' };
          }else{
            return { results: true, message: '' };
          }
        }else{
          return { results: true, message: '' };
        }
      }else{
        return { results: true, message: '' };
      }
    } else {
      return { results: false, message: 'Course not found' };
    }
  } catch (error) {
    console.error('Error in checkCourseShare', error.stack);
    return { results: false, message: 'Internal server error' };
  }
}

app.post('/addBookingByAdmin', verifyToken, async (req, res) => {
  try {
    const { studentid, classid, classdate, classtime, courseid, classday, freeflag } = req.body;
    // ตรวจสอบว่าคลาสเต็มหรือไม่
    const checkClassFullQuery = `
      SELECT 
        tclassinfo.maxperson, 
        COUNT(treservation.classid) AS currentCount 
      FROM tclassinfo 
      LEFT JOIN treservation ON tclassinfo.classid = treservation.classid AND treservation.classdate = ? 
      WHERE tclassinfo.classid = ? AND tclassinfo.classday = ? AND tclassinfo.classtime = ? 
      GROUP BY tclassinfo.maxperson
    `;
    const resCheckClassFull = await queryPromise(checkClassFullQuery, [classdate, classid, classday, classtime]);

    if (resCheckClassFull.length > 0) {
      const { maxperson, currentCount } = resCheckClassFull[0];
      let fullflag = currentCount >= maxperson ? 1 : 0;
      if (currentCount >= maxperson) {
        //return res.json({ success: false, message: 'Sorry, this class is full' });
      }
      if(freeflag == 0) {
        // ตรวจสอบข้อมูลคอร์สของนักเรียน
        const checkCourseQuery = `
          SELECT 
            tstudent.courserefer, 
            tcustomer_course.coursetype, 
            tcustomer_course.remaining, 
            tcustomer_course.expiredate, 
            tcustomer_course.period,
            tcustomer_course.owner,
            tcustomer_course.enable_double_booking
          FROM tstudent 
          INNER JOIN tcustomer_course ON tstudent.courserefer = tcustomer_course.courserefer 
          WHERE tstudent.studentid = ?
        `;
        const resCheckCourse = await queryPromise(checkCourseQuery, [studentid]);

        if (resCheckCourse.length > 0) {
          const { courserefer, coursetype, remaining, expiredate, period, owner } = resCheckCourse[0];
          let newExpireDate = expiredate;

          // ตรวจสอบวันหมดอายุของคอร์ส
          if(owner != 'trial') {
            if (!expiredate) {
              newExpireDate = momentTH(classdate).add(period, 'M').format('YYYY-MM-DD');
              const updateExpireDateQuery = 'UPDATE tcustomer_course SET startdate = ?, expiredate = ? WHERE courserefer = ?';
              await queryPromise(updateExpireDateQuery, [classdate, newExpireDate, courserefer]);
            } else {
              const today = new Date();
              const todayDateOnly = new Date(today.getFullYear(), today.getMonth(), today.getDate());
              if (todayDateOnly > newExpireDate) {
                return res.json({ success: false, message: 'Sorry, your course has expired' });
              }

              console.log('classdate', classdate);
              console.log('newExpireDate', newExpireDate);
              if (momentTH(classdate).isAfter(momentTH(newExpireDate), 'day')) {
                console.log(`Sorry, your course has expired on ${momentTH(newExpireDate).format('DD/MM/YYYY')}`);
                return res.json({ success: false, message: 'Sorry, your course has expire on ' + momentTH(expiredate).format('DD/MM/YYYY') });
              } else {
                console.log('Your course is still valid.');
              }
            }

            // ตรวจสอบจำนวนคลาสที่เหลือ
            if (coursetype !== 'Monthly' && remaining <= 0) {
              return res.json({ success: false, message: 'Sorry, you have no remaining classes' });
            }

            // ตรวจสอบการจองซ้ำในวันเดียวกัน
            const enable_double_booking = resCheckCourse[0].enable_double_booking || 0; // ใช้ค่าเริ่มต้นเป็น 0 ถ้าไม่พบ
            let checkDuplicateReservationQuery = 'SELECT * FROM treservation WHERE studentid = ? AND classdate = ?';
            let params = [studentid, classdate];
            let msg = 'มีชื่อจองคลาสในวันนี้อยู่แล้ว ไม่สามารถจองซ้ำได้';
            if(enable_double_booking == 1) {
              checkDuplicateReservationQuery += ' AND classtime = ?';
              params.push(classtime);
              msg = 'มีชื่ออยู่ในคลาสนี้อยู่แล้ว ไม่สามารถจองซ้ำได้';
            }
            const resCheckDuplicateReservation = await queryPromise(checkDuplicateReservationQuery, params);

            if (resCheckDuplicateReservation.length > 0) {
              return res.json({ success: false, message: msg });
            }
          }

          // เพิ่มการจองคลาส
          const insertReservationQuery = `
            INSERT INTO treservation (studentid, classid, classdate, classtime, courseid, courserefer, createby) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
          `;
          const insertResult = await queryPromise(insertReservationQuery, [studentid, classid, classdate, classtime, courseid, courserefer, req.user.username]);

          if (insertResult.affectedRows > 0) {

            if(owner != 'trial') {
              // อัปเดตจำนวนคลาสที่เหลือ
              const updateRemainingQuery = 'UPDATE tcustomer_course SET remaining = remaining - 1 WHERE courserefer = ?';
              await queryPromise(updateRemainingQuery, [courserefer]);
            }

            // ส่งการแจ้งเตือน
            try {
              const queryNotifyData = `
                SELECT 
                  tstudent.nickname, 
                  CONCAT(IFNULL(tstudent.firstname, ''), ' ', IFNULL(tstudent.middlename, ''), IF(tstudent.middlename<>'', ' ', ''), IFNULL(tstudent.lastname, '')) AS fullname, 
                  tstudent.dateofbirth, 
                  tcourseinfo.course_shortname 
                FROM tstudent 
                INNER JOIN tcustomer_course ON tstudent.courserefer = tcustomer_course.courserefer 
                INNER JOIN tcourseinfo ON tcustomer_course.courseid = tcourseinfo.courseid 
                WHERE tstudent.studentid = ?
              `;
              const notifyResults = await queryPromise(queryNotifyData, [studentid]);
              if (notifyResults.length > 0) {
                const { nickname, fullname, dateofbirth, course_shortname } = notifyResults[0];
                var a = momentTH(classdate).format("YYYYMMDD");
                const bookdate = new Date(a).toLocaleDateString('th-TH', {
                  year: 'numeric',
                  month: 'short',
                  day: 'numeric',
                });

                const message = `${course_shortname}\n${nickname} ${fullname}\nอายุ ${calculateAge(dateofbirth)}ปี\nวันที่ ${bookdate} ${classtime}\nโดยแอดมิน ${req.user.username}`
                logBookingToDiscord('info', `✅ [addBookingByAdmin][${req.user.username}]`, `:calendar_spiral: การจองคลาสสำเร็จ\n${message}`);
              }
            } catch (error) {
              console.error('Error sending notification', error.stack);
            }
            
            if (fullflag == 1) {
              return res.json({ success: true, message: 'จองคลาสสำเร็จ (เป็นการจองคลาสเกิน Maximun)' });
            } else {
              return res.json({ success: true, message: 'จองคลาสสำเร็จ' });
            }
          }
        } else {
          return res.json({ success: false, message: 'Not found customer\'s course' });
        }
      }else {
        // เรียนฟรี
        const insertReservationQuery = `
          INSERT INTO treservation (studentid, classid, classdate, classtime, courseid, freeflag, createby) 
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `;

        const insertResult = await queryPromise(insertReservationQuery, [studentid, classid, classdate, classtime, courseid, freeflag, req.user.username]);
        if (insertResult.affectedRows > 0) {
          // ส่งการแจ้งเตือน
          try {
            const queryNotifyData = `
              SELECT 
                tstudent.nickname, 
                CONCAT(IFNULL(tstudent.firstname, ''), ' ', IFNULL(tstudent.middlename, ''), IF(tstudent.middlename<>'', ' ', ''), IFNULL(tstudent.lastname, '')) AS fullname, 
                tstudent.dateofbirth, 
                tcourseinfo.course_shortname 
              FROM tstudent 
              INNER JOIN tcustomer_course ON tstudent.courserefer = tcustomer_course.courserefer 
              INNER JOIN tcourseinfo ON tcustomer_course.courseid = tcourseinfo.courseid 
              WHERE tstudent.studentid = ?
            `;
            const notifyResults = await queryPromise(queryNotifyData, [studentid]);
            if (notifyResults.length > 0) {
              const { nickname, fullname, dateofbirth, course_shortname } = notifyResults[0];
              var a = momentTH(classdate).format("YYYYMMDD");
              const bookdate = new Date(a).toLocaleDateString('th-TH', {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
              });

              const message = `${course_shortname}\n${nickname} ${fullname}\nอายุ ${calculateAge(dateofbirth)}ปี\nวันที่ ${bookdate} ${classtime}\nโดยแอดมิน ${req.user.username}`
              logBookingToDiscord('info', `✅ [addBookingByAdmin][${req.user.username}]`, `:calendar_spiral: การจองคลาสสำเร็จ\n${message}`);
            }
          } catch (error) {
            console.error('Error sending notification', error.stack);
          }
          return res.json({ success: true, message: 'จองคลาสสำเร็จ' });
        }
      }
    } else {
      return res.json({ success: false, message: 'No class found' });
    }
  } catch (error) {
    logBookingToDiscord('error', `❌ [addBookingByAdmin][${req.user.username}]`, `Body : ${JSON.stringify(req.body)}\n ❌ Error updating student: ${error.message}`);
    console.log("addBookingByAdmin error : " + JSON.stringify(error));
    res.status(500).send(error);
  }
});

app.post('/updateBookingByAdmin', verifyToken, async (req, res) => {
  try {
    const { studentid, classid, classdate, classtime, courseid, classday, reservationid, freeflag } = req.body;

    // ตรวจสอบว่าคลาสเต็มหรือไม่
    const checkClassFullQuery = `
      SELECT 
        tclassinfo.maxperson, 
        COUNT(treservation.classid) AS currentCount 
      FROM tclassinfo 
      LEFT JOIN treservation ON tclassinfo.classid = treservation.classid AND treservation.classdate = ? 
      WHERE tclassinfo.classid = ? AND tclassinfo.classday = ? AND tclassinfo.classtime = ? 
      GROUP BY tclassinfo.maxperson
    `;
    const resCheckClassFull = await queryPromise(checkClassFullQuery, [classdate, classid, classday, classtime]);

    if (resCheckClassFull.length > 0) {
      const { maxperson, currentCount } = resCheckClassFull[0];
      if (currentCount >= maxperson) {
        return res.json({ success: false, message: 'Sorry, this class is full' });
      }

      if(freeflag == 1) {
        // แก้ไขข้อมูลการจอง (เรียนฟรี)
        const insertReservationQuery = `
          UPDATE treservation SET classid = ?, classdate = ?, classtime = ?, courseid = ?, updateby = ? WHERE reservationid = ?
        `;

        const insertResult = await queryPromise(insertReservationQuery, [classid, classdate, classtime, courseid, req.user.username, reservationid]);
        if (insertResult.affectedRows > 0) {
          // ส่งการแจ้งเตือน
          try {
            
            const queryNotifyData = `
              SELECT a.nickname, CONCAT(IFNULL(a.firstname, ''), ' ', IFNULL(a.middlename, ''), IF(a.middlename<>'', ' ', ''), IFNULL(a.lastname, '')) AS fullname, a.dateofbirth, 
                c.course_shortname 
              FROM tstudent a 
              INNER JOIN tcustomer_course b ON a.courserefer = b.courserefer 
              INNER JOIN tcourseinfo c ON b.courseid = c.courseid 
              WHERE a.studentid = ?
            `;
            const results = await queryPromise(queryNotifyData, [studentid]);
            if (results.length > 0) {
              const studentnickname = results[0].nickname;
              const studentname = results[0].fullname;
              const coursename = results[0].course_shortname;
              var a = momentTH(classdate).format("YYYYMMDD");
              const bookdate = new Date(a).toLocaleDateString('th-TH', {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
              });
              // ดึงข้อมูลการจองเดิม
              const queryOldReservation = 'SELECT * FROM treservation WHERE reservationid = ?';
              const results4 = await queryPromise(queryOldReservation, [reservationid]);
              if (results4.length > 0) {
                const oldClassdate = new Date(results4[0].classdate).toLocaleDateString('th-TH', {
                  year: 'numeric',
                  month: 'short',
                  day: 'numeric',
                });
                const oldClasstime = results4[0].classtime;
                
                const message = `${coursename}\n${studentnickname} ${studentname}\nอายุ ${calculateAge(results[0].dateofbirth)}ปี\nจาก ${oldClassdate} ${oldClasstime}\nเป็น ${bookdate} ${classtime}\nโดยแอดมิน ${req.user.username}`
                logBookingToDiscord('info', `✅ [updateBookingByAdmin][${req.user.username}]`, `:pencil: แก้ไขการจองคลาสสำเร็จ(ทดลองเรียนฟรี).\n${message}`);
              }
            }
          } catch (error) {
            console.error('Error sending notification', error.stack);
          }
          return res.json({ success: true, message: 'แก้ไขข้อมูลการจองคลาสสำเร็จ' });
        } else {
          return res.json({ success: false, message: 'แก้ไขข้อมูลการจองคลาสไม่สำเร็จ' });
        }
      } else {
        // ตรวจสอบข้อมูลคอร์สของนักเรียน
        const checkCourseQuery = `
          SELECT 
            tstudent.courserefer, 
            tcustomer_course.coursetype, 
            tcustomer_course.remaining, 
            tcustomer_course.expiredate, 
            tcustomer_course.period,
            tcustomer_course.enable_double_booking
          FROM tstudent 
          INNER JOIN tcustomer_course ON tstudent.courserefer = tcustomer_course.courserefer 
          WHERE tstudent.studentid = ?
        `;
        const resCheckCourse = await queryPromise(checkCourseQuery, [studentid]);

        if (resCheckCourse.length > 0) {
          const { courserefer, coursetype, remaining, expiredate, period } = resCheckCourse[0];
          let newExpireDate = expiredate;

          // ตรวจสอบวันหมดอายุของคอร์ส
          if (!expiredate) {
            newExpireDate = momentTH(classdate).add(period, 'M').format('YYYY-MM-DD');
            const updateExpireDateQuery = 'UPDATE tcustomer_course SET startdate = ?, expiredate = ? WHERE courserefer = ?';
            await queryPromise(updateExpireDateQuery, [classdate, newExpireDate, courserefer]);
          } else {
            const today = new Date();
            const todayDateOnly = new Date(today.getFullYear(), today.getMonth(), today.getDate());
            if (todayDateOnly > newExpireDate) {
              return res.json({ success: false, message: 'Sorry, your course has expired' });
            }

            const classDate = new Date(classdate);
            if (classDate > newExpireDate) {
              return res.json({ success: false, message: `Sorry, your course has expired on ${momentTH(newExpireDate).format('DD/MM/YYYY')}` });
            }
          }

          // ตรวจสอบข้อมูลคอร์สของนักเรียน
          const enable_double_booking = resCheckCourse[0].enable_double_booking || 0; // ใช้ค่าเริ่มต้นเป็น 0 ถ้าไม่พบ
          // ตรวจสอบการจองซ้ำในวันเดียวกัน
          let checkDuplicateReservationQuery = 'SELECT * FROM treservation WHERE studentid = ? AND reservationid <> ? AND classdate = ? ';
          let params = [studentid, reservationid, classdate];
          let msg = 'มีชื่อจองคลาสในวันนี้อยู่แล้ว ไม่สามารถจองซ้ำได้';
          if(enable_double_booking == 1) {
            checkDuplicateReservationQuery += ' AND classtime = ?';
            params.push(classtime);
            msg = 'มีชื่ออยู่ในคลาสนี้อยู่แล้ว ไม่สามารถจองซ้ำได้';
          }
          
          const resCheckDuplicateReservation = await queryPromise(checkDuplicateReservationQuery, params);
          if (resCheckDuplicateReservation.length > 0) {
            return res.json({ success: false, message: msg });
          }

          // ดึงข้อมูลการจองเดิม
          const queryOldReservation = 'SELECT * FROM treservation WHERE reservationid = ?';
          const results4 = await queryPromise(queryOldReservation, [reservationid]);
          if (results4.length > 0) {
            const oldClassdate = new Date(results4[0].classdate).toLocaleDateString('th-TH', {
              year: 'numeric',
              month: 'short',
              day: 'numeric',
            });
            const oldClasstime = results4[0].classtime;

            // อัปเดตการจองคลาส
            const query = 'UPDATE treservation SET classid = ?, classdate = ?, classtime = ?, courseid = ?, updateby = ? WHERE reservationid = ?';
            const insertResult = await queryPromise(query, [classid, classdate, classtime, courseid, req.user.username, reservationid]);

            if (insertResult.affectedRows > 0) {
              // ส่งการแจ้งเตือน
              try {
                const queryNotifyData = `
                  SELECT a.nickname, CONCAT(IFNULL(a.firstname, ''), ' ', IFNULL(a.middlename, ''), IF(a.middlename<>'', ' ', ''), IFNULL(a.lastname, '')) AS fullname, a.dateofbirth, 
                    c.course_shortname 
                  FROM tstudent a 
                  INNER JOIN tcustomer_course b ON a.courserefer = b.courserefer 
                  INNER JOIN tcourseinfo c ON b.courseid = c.courseid 
                  WHERE a.studentid = ?
                `;
                const results = await queryPromise(queryNotifyData, [studentid]);
                if (results.length > 0) {
                  const studentnickname = results[0].nickname;
                  const studentname = results[0].fullname;
                  const coursename = results[0].course_shortname;
                  var a = momentTH(classdate).format("YYYYMMDD");
                  const bookdate = new Date(a).toLocaleDateString('th-TH', {
                    year: 'numeric',
                    month: 'short',
                    day: 'numeric',
                  });

                  const message = `${coursename}\n${studentnickname} ${studentname}\nอายุ ${calculateAge(results[0].dateofbirth)}ปี\nจาก ${oldClassdate} ${oldClasstime}\nเป็น ${bookdate} ${classtime}\nโดยแอดมิน ${req.user.username}`
                  logBookingToDiscord('info', `✅ [updateBookingByAdmin][${req.user.username}]`, `:pencil: แก้ไขการจองคลาสสำเร็จ.\n${message}`);
                }
              } catch (error) {
                console.error('Error sending notification', error.stack);
              }
              return res.json({ success: true, message: 'แก้ไขข้อมูลการจองสำเร็จ' });
            }
          }
        }
      }
    } else {
      return res.json({ success: false, message: 'No class found' });
    }
  } catch (error) {
    logBookingToDiscord('error', `❌ [updateBookingByAdmin][${req.user.username}]`, `Body : ${JSON.stringify(req.body)}\n ❌ Error updating student: ${error.message}`);
    console.log("updateBookingByAdmin error : " + JSON.stringify(error));
    res.status(500).send(error);
  }
});

app.post("/cancelBookingByAdmin", verifyToken, async (req, res) => {
  try {
    const { reservationid, studentid, courserefer } = req.body;
    let message = '';
    const queryNotifyData = `
      SELECT a.nickname, CONCAT(IFNULL(a.firstname, ''), ' ', IFNULL(a.middlename, ''), IF(a.middlename<>'', ' ', ''), IFNULL(a.lastname, '')) AS fullname, a.dateofbirth, 
        c.course_shortname, d.classdate, d.classtime
      FROM tstudent a
      INNER JOIN treservation d ON a.studentid = d.studentid and d.reservationid = ?
      INNER JOIN tcustomer_course b ON a.courserefer = b.courserefer 
      INNER JOIN tcourseinfo c ON b.courseid = c.courseid
      WHERE a.studentid = ?
    `;
    const resultsMsg = await queryPromise(queryNotifyData, [reservationid, studentid]);
    if (resultsMsg.length > 0) {
      const studentnickname = resultsMsg[0].nickname;
      const studentname = resultsMsg[0].fullname;
      const coursename = resultsMsg[0].course_shortname;
      const classdate = resultsMsg[0].classdate;
      const classtime = resultsMsg[0].classtime;
      var a = momentTH(classdate).format("YYYYMMDD");
      const bookdate = new Date(a).toLocaleDateString('th-TH', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
      });
      message = `${coursename}\n${studentnickname} ${studentname}\nอายุ ${calculateAge(resultsMsg[0].dateofbirth)}ปี\n${bookdate} ${classtime}\nโดยแอดมิน ${req.user.username}`
    }
    
    const query = 'DELETE FROM treservation WHERE reservationid = ?';
    const results = await queryPromise(query, [reservationid]);
    console.log("parameters : " + reservationid + " " + studentid + " " + courserefer);
    if (results.affectedRows > 0) {
        const updateRemainingQuery = 'UPDATE tcustomer_course SET remaining = remaining + 1 WHERE courserefer = ? and owner <> \'trial\'';
        await queryPromise(updateRemainingQuery, [courserefer]);
        
        logBookingToDiscord('info', `✅ [cancelBookingByAdmin][${req.user.username}]`, `:put_litter_in_its_place: ยกเลิกการจองคลาสสำเร็จ\nReservationid : ${reservationid}\n${message}`);
        res.json({ success: true, message: 'ยกเลิกการจองสำเร็จ' });
    } else {
      logBookingToDiscord('error', `❌ [cancelBookingByAdmin][${req.user.username}]`, `ยกเลิกการจองคลาสไม่สำเร็จ\nReservationid : ${reservationid}\nไม่มีข้อมูลการจอง`);
      res.json({ success: false, message: 'ไม่มีข้อมูลการจอง' });
    }
  } catch (error) {
    console.error("Error in cancelBookingByAdmin", error.stack);
    logBookingToDiscord('error', `❌ [cancelBookingByAdmin][${req.user.username}]`, `Body : ${JSON.stringify(req.body)}\n ❌ Error updating student: ${error.message}`);
    res.json({ success: false, message: error.message });
  }
});

app.post('/deleteStudent', verifyToken, async (req, res) => {
  const { familyid, studentid, journal } = req.body;
  console.log("deleteStudent : " + JSON.stringify(req.body));
  let queryDeleteStudent = 'UPDATE tstudent SET delflag = 1, courserefer = NULL, updateby = ? WHERE familyid = ? AND studentid = ?';
  let params = [req.user.username, familyid, studentid];
  if (journal === '1') {
    queryDeleteStudent = 'DELETE FROM jstudent WHERE familyid = ? AND studentid = ?';
    params = [familyid, studentid];
  }
  try {
    const results = await queryPromise(queryDeleteStudent, params);
    if (results.affectedRows > 0) {
      // if (journal != '1') {
      //   const queryDeleteTreservation = 'DELETE FROM treservation WHERE studentid = ?';
      //   await queryPromise(queryDeleteTreservation, [studentid]);
      // }
      logStudentToDiscord('info', `✅ [cancelBookingByAdmin][${req.user.username}]`, 'Delete Studentid '+studentid+' Successfuly.')
      return res.json({ success: true, message: 'Family member deleted successfully' });
    } else {
      return res.json({ success: false, message: 'No Family member data' });
    }
  } catch (error) {
    logStudentToDiscord('error', `❌ [cancelBookingByAdmin][${req.user.username}]`, `Body : ${JSON.stringify(req.body)}\n ❌ Error updating student: ${error.message}`);
    console.error('Error in deleteStudent', error.stack);
    return res.status(500).send(error);
  }
});

app.post('/getMemberInfo', verifyToken, async (req, res) => {
  const { studentid } = req.body;
  const query = 'SELECT * FROM treservations WHERE studentid = ?';
  try {
    const results = await queryPromise(query, [studentid]);
    if (results.length > 0) {
      res.json({ success: true, message: 'Get Member Info successful', results });
    } else {
      res.json({ success: false, message: 'No Member Info' });
    }
  } catch (error) {
    console.error('Error in getMemberInfo', error.stack);
    res.status(500).send(error);
  }
});

app.post('/getMemberReservationDetail', verifyToken, async (req, res) => {
  const { studentid, courserefer } = req.body;
  const query = 'SELECT * FROM treservation WHERE studentid = ? and courserefer = ? order by classdate desc limit 10';
  try {
    const results = await queryPromise(query, [studentid, courserefer]);
    if (results.length > 0) {
      res.json({ success: true, message: 'Get Reservation Detail successful', results });
    } else {
      res.json({ success: true, message: 'No Reservation Detail' });
    }
  } catch (error) {
    res.json({ success: false, message: error.message });
    console.error('Error in getMemberReservationDetail', error.stack);
  }
});

app.post('/addBookingByCustomer', verifyToken, async (req, res) => {
  try {
    const { courseid, classid, classday, classdate, classtime, studentid } = req.body;

    // ตรวจสอบว่าคลาสเต็มหรือไม่
    const checkClassFullQuery = `
      SELECT 
        tclassinfo.maxperson, 
        COUNT(treservation.classid) AS currentCount 
      FROM tclassinfo 
      LEFT JOIN treservation ON tclassinfo.classid = treservation.classid AND treservation.classdate = ? 
      WHERE tclassinfo.classid = ? AND tclassinfo.classday = ? AND tclassinfo.classtime = ? 
      GROUP BY tclassinfo.maxperson
    `;
    const resCheckClassFull = await queryPromise(checkClassFullQuery, [classdate, classid, classday, classtime], true);

    if (resCheckClassFull.length > 0) {
      const { maxperson, currentCount } = resCheckClassFull[0];
      if (currentCount >= maxperson) {
        return res.json({ success: false, message: 'Sorry, this class is full' });
      }

      // ตรวจสอบข้อมูลคอร์สของนักเรียน
      const checkCourseQuery = `
        SELECT 
          tstudent.courserefer, 
          tcustomer_course.coursetype, 
          tcustomer_course.remaining, 
          tcustomer_course.expiredate, 
          tcustomer_course.period,
          tcustomer_course.enable_double_booking 
        FROM tstudent 
        INNER JOIN tcustomer_course ON tstudent.courserefer = tcustomer_course.courserefer 
        WHERE tstudent.studentid = ?
      `;
      const resCheckCourse = await queryPromise(checkCourseQuery, [studentid]);

      if (resCheckCourse.length > 0) {
        const { courserefer, coursetype, remaining, expiredate, period } = resCheckCourse[0];
        let newExpireDate = expiredate;

        // ตรวจสอบวันหมดอายุของคอร์ส
        if (!expiredate) {
          newExpireDate = momentTH(classdate).add(period, 'M').format('YYYY-MM-DD');
          const updateExpireDateQuery = 'UPDATE tcustomer_course SET startdate = ?, expiredate = ? WHERE courserefer = ?';
          await queryPromise(updateExpireDateQuery, [classdate, newExpireDate, courserefer]);
        } else {
          const today = new Date();
          const todayDateOnly = new Date(today.getFullYear(), today.getMonth(), today.getDate());
          if (todayDateOnly > newExpireDate) {
            return res.json({ success: false, message: 'Sorry, your course has expired' });
          }

          console.log("classDate : " + classdate);
          console.log("newExpireDate : " + newExpireDate);
          if (momentTH(classdate).isAfter(momentTH(newExpireDate), 'day')) {
            console.log(`Sorry, your course has expired on ${moment(newExpireDate).format('DD/MM/YYYY')}`);
            return res.json({ success: false, message: 'Sorry, your course has expire on ' + momentTH(expiredate).format('DD/MM/YYYY') });
          } else {
            console.log('Your course is still valid.');
          }
        }

        // ตรวจสอบจำนวนคลาสที่เหลือ
        if (coursetype !== 'Monthly' && remaining <= 0) {
          return res.json({ success: false, message: 'Sorry, you have no remaining classes' });
        }

        // ตรวจสอบการจองซ้ำในวันเดียวกัน
        const enable_double_booking = resCheckCourse[0].enable_double_booking || 0; // ใช้ค่าเริ่มต้นเป็น 0 ถ้าไม่พบ
        let checkDuplicateReservationQuery = 'SELECT * FROM treservation WHERE studentid = ? AND classdate = ?';
        let params = [studentid, classdate];
        let msg = 'มีชื่อจองคลาสในวันนี้อยู่แล้ว ไม่สามารถจองซ้ำได้';
        if(enable_double_booking == 1) {
          checkDuplicateReservationQuery += ' AND classtime = ?';
          params.push(classtime);
          msg = 'มีชื่ออยู่ในคลาสนี้อยู่แล้ว ไม่สามารถจองซ้ำได้';
        }
        const resCheckDuplicateReservation = await queryPromise(checkDuplicateReservationQuery, params);

        if (resCheckDuplicateReservation.length > 0) {
          return res.json({ success: false, message: msg });
        }

        // เพิ่มการจองคลาส
        const insertReservationQuery = `
          INSERT INTO treservation (studentid, classid, classdate, classtime, courseid, courserefer, createby) 
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `;
        const insertResult = await queryPromise(insertReservationQuery, [studentid, classid, classdate, classtime, courseid, courserefer, req.user.username]);

        if (insertResult.affectedRows > 0) {
          // อัปเดตจำนวนคลาสที่เหลือ
          const updateRemainingQuery = 'UPDATE tcustomer_course SET remaining = remaining - 1 WHERE courserefer = ?';
          await queryPromise(updateRemainingQuery, [courserefer]);

          // ส่งการแจ้งเตือน
          
          try {
            const queryNotifyData = `
              SELECT 
                tstudent.nickname, 
                CONCAT(IFNULL(tstudent.firstname, ''), ' ', IFNULL(tstudent.middlename, ''), IF(tstudent.middlename<>'', ' ', ''), IFNULL(tstudent.lastname, '')) AS fullname, 
                tstudent.dateofbirth, 
                tcourseinfo.course_shortname 
              FROM tstudent 
              INNER JOIN tcustomer_course ON tstudent.courserefer = tcustomer_course.courserefer 
              INNER JOIN tcourseinfo ON tcustomer_course.courseid = tcourseinfo.courseid 
              WHERE tstudent.studentid = ?
            `;
            const notifyResults = await queryPromise(queryNotifyData, [studentid]);
            console.log("notifyResults lenght: " + notifyResults.length);
            if (notifyResults.length > 0) {
              const { nickname, fullname, dateofbirth, course_shortname } = notifyResults[0];
              var a = momentTH(classdate).format("YYYYMMDD");
              const bookdate = new Date(a).toLocaleDateString('th-TH', {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
              });

              const message = `${course_shortname}\n${nickname} ${fullname}\nอายุ ${calculateAge(dateofbirth)}ปี\nวันที่ ${bookdate} ${classtime}\nโดยผู้ปกครอง ${req.user.username}`
              logBookingToDiscord('info', `✅ [addBookingByCustomer][${req.user.username}]`, `:calendar_spiral: การจองคลาสสำเร็จ\n${message}`);
            }
          } catch (error) {
            logBookingToDiscord('error', `❌ [addBookingByCustomer][${req.user.username}]`, 'Error sending notification', error.message);
            console.error('Error sending notification', error.stack);
          }
          return res.json({ success: true, message: 'Booking added successfully' });
        }
      }
    }

    return res.json({ success: false, message: 'Error in processing booking' });
  } catch (error) {
    logBookingToDiscord('error', `❌ [addBookingByCustomer][${req.user.username}]`, `Body : ${JSON.stringify(req.body)}\n ❌ Error create booking: ${error.message}`)
    console.log("addBookingByCustomer error : " + JSON.stringify(error));
    res.status(500).send(error);
  }
});

app.post('/deleteReservation', verifyToken, async (req, res) => {
  const { reservationid } = req.body;
  const query = 'DELETE FROM treservation WHERE reservationid = ?';
  try {
    const results = await queryPromise(query, [reservationid]);
    if (results.affectedRows > 0) {
      logBookingToDiscord('info', `✅ [deleteReservation][${req.user.username}]`, 'Delete Booking Successfully.')
      res.json({ success: true, message: 'Reservation deleted successfully' });
    } else {
      res.json({ success: false, message: 'No reservation found with the given ID' });
    }
  } catch (error) {
    logBookingToDiscord('error', `❌ [deleteReservation][${req.user.username}]`, `Body : ${JSON.stringify(req.body)}\n ❌ Error delete booking: ${error.message}`)
    console.error('Error in deleteReservation', error.stack);
    res.status(500).send(error);
  }
});

app.post('/checkDuplicateReservation', verifyToken, async (req, res) => {
  const { studentid, classdate, classtime } = req.body;
  try {
    const checkCourseQuery = `
        SELECT 
          tstudent.courserefer, 
          tcustomer_course.coursetype, 
          tcustomer_course.remaining, 
          tcustomer_course.expiredate, 
          tcustomer_course.period,
          tcustomer_course.owner,
          tcustomer_course.enable_double_booking
        FROM tstudent 
        INNER JOIN tcustomer_course ON tstudent.courserefer = tcustomer_course.courserefer 
        WHERE tstudent.studentid = ?
      `;
    const resCheckCourse = await queryPromise(checkCourseQuery, [studentid]);
    // ตรวจสอบการจองซ้ำในวันเดียวกัน
    const enable_double_booking = resCheckCourse[0].enable_double_booking || 0; // ใช้ค่าเริ่มต้นเป็น 0 ถ้าไม่พบ
    let checkDuplicateReservationQuery = 'SELECT * FROM treservation WHERE studentid = ? AND classdate = ?';
    let params = [studentid, classdate];
    let msg = 'มีชื่อจองคลาสในวันนี้อยู่แล้ว ไม่สามารถจองซ้ำได้';
    if(enable_double_booking == 1) {
      checkDuplicateReservationQuery += ' AND classtime = ?';
      params.push(classtime);
      msg = 'มีชื่ออยู่ในคลาสนี้อยู่แล้ว ไม่สามารถจองซ้ำได้';
    }
    const resCheckDuplicateReservation = await queryPromise(checkDuplicateReservationQuery, params);

    if (resCheckDuplicateReservation.length > 0) {
      return res.json({ success: false, message: msg });
    }else{
      return res.json({ success: true, message: 'No duplicate reservation found' });
    }
  
  } catch (error) {
    console.error('Error in checkDuplicateReservation', error.stack);
    return res.status(500).send(error);
  }
});

app.get('/getAllCourses', verifyToken, async (req, res) => {
  const query = 'SELECT * FROM tcourseinfo';
  try {
    const results = await queryPromise(query, null);
    if (results.length > 0) {
      return res.json({ success: true, message: 'Get All Course successful', results });
    } else {
      return res.json({ success: false, message: 'No Course' });
    }
  } catch (error) {
    console.error('Error in getAllCourses', error.stack);
    return res.status(500).send(error);
  }
});

app.post('/addCourse', verifyToken, async (req, res) => {
  const { coursename, course_shortname } = req.body;
  const query = 'INSERT INTO tcourseinfo (coursename, course_shortname) VALUES (?, ?)';
  try {
    const results = await queryPromise(query, [coursename, course_shortname]);
    logCourseToDiscord('info', `✅ [addCourse][${req.user.username}]`, 'Add Course Successfully');
    res.json({ success: true, message: 'Course added successfully' });
  } catch (error) {
    logCourseToDiscord('error', `❌ [addCourse][${req.user.username}]`, `Body : ${JSON.stringify(req.body)}\n ❌ Error add course: ${error.message}`)
    console.error('Error in addCourse', error.stack);
    res.status(500).send(error);
  }
});

app.post('/updateCourse', verifyToken, async (req, res) => {
  const { coursename, course_shortname, courseid } = req.body;
  const query = 'UPDATE tcourseinfo SET coursename = ?, course_shortname = ? WHERE courseid = ?';
  try {
    const results = await queryPromise(query, [coursename, course_shortname, courseid]);
    logCourseToDiscord('info', `✅ [updateCourse][${req.user.username}]`, 'Update Course Successfully');
    res.json({ success: true, message: 'Course updated successfully' });
  } catch (error) {
    logCourseToDiscord('error', `❌ [updateCourse][${req.user.username}]`, `Body : ${JSON.stringify(req.body)}\n ❌ Error update course: ${error.message}`)
    console.error('Error in updateCourse', error.stack);
    res.status(500).send(error);
  }
});

app.post('/deleteCourse', verifyToken, async (req, res) => {
  const { courseid } = req.body;
  const deletetcourseinfoQuery = 'UPDATE tcourseinfo SET enableflag = 0 WHERE courseid = ?';
  const deleteTclassinfoQuery = 'UPDATE tclassinfo SET enableflag = 0 WHERE courseid = ?';
  try {
    await queryPromise(deletetcourseinfoQuery, [courseid]);
    await queryPromise(deleteTclassinfoQuery, [courseid]);
    logCourseToDiscord('info', `✅ [deleteCourse][${req.user.username}]`, 'Delete Course Successfully');
    res.json({ success: true, message: 'Course disabled successfully' });
  } catch (error) {
    logCourseToDiscord('error', `❌ [deleteCourse][${req.user.username}]`, `Body : ${JSON.stringify(req.body)}\n ❌ Error delete course: ${error.message}`)
    console.error('Error in deleteCourse', error.stack);
    res.status(500).send(error);
  }
});

app.get('/getAllClasses', verifyToken, async (req, res) => {
  const query = 'SELECT b.courseid, b.coursename, a.* FROM tclassinfo a inner join tcourseinfo b on a.courseid = b.courseid order by b.coursename , a.classday';
  try {
    const results = await queryPromise(query, null);
    if (results.length > 0) {
      return res.json({ success: true, message: 'Get All Class successful', results });
    } else {
      return res.json({ success: true, message: 'No Class', results });
    }
  } catch (error) {
    console.error('Error in getAllClasses', error.stack);
    return res.status(500).send(error);
  }
});

app.post('/addClass', verifyToken, async (req, res) => {
  const { courseid, classday, classtime, maxperson, adminflag } = req.body;
  const query = 'INSERT INTO tclassinfo (courseid, classday, classtime, maxperson, adminflag) VALUES (?, ?, ?, ?, ?)';
  try {
    const results = await queryPromise(query, [courseid, classday, classtime, maxperson, adminflag]);
    return res.json({ success: true, message: 'Class added successfully' });
  } catch (error) {
    console.error('Error in addClass', error.stack);
    res.status(500).send(error);
  }
});

app.post('/updateClass', verifyToken, async (req, res) => {
  const { classid, courseid, classday, classtime, maxperson, adminflag } = req.body;
  const query = 'UPDATE tclassinfo SET courseid = ?, classday = ?, classtime = ?, maxperson = ?, adminflag = ? WHERE classid = ?';
  try {
    const results = await queryPromise(query, [courseid, classday, classtime, maxperson, adminflag, classid]);
    res.json({ success: true, message: 'Class updated successfully' });
  } catch (error) {
    console.error('Error in updateClass', error.stack);
    res.status(500).send(error);
  }
});

app.post('/deleteClass', verifyToken, async (req, res) => {
  const { classid } = req.body;
  const deleteClassQuery = 'DELETE FROM tclassinfo WHERE classid = ?';
  const deleteReservationQuery = 'DELETE FROM treservation WHERE classid = ?';
  try {
    await queryPromise(deleteClassQuery, [classid]);
    await queryPromise(deleteReservationQuery, [classid]);
    res.json({ success: true, message: 'Class deleted successfully' });
  } catch (error) {
    console.error('Error in deleteClass', error.stack);
    res.status(500).send(error);
  }
});

app.post('/getClassTime', verifyToken, async (req, res) => {
  const { classdate, classday, courseid } = req.body;
  let query = `
    SELECT a.*, 
      CASE 
        WHEN count(b.reservationid) > 0 THEN a.maxperson - count(b.reservationid) 
        ELSE a.maxperson 
      END AS available,
      CASE 
        WHEN d.classid IS NOT NULL THEN 0 
        ELSE CASE 
          WHEN count(b.reservationid) > 0 THEN a.maxperson - count(b.reservationid) 
          ELSE a.maxperson 
        END 
      END AS adjusted_available,
      d.description
    FROM tclassinfo a 
    LEFT JOIN treservation b ON a.classid = b.classid 
      AND b.classdate = ? 
    LEFT JOIN tclassdisable d ON a.classid = d.classid 
      AND d.classdate = ? 
      AND d.courseid = ? 
    WHERE a.classday = ? 
      AND a.courseid = ? 
  `;
  if (req.user.adminflag != '1') {
    query += 'AND a.adminflag = 0 ';
  }
  query += 'GROUP BY a.classid, a.classday, a.classtime, a.maxperson, a.courseid, d.description ';

  try {
    const results = await queryPromise(query, [classdate, classdate, courseid, classday, courseid]);
    if (results.length > 0) {
      results.forEach((element, index) => {
        // ใช้ adjusted_available แทน available 
        results[index].text = element.classtime + ' ว่าง ' + element.adjusted_available + ' คน';
        if (element.description) {
          results[index].text += ' (' + element.description + ')'; // เพิ่ม description
        }
        results[index].available = element.adjusted_available; // อัปเดตค่า available
      });
      res.json({ success: true, message: 'Get Class Time successful', results });
    } else {
      res.json({ success: true, message: 'No Class Time', results: [] });
    }
  } catch (error) {
    console.error('Error in getClassTime', error.stack);
    res.status(500).send(error);
  }
});

app.get("/getNewStudentList", verifyToken, async (req, res) => {
  const query = `
    SELECT a.*, 
      CONCAT(IFNULL(a.firstname, ''), ' ', IFNULL(a.middlename, ''), IF(a.middlename<>'', ' ',''), IFNULL(a.lastname, ''), ' (', a.nickname,')') AS fullname, 
      c.username, c.mobileno 
    FROM jstudent a 
    LEFT JOIN tfamily b ON a.familyid = b.familyid 
    LEFT JOIN tuser c ON b.username = c.username
  `;
  try {
    const results = await queryPromise(query, null);
    if (results.length > 0) {
      res.json({ success: true, message: 'Get New Students successful', results });
    } else {
      res.json({ success: true, message: 'No New Students', results });
    }
  } catch (error) {
    console.error('Error in getNewStudentList', error.stack);
    res.status(500).send(error);
  }
});

app.get("/courseLookup", verifyToken, async (req, res) => {
  const query = 'SELECT * FROM tcourseinfo WHERE enableflag = 1';
  try {
    const results = await queryPromise(query, null);
    if (results.length > 0) {
      res.json({ success: true, message: 'Get Course Lookup successful', results });
    } else {
      res.json({ success: true, message: 'No Course Lookup' });
    }
  } catch (error) {
    console.error('Error in courseLookup', error.stack);
    res.status(500).send(error);
  }
});

app.get("/customerCourseLookup", verifyToken, async (req, res) => {
  const query = 'SELECT * FROM tcustomer_course WHERE finish = 0';
  try {
    const results = await queryPromise(query, null);
    if (results.length > 0) {
      res.json({ success: true, message: 'Get Customer Course Lookup successful', results });
    } else {
      res.json({ success: true, message: 'No Customer Course Lookup' });
    }
  } catch (error) {
    console.error('Error in customerCourseLookup', error.stack);
    res.status(500).send(error);
  }
});

app.post('/getCustomerCourseInfo', verifyToken, async (req, res) => {
  const { studentid } = req.body;
  const query = 'SELECT * FROM tcustomer_course WHERE courserefer = (SELECT courserefer FROM tstudent WHERE studentid = ?)';
  try {
    const results = await queryPromise(query, [studentid]);
    res.json({ success: true, results });
  } catch (error) {
    console.error('Error in getCustomerCourseInfo', error.stack);
    res.status(500).send(error);
  }
});

app.post('/finishCustomerCourse', verifyToken, async (req, res) => {
  const { courserefer } = req.body;
  if (!courserefer.includes('รายครั้ง')) {
    const query = 'UPDATE tcustomer_course SET finish = 1 WHERE courserefer = ?';
    try {
      const results = await queryPromise(query, [courserefer]);
      if (results.affectedRows > 0) {
        const query2 = 'UPDATE tstudent SET courserefer = NULL WHERE courserefer = ?';
        await queryPromise(query2, [courserefer]);
        // Send log to Discord
        const logMessage = `:open_file_folder: จบคอร์ส ${courserefer}`;
        logCourseToDiscord('info', `[finishCustomerCourse][${req.user.username}]`, logMessage);
        res.json({ success: true, message: 'Course finished successfully' });
      } else {
        res.json({ success: false, message: 'No course found with the given reference' });
      }
    } catch (error) {
      console.error('Error in finishCustomerCourse', error.stack);
      res.status(500).send(error);
    }
  } else {
    res.json({ success: false, message: 'ไม่สามารถจบคอร์สรายครั้ง' });
  }
});

app.get("/getFinishedCourse", verifyToken, async (req, res) => {
  const query = 'SELECT * FROM tcustomer_course WHERE finish = 1';
  try {
    const results = await queryPromise(query, null);
    res.json({ success: true, results });
  } catch (error) {
    console.error('Error in getFinishedCourse', error.stack);
    res.status(500).send(error);
  }
});

app.get("/familyLookup", verifyToken, async (req, res) => {
  const query = 'SELECT * FROM tfamily';
  try {
    const results = await queryPromise(query, null);
    if (results.length > 0) {
      res.json({ success: true, message: 'Get Family Lookup successful', results });
    } else {
      res.json({ success: true, message: 'No Family Lookup' });
    }
  } catch (error) {
    console.error('Error in familyLookup', error.stack);
    res.status(500).send(error);
  }
});

app.post("/studentLookup", verifyToken, async (req, res) => {
  const { familyid } = req.body;
  let query = `
    SELECT studentid, 
      CONCAT(IFNULL(nickname, ''), ' ', IFNULL(firstname, ''), ' ', IFNULL(middlename, ''), IF(middlename<>'', ' ', ''), IFNULL(lastname, '')) AS name 
    FROM tstudent 
    WHERE delflag = 0
  `;
  const params = [];
  if (familyid) {
    query += ' AND familyid = ?';
    params.push(familyid);
  }

  try {
    const results = await queryPromise(query, params);
    if (results.length > 0) {
      res.json({ success: true, message: 'Get Student Lookup successful', results });
    } else {
      res.json({ success: true, message: 'No Student Lookup' });
    }
  } catch (error) {
    console.error('Error in studentLookup', error.stack);
    res.status(500).send(error);
  }
});

app.get("/getStudentList", verifyToken, async (req, res) => {
  try {
    const query = `
      SELECT 
        a.studentid, 
        a.familyid, 
        a.firstname, 
        a.middlename, 
        a.lastname, 
        a.nickname, 
        a.gender, 
        a.dateofbirth, 
        a.courserefer, 
        a.courserefer2, 
        a.shortnote, 
        CONCAT(IFNULL(a.firstname,''), ' ', IFNULL(a.middlename,''), IF(a.middlename<>'', ' ',''), IFNULL(a.lastname,'')) AS fullname, 
        CASE 
          WHEN b.coursetype = 'Monthly' THEN 'รายเดือน' 
          WHEN b.coursetype IS NULL THEN 'ไม่มีคอร์ส' 
          ELSE CONCAT(b.remaining, ' ครั้ง') 
        END AS remaining_label, 
        b.remaining, 
        b.expiredate, 
        t.coursename, 
        d.mobileno, 
        a.shortnote, 
        a.level 
      FROM tstudent a 
      LEFT JOIN tcustomer_course b ON a.courserefer = b.courserefer 
      LEFT JOIN tcourseinfo t ON b.courseid = t.courseid 
      LEFT JOIN tfamily c ON a.familyid = c.familyid 
      LEFT JOIN tuser d ON c.username = d.username 
      WHERE a.delflag = 0 
      ORDER BY a.createdate DESC
    `;
    const results = await queryPromise(query);

    if (results.length > 0) {
      res.json({ success: true, message: 'Get Student list successful', results });
    } else {
      res.json({ success: true, message: 'No Student list', results });
    }
  } catch (error) {
    console.error("Error in getStudentList", error.stack);
    res.status(500).send(error);
  }
});

app.get("/getStudentInfo/:studentid", verifyToken, async (req, res) => {
  const { studentid } = req.params;
  console.log("studentid : " + studentid);
  try {
    const query = `
      SELECT 
        a.studentid, 
        a.familyid, 
        a.firstname, 
        a.middlename, 
        a.lastname, 
        a.nickname, 
        a.gender, 
        a.dateofbirth, 
        a.courserefer, 
        a.courserefer2, 
        a.shortnote,
        CONCAT(IFNULL(a.firstname,''), ' ', IFNULL(a.middlename,''), IF(a.middlename<>'', ' ',''), IFNULL(a.lastname,''), ' (', a.nickname,')') AS fullname, 
        CASE 
          WHEN b.coursetype = 'Monthly' THEN 'รายเดือน' 
          WHEN b.coursetype IS NULL THEN 'ไม่มีคอร์ส' 
          ELSE CONCAT(b.remaining, ' ครั้ง') 
        END AS remaining_label, 
        b.remaining, 
        b.expiredate, 
        t.coursename, 
        d.mobileno, 
        a.shortnote, 
        a.level,
        a.delflag
      FROM tstudent a 
      LEFT JOIN tcustomer_course b ON a.courserefer = b.courserefer 
      LEFT JOIN tcourseinfo t ON b.courseid = t.courseid 
      LEFT JOIN tfamily c ON a.familyid = c.familyid 
      LEFT JOIN tuser d ON c.username = d.username
      WHERE a.studentid = ?
      ORDER BY a.createdate DESC
    `;
    const results = await queryPromise(query, [studentid]);
    if (results.length > 0) {
      res.json({ success: true, message: 'Get Student list successful', results });
    } else {
      res.json({ success: true, message: 'No Student list', results });
    }
  } catch (error) {
    console.error("Error in getStudentList", error.stack);
    res.status(500).send(error);
  }
});

app.post("/getReservationList", verifyToken, async (req, res) => {
  try {
    const { classdate } = req.body;
    const query = `
      SELECT a.*, b.coursename, 
        CONCAT(IFNULL(c.firstname, ''), ' ', IFNULL(c.middlename,''), IF(c.middlename<>'', ' ', ''), IFNULL(c.lastname, ''), ' (', IFNULL(c.nickname,'') ,')') AS fullname, 
        c.dateofbirth, 
        CASE WHEN c.gender = 'ชาย' THEN 'ช.' ELSE 'ญ.' END AS gender 
      FROM treservation a
      LEFT JOIN tcourseinfo b ON a.courseid = b.courseid
      LEFT JOIN tstudent c ON a.studentid = c.studentid
      WHERE a.classdate = ?
      ORDER BY a.classtime ASC
    `;

    const results = await queryPromise(query, [classdate]);

    // Add age field to each result
    results.forEach(result => {
      result.fullname = `${result.fullname} (${result.gender} ${calculateAge(result.dateofbirth)})`;
    });

    if (results.length > 0) {
      res.json({ success: true, message: 'Get Reservation list successful', results });
    } else {
      res.json({ success: true, message: 'No Reservation list', results });
    }
  } catch (error) {
    console.error("Error in getReservationList", error.stack);
    res.status(500).send(error);
  }
});

app.post("/checkinByAdmin", verifyToken, async (req, res) => {
  try {
    const { reservationid, studentid } = req.body;
    const query = 'UPDATE treservation SET checkedin = 1 WHERE reservationid = ? AND studentid = ?';
    const results = await queryPromise(query, [reservationid, studentid]);

    if (results.affectedRows > 0) {
      logSystemToDiscord('info', `✅ [checkinByAdmin][${req.user.username}]`, `Admin checked in reservation ID ${reservationid} for student ID ${studentid}`);
      res.json({ success: true, message: 'Checkin successful' });
    } else {
      res.json({ success: false, message: 'No Booking data' });
    }
  }
  catch (error) {
    console.error("Error in checkinByAdmin" + JSON.stringify(error));
    res.status(500).send(error);
  }
});

app.post("/undoCheckinByAdmin", verifyToken, async (req, res) => {
  try {
    const { reservationid, studentid } = req.body;
    const query = 'UPDATE treservation SET checkedin = 0 WHERE reservationid = ? AND studentid = ?';
    const results = await queryPromise(query, [reservationid, studentid]);

    if (results.affectedRows > 0) {
      logSystemToDiscord('info', `✅ [undoCheckinByAdmin][${req.user.username}]`, `Admin unchecked reservation ID ${reservationid} for student ID ${studentid}`);
      res.json({ success: true, message: 'Cancel Checkin successful' });
    } else {
      res.json({ success: false, message: 'No Booking data' });
    }
  }
  catch (error) {
    console.error("Error in checkinByAdmin" + JSON.stringify(error));
    res.status(500).send(error);
  }
});

app.post("/refreshCardDashboard", verifyToken, async (req, res) => {
  const { today, tomorrow } = req.body;
  var datacard = {
    totalStudents: 0,
    totalBookingToday: 0,
    totalBookingTomorrow: 0,
    totalWaitingNewStudents: 0,
    totalWaitCancelBooking: 0
  };

  try {
    // Combined query to get all necessary data in one go
    const query = `
      SELECT 
        (SELECT count(*) FROM tstudent WHERE delflag = 0) AS totalStudents,
        (SELECT count(*) FROM treservation WHERE classdate = ?) AS totalBookingToday,
        (SELECT count(*) FROM treservation WHERE classdate = ?) AS totalBookingTomorrow,
        (SELECT count(*) FROM jstudent) AS totalWaitingNewStudents
    `;
    const results = await queryPromise(query, [today, tomorrow], false);

    if (results.length > 0) {
      datacard.totalStudents = results[0].totalStudents;
      datacard.totalBookingToday = results[0].totalBookingToday;
      datacard.totalBookingTomorrow = results[0].totalBookingTomorrow;
      datacard.totalWaitingNewStudents = results[0].totalWaitingNewStudents;
    }

    // Send the response after all queries are completed
    console.log("API datacard: " + JSON.stringify(datacard));
    res.json({ success: true, message: 'Refresh Card Dashboard successful', datacard });
  } catch (error) {
    console.error("Error in refreshCardDashboard", error.stack);
    res.status(500).send(error);
    throw error;
  }
});

app.post('/getBookingListAdmin', verifyToken, async (req, res) => {
  //console.log("getBookingListAdmin [request] : " + JSON.stringify(req.body));
  try {
    const { classday, classdate } = req.body;

    // Query to get all necessary data in one go
    const query = `
      SELECT 
        a.classtime, 
        a.courseid, 
        CONCAT(a.classtime, ' (', b.course_shortname, ')') as class_label, 
        a.classid,
        c.nickname,
        c.studentid,
        c.shortnote,
        c.courserefer as currnent_courserefer,
        r.courserefer as booking_courserefer,
        r.checkedin,
        r.freeflag,
        c.dateofbirth,
        CASE WHEN c.gender = 'ชาย' THEN 'ช.' ELSE 'ญ.' END as gender,
        cc.color,
        cc.expiredate,
        cc.remaining,
        cc.paid,
        cc.coursetype
        
      FROM tclassinfo a
      JOIN tcourseinfo b ON a.courseid = b.courseid AND b.enableflag = 1
      LEFT JOIN treservation r ON a.classid = r.classid AND r.classdate = ?
      LEFT JOIN tstudent c ON r.studentid = c.studentid
      LEFT JOIN tcustomer_course cc ON r.courserefer = cc.courserefer
      WHERE a.classday = ? AND a.enableflag = 1
      ORDER BY a.classtime, r.classtime ASC
    `;
    const results = await queryPromise(query, [classdate, classday], true);

    // Process results to create booking list
    const getName = async (nickname, currnent_courserefer, booking_courserefer, checkedin, color, remaining, freeflag, coursetype, expiredate, paid) => {
      let name = nickname;
      let warning_msg = "";
      // เช็คว่า ไม่ใช่คอร์สทดลอง และ ไม่ใช่คอร์สฟรี
      if ((booking_courserefer && !booking_courserefer.includes('ทดลอง')) || freeflag != 1) {
        if (currnent_courserefer != booking_courserefer) {
          // # ---- ถ้า คอร์สที่จอง ไม่ใช่คอร์สปัจจุบัน ให้ใช้คอร์สปัจจุบันเช็คแทน ---- #
          const query2 = 'SELECT * from tcustomer_course where courserefer = ?';
          const results2 = await queryPromise(query2, [currnent_courserefer]);
          if (results2.length > 0) {
            const courseType = results2[0].coursetype;
            if(courseType === "Monthly" && isExpired(results2[0].expiredate)){
              name += '(pay)';
              warning_msg = "คอรส์หมดอายุการใช้งาน";
            }
            if(courseType !== "Monthly"){
              const newRemaining = results2[0].remaining;
              
              if (newRemaining <= 0) {
                name += '(pay)';
                warning_msg = "คอรส์คอร์สเหลือ 0 ครั้ง";
              }
            }
            const paid = results2[0].paid;
            if(paid === 0){
              name += '(pay)';
              warning_msg = "ยังไม่ได้ชำระค่าคอร์ส";
            }
          }
        }else{
          // # ---- ถ้า คอร์สที่จอง เป็นคอร์สปัจจุบัน ---- #
          if(coursetype !== "Monthly" && remaining <= 0){
            name += '(pay)';
            if(booking_courserefer.includes('รายครั้ง')){
              warning_msg = "[" + booking_courserefer + "]";
            }else{
              warning_msg = "คอร์สเหลือ 0 ครั้ง";
            }
          }else if(isExpired(expiredate)){
            name += '(pay)';
            if(coursetype === "Monthly") {
              warning_msg = "คอรส์หมดอายุการใช้งาน";
            }else{
              if(remaining <= 0){
                warning_msg = "คอร์สคงเหลือ 0 และ หมดอายุการใช้งาน";
              }else{
                warning_msg = "คอรส์หมดอายุการใช้งาน";
              }
            }
          }else if (paid === 0){
            name += '(pay)';
            warning_msg = "ยังไม่ได้ชำระค่าคอร์ส";
          }
        }
      }
      if (checkedin == 1) name += `(${checkedin})`;
      if (color != null) name += `(${color})`;
      if (freeflag == 1) name += '(blue)';
      const result = { nickname : name , msg: warning_msg };
      return result;
    };
    
    // Process results to create booking list
    const bookinglist = await results.reduce(async (accPromise, row) => {
      const acc = await accPromise;
      const classLabel = row.class_label;
      const nickname = row.nickname ? `${row.nickname} (${row.gender}${calculateAge(row.dateofbirth)})` : null;
    
      if (!acc[classLabel]) {
        acc[classLabel] = [];
      }
    
      if (nickname) {
        const obj = await getName(nickname, row.currnent_courserefer, row.booking_courserefer, row.checkedin, row.color, row.remaining, row.freeflag, row.coursetype, row.expiredate, row.paid);
        acc[classLabel].push({ name: obj.nickname, studentid: row.studentid, msg: obj.msg });
      }
    
      return acc;
    }, Promise.resolve({}));

    // Remove classes with "แข่ง" in the class time only if there are no names
    Object.keys(bookinglist).forEach(classLabel => {
      if (classLabel.includes('แข่ง') && bookinglist[classLabel].length === 0) {
        delete bookinglist[classLabel];
      }
    });

    //console.log("getBookingList [response] : " + JSON.stringify(bookinglist));
    res.json({ success: true, message: 'Get Booking list successful', bookinglist });
  } catch (error) {
    console.error('Error in getBookingList', error.stack);
    res.status(500).send(error);
  }
});

app.post('/getBookingList', verifyToken, async (req, res) => {
  //console.log("getBookingList [request] : " + JSON.stringify(req.body));
  try {
    const { classday, classdate } = req.body;

    // Query to get all necessary data in one go
    const query = `
      SELECT 
        a.classtime, 
        a.courseid, 
        CONCAT(a.classtime, ' (', b.course_shortname, ')') as class_label, 
        a.classid,
        c.nickname,
        r.checkedin,
        c.dateofbirth,
        CASE WHEN c.gender = 'ชาย' THEN 'ช.' ELSE 'ญ.' END as gender,
        cc.color,
        cc.expiredate,
        cc.remaining
      FROM tclassinfo a
      JOIN tcourseinfo b ON a.courseid = b.courseid AND b.enableflag = 1
      LEFT JOIN treservation r ON a.classid = r.classid AND r.classdate = ?
      LEFT JOIN tstudent c ON r.studentid = c.studentid
      LEFT JOIN tcustomer_course cc ON r.courserefer = cc.courserefer
      WHERE a.classday = ? AND a.enableflag = 1
      ORDER BY a.classtime, r.classtime ASC
    `;
    const results = await queryPromise(query, [classdate, classday]);

    // Process results to create booking list
    const bookinglist = results.reduce((acc, row) => {
      const classLabel = row.class_label;
      const nickname = row.nickname ? `${row.nickname} (${row.gender}${calculateAge(row.dateofbirth)})` : null;

      if (!acc[classLabel]) {
        acc[classLabel] = [];
      }

      if (nickname) {
        acc[classLabel].push(nickname);
      }

      return acc;
    }, {});

    // Remove classes with "แข่ง" in the class time only if there are no names
    Object.keys(bookinglist).forEach(classLabel => {
      if (classLabel.includes('แข่ง') && bookinglist[classLabel].length === 0) {
        delete bookinglist[classLabel];
      }
    });

    //console.log("getBookingList [response] : " + JSON.stringify(bookinglist));
    res.json({ success: true, message: 'Get Booking list successful', bookinglist });
  } catch (error) {
    console.error('Error in getBookingList', error.stack);
    res.status(500).send(error);
  }
});

function isExpired(expiredate) {
  if (!expiredate) {
    return false;
  }

  const today = new Date();
  const todayDateOnly = new Date(today.getFullYear(), today.getMonth(), today.getDate());
  console.log("isExpired : " + new Date(expiredate) <= todayDateOnly);
  return new Date(expiredate) <= todayDateOnly;
}
// Function to calculate age in years and months
function calculateAge(dateOfBirth) {
  if (!dateOfBirth) {
    return '';
  }
  const dob = new Date(dateOfBirth);
  const diff = Date.now() - dob.getTime();
  const ageDate = new Date(diff);
  const ageYears = ageDate.getUTCFullYear() - 1970;
  const ageMonths = ageDate.getUTCMonth();
  if (ageMonths === 0) {
    return `${ageYears}`;
  }
  const ageMonthsFormatted = ageMonths < 10 ? ageMonths : ageMonths;
  return `${ageYears}.${ageMonthsFormatted}`;
}

app.post('/getFinishedCustomerCourseList', verifyToken, async (req, res) => {
  try {
    const { username } = req.body;
    const query = `SELECT a.*, b.coursename, 
        CASE 
         WHEN a.courserefer LIKE '%ทดลองเรียน%' OR a.courserefer LIKE '%รายครั้ง%' THEN ''
         ELSE (
           SELECT GROUP_CONCAT(DISTINCT s.nickname SEPARATOR ', ')
           FROM tstudent s
           JOIN treservation r ON s.studentid = r.studentid
           WHERE r.courserefer = a.courserefer
         )
        END AS userlist
FROM tcustomer_course a 
LEFT JOIN tcourseinfo b 
ON a.courseid = b.courseid 
WHERE a.finish = 1 
GROUP BY a.courseid, a.courserefer, b.coursename
ORDER BY a.createdate desc
    `;

    const results = await queryPromise(query, null);
    if (results.length > 0) {
      res.json({ success: true, message: 'Get Customer Course List successful', results });
    } else {
      res.json({ success: true, message: 'No Customer Course List' });
    }
  } catch (error) {
    console.error('Error in getCustomerCourseList', error.stack);
    res.status(500).send(error);
  }
});

app.post('/getCustomerCourseList', verifyToken, async (req, res) => {
  try {
    const { username } = req.body;
    const query = `SELECT a.*, b.coursename, 
        CASE 
         WHEN a.courserefer LIKE '%ทดลองเรียน%' OR a.courserefer LIKE '%รายครั้ง%' THEN ''
         ELSE GROUP_CONCAT(s.nickname SEPARATOR ', ')
        END AS userlist
        FROM tcustomer_course a 
        LEFT JOIN tcourseinfo b 
        ON a.courseid = b.courseid 
        LEFT JOIN tstudent s 
        ON a.courserefer = s.courserefer 
        WHERE a.finish = 0 
        GROUP BY a.courseid, a.courserefer, b.coursename
        ORDER BY a.createdate desc
    `;

    const results = await queryPromise(query, null);
    if (results.length > 0) {
      res.json({ success: true, message: 'Get Customer Course List successful', results });
    } else {
      res.json({ success: true, message: 'No Customer Course List' });
    }
  } catch (error) {
    console.error('Error in getCustomerCourseList', error.stack);
    res.status(500).send(error);
  }
});

app.get('/getCustomerCourseLookup', verifyToken, async (req, res) => {
  try {
    const query = 'SELECT a.* FROM tcustomer_course a WHERE a.finish = 0';
    const results = await queryPromise(query, null);
    if (results.length > 0) {
      res.json({ success: true, message: 'Get Customer Course List successful', results });
    } else {
      res.json({ success: true, message: 'No Customer Course List' });
    }
  } catch (error) {
    console.error('Error in getCustomerCourseLookup', error.stack);
    res.status(500).send(error);
  }
});

async function uploadSlipImageToS3(reqFile, refer) {
  if (!reqFile) return { url: null, key: null };

  let originalFileName = reqFile.originalname;
  let fileExtension = originalFileName.split('.').pop();
  let fileName = `slip_customer_course/${refer}.${fileExtension}`;
  let params = {
    Bucket: 'istar',
    Key: fileName,
    Body: fs.createReadStream(reqFile.path),
    ACL: 'public-read',
    ContentType: reqFile.mimetype
  };

  // ตรวจสอบชื่อซ้ำ
  let fileExists = true;
  let fileIndex = 1;
  while (fileExists) {
    try {
      await s3Client.send(new HeadObjectCommand({ Bucket: params.Bucket, Key: params.Key }));
      // ถ้าซ้ำ ให้เพิ่ม _1, _2, ...
      fileName = `slip_customer_course/${refer}_${fileIndex}.${fileExtension}`;
      params.Key = fileName;
      fileIndex++;
    } catch (headErr) {
      if (headErr.name === 'NotFound') {
        fileExists = false;
      } else {
        throw headErr;
      }
    }
  }

  // อัปโหลดไฟล์ (ใช้ Buffer เพื่อความชัวร์)
  const fileBuffer = fs.readFileSync(reqFile.path);
  params.Body = fileBuffer;
  await s3Client.send(new PutObjectCommand(params));

  // ลบไฟล์ชั่วคราว
  fs.unlink(reqFile.path, (err) => {
    if (err) console.error('Failed to delete temporary file:', err);
  });

  const slipImageUrl = `https://${params.Bucket}.sgp1.digitaloceanspaces.com/${params.Key}`;
  return { url: slipImageUrl, key: params.Key };
}

app.post('/addCustomerCourse', verifyToken, upload.single('slipImage'), async (req, res) => {
  try {
    const { coursetype, coursestr, remaining, startdate, expiredate, period, enable_double_booking, paid, paydate, shortnote } = req.body;
    //convert course from JSON string to object
    if (typeof coursestr === 'string') {
      try {
        course = JSON.parse(coursestr);
      } catch (error) {
        console.error('Error parsing course JSON', error);
        return res.status(400).json({ success: false, message: 'Invalid course data' });
      }
    }
    const courserefer = await generateRefer(course.refercode);

    // สร้างคำสั่ง SQL และพารามิเตอร์
    const fields = ['courserefer', 'courseid', 'paid', 'shortnote'];
    const values = [courserefer, course.courseid, paid, shortnote];
    
    if (coursetype) {
      fields.push('coursetype');
      values.push(coursetype);
    }
    if (remaining !== undefined && remaining !== null && remaining !== 'null' && remaining !== '') {
      fields.push('remaining');
      values.push(remaining);
    }
    if (startdate !== undefined && startdate !== null && startdate !== 'null' && startdate !== '') {
      fields.push('startdate');
      values.push(startdate);
    }
    if (expiredate !== undefined && expiredate !== null && expiredate !== 'null' && expiredate !== '') {
      fields.push('expiredate');
      values.push(expiredate);
    }
    if (enable_double_booking !== undefined && enable_double_booking !== null && enable_double_booking !== 'null' && enable_double_booking !== '') {
      fields.push('enable_double_booking');
      values.push(enable_double_booking);
    }
    if (period) {
      fields.push('period');
      values.push(period);
    }
    if (paydate !== undefined && paydate !== null && paydate !== 'null' && paydate !== '') {
      fields.push('paydate');
      values.push(paydate);
    }
    if(req.user.username) {
      fields.push('createby');
      values.push(req.user.username);
    }

    let slipImageUrl = null;
    if (req.file) {
      const uploadResult = await uploadSlipImageToS3(req.file, courserefer);
      slipImageUrl = uploadResult.url;
      if (slipImageUrl) {
        fields.push('slip_image_url');
        values.push(slipImageUrl);
      }
    }

    const query = `INSERT INTO tcustomer_course (${fields.join(', ')}) VALUES (${fields.map(() => '?').join(', ')})`;

    const results = await queryPromise(query, values, true);
    if (results.affectedRows > 0) {
      let haveImageString = "";
      if(!slipImageUrl) {
        haveImageString = `\nยังไม่มีการอัพโหลดรูปภาพ Slip 🤦🤦`;
      } else {
        haveImageString = `\nมีการอัพโหลดรูปภาพ Slip 👍👍`;
        
      }
      //Send Log to Discord
      const logMessage = `${courserefer} : สร้าง Customer Course มีรายละเอียดดังนี้:\n` +
        `Course ID: ${course.courseid}, Course Type: ${coursetype}, Remaining: ${remaining}\n` +
        `Start Date: ${startdate}, Expire Date: ${expiredate}, Paid: ${paid}, Pay Date: ${paydate}\n` +
        `Short Note: ${shortnote}\n` +
        `Created By: ${req.user.username}` + haveImageString;

      if(slipImageUrl) {
        await logCourseToDiscord('info', `✅[addCustomerCourse][${req.user.username}]`, logMessage, slipImageUrl);
      } else {
        await logCourseToDiscord('info', `✅[addCustomerCourse][${req.user.username}]`, logMessage);
      }
      res.json({ success: true, message: 'Successfully Course No :' + courserefer, courserefer });
    } else {
      res.json({ success: false, message: 'Error adding Customer Course' });
    }
  } catch (error) {
    console.log("Error in addCustomerCourse2 : " + JSON.stringify(error));
    console.error('Error in addCustomerCourse', error.stack);
    res.status(500).send(error);
  }
});

app.post('/updateCustomerCourse', verifyToken, upload.single('slipImage'), async (req, res) => {
  try {
    const { courserefer, courseid, coursetype, startdate, expiredate, enable_double_booking, paid, paydate, shortnote } = req.body;
    let slip_image_url = req.body.slip_image_url || null; // ใช้ค่า slip_image_url จาก body ถ้ามี
    queryData = 'SELECT * FROM tcustomer_course WHERE courserefer = ?';
    let oldData = await queryPromise(queryData, [courserefer]);
    let fieldsToUpdate = ['courseid', 'coursetype', 'paid', 'shortnote', 'updateby'];
    let valuesToUpdate = [courseid, coursetype, paid , shortnote, req.user.username];

    if (startdate !== undefined && startdate !== null && startdate !== '' && startdate !== 'null') {
      fieldsToUpdate.push('startdate');
      valuesToUpdate.push(startdate);
    } else {
      fieldsToUpdate.push('startdate');
      valuesToUpdate.push(null);
    }
    if (expiredate !== undefined && expiredate !== null && expiredate !== '' && expiredate !== 'null') {
      fieldsToUpdate.push('expiredate');
      valuesToUpdate.push(expiredate);
    } else {
      fieldsToUpdate.push('expiredate');
      valuesToUpdate.push(null);
    }
    if (enable_double_booking !== undefined && enable_double_booking !== null && enable_double_booking !== '' && enable_double_booking !== 'null') {
      fieldsToUpdate.push('enable_double_booking');
      valuesToUpdate.push(enable_double_booking);
    } else {
      fieldsToUpdate.push('enable_double_booking');
      valuesToUpdate.push(null);
    }
    if (paydate !== undefined && paydate !== null && paydate !== '' && paydate !== 'null') {
      fieldsToUpdate.push('paydate');
      valuesToUpdate.push(paydate);
    } else {
      fieldsToUpdate.push('paydate');
      valuesToUpdate.push(null);
    }
    let slipImageUrl = null;
    if (req.file) {
      const uploadResult = await uploadSlipImageToS3(req.file, courserefer);
      slipImageUrl = uploadResult.url;
      if (slipImageUrl) {
        fieldsToUpdate.push('slip_image_url');
        valuesToUpdate.push(slipImageUrl);
        slip_image_url = slipImageUrl; // อัพเดตค่า slip_image_url ให้เป็น URL ที่อัพโหลดใหม่
      }
    }

    const query = `UPDATE tcustomer_course SET ${fieldsToUpdate.map(field => `${field} = ?`).join(', ')} WHERE courserefer = ?`;
    valuesToUpdate.push(courserefer);

    const results = await queryPromise(query, valuesToUpdate);
    if (results.affectedRows > 0) {
      //Send Log to Discord
      let newData = await queryPromise(queryData, [courserefer]);

      //เปรียบเทียบข้อมูลที่มีการเปลี่ยนแปลง ระหว่าง oldData และ newData เพื่อ log เฉพาะข้อมูลที่มีการเปลี่ยนแปลง ค่าที่เป็น datetime จะเปรียบเทียบแค่วันที่ ไม่เปรียบเทียบเวลา
      let logData = {
        courserefer: courserefer,
        oldData: {},
        newData: {},
        changedFields: {}
      };
      for (const key in req.body) {
        if(key === 'coursestr') {
          continue; // ข้าม key นี้เพราะไม่ต้องการเปรียบเทียบ
        }
        if (Object.prototype.hasOwnProperty.call(req.body, key)) {
          let newValue = req.body[key];
          if (key === 'slip_image_url') {
            // ถ้าเป็น slip_image_url ให้ใช้ค่า slip_image_url ที่อัพโหลดใหม่
            newValue = slip_image_url || null; // ใช้ค่า slip_image_url ที่อัพโหลดใหม่ ถ้าไม่มีให้เป็น null
          }
          const oldValue = oldData[0][key];

          if (key !== 'course') {
            if (['startdate', 'expiredate', 'paydate', 'editdate', 'createdate'].includes(key)) {
              console.log("------------- DEBUG # 0 oldValue : " + oldValue + " newValue : " + newValue);
              // Normalize oldValue
              if (oldValue === undefined || oldValue === '' || oldValue === 'null') {
                oldValue = null;
              }
              // Normalize newValue
              if (newValue === undefined || newValue === '' || newValue === 'null') {
                newValue = null;
              }

              if (oldValue === null && newValue === null) {
                continue; // ถ้าไม่มีการเปลี่ยนแปลงให้ข้าม
              }else{
                let oldDateObj = null;
                let newDateObj = null;

                if(oldValue !== null) {
                  oldDateObj = new Date(oldValue);
                }
                if(newValue !== null) {
                  newDateObj = new Date(newValue);
                }
                // ถ้าค่าใดค่าหนึ่งเป็น null ให้ถือว่าแตกต่างกันทันที
                if (oldDateObj === null || newDateObj === null) {
                  const oldDateString = oldDateObj ? oldDateObj.toISOString().split('T')[0] : null;
                  const newDateString = newDateObj ? newDateObj.toISOString().split('T')[0] : null;
                  logData.changedFields[key] = { old: oldDateString, new: newDateString };
                } else {
                  console.log("------------- DEBUG # 1 oldDateObj : " + oldDateObj + " newDateObj : " + newDateObj);
                  const isOldDateValid = !isNaN(oldDateObj.getTime());
                  const isNewDateValid = !isNaN(newDateObj.getTime());
                  console.log("------------- DEBUG # 2 isOldDateValid : " + isOldDateValid + " isNewDateValid : " + isNewDateValid);

                  if (isOldDateValid && isNewDateValid) {
                  const oldDate = oldDateObj.setHours(0, 0, 0, 0);
                  const newDate = newDateObj.setHours(0, 0, 0, 0);

                  if (oldDate !== newDate) {
                    const oldDateString = new Date(oldDate).toISOString().split('T')[0];
                    const newDateString = new Date(newDate).toISOString().split('T')[0];
                    logData.changedFields[key] = { old: oldDateString, new: newDateString };
                  }
                  } else if (isOldDateValid && !isNewDateValid) {
                  const oldDateString = oldDateObj.toISOString().split('T')[0];
                  logData.changedFields[key] = { old: oldDateString, new: 'Invalid Date' };
                  } else if (!isOldDateValid && isNewDateValid) {
                  const newDateString = newDateObj.toISOString().split('T')[0];
                  logData.changedFields[key] = { old: 'Invalid Date', new: newDateString };
                  } else {
                  logData.changedFields[key] = { old: 'Invalid Date', new: 'Invalid Date' };
                  }
                }
              }
            } else if (newValue != oldValue) {
              let oldVal = oldValue;
              let newVal = newValue;
              // ถ้าเป็น string 'null' ให้แปลงเป็น null
              if (oldVal === 'null') oldVal = null;
              if (newVal === 'null') newVal = null;
              if(oldVal == null && newVal == null) {
                continue; // ถ้าไม่มีการเปลี่ยนแปลงให้ข้าม
              }
              
              if (key === 'slip_image_url') {
                oldVal = oldValue ? encodeURI(oldValue) : '';
                newVal = newValue ? encodeURI(newValue) : '';
              }
              logData.oldData[key] = oldVal;
              logData.newData[key] = newVal;
              logData.changedFields[key] = { old: oldVal, new: newVal };
            }
          }
        }
      }
      let haveImageString = "";
      if(!slipImageUrl) {
        haveImageString = `\nไม่มีการอัพโหลดรูปภาพ Slip ใหม่`;
        if(slip_image_url) {
          haveImageString += ` แต่มี Slip เก่าที่อัพโหลดไว้ 👍👍 : ${slip_image_url}`;
        }
      } else {
          haveImageString = `\nมีการอัพโหลดรูปภาพ Slip ใหม่ 👍👍`;
      }
      // Log ข้อมูลที่มีการเปลี่ยนแปลง
      if (Object.keys(logData.changedFields).length > 0) {
        const beautifulChangedFields = JSON.stringify(logData.changedFields, null, 2); // <--- เพิ่ม null, 2 ตรงนี้
        if(!slipImageUrl) {
          logCourseToDiscord('info', `✅ [updateCustomerCourse][${req.user.username}]`, `Successfully updated CustomerCourse : ${courserefer}\nChanged Fields :\n\`\`\`json\n${beautifulChangedFields}\n\`\`\`` + haveImageString);
        }else{
          logCourseToDiscord('info', `✅ [updateCustomerCourse][${req.user.username}]`, `Successfully updated CustomerCourse : ${courserefer}\nChanged Fields :\n\`\`\`json\n${beautifulChangedFields}\n\`\`\`` + haveImageString, slipImageUrl);
        }
      } else {
        if(!slipImageUrl) {
          logCourseToDiscord('info', `✅ [updateCustomerCourse][${req.user.username}]`, `No changes detected for CustomerCourse : ${courserefer}\nBody : ${JSON.stringify(req.body)}\n${haveImageString}`, slipImageUrl);
        } else {
          logCourseToDiscord('info', `✅ [updateCustomerCourse][${req.user.username}]`, `No changes detected for CustomerCourse : ${courserefer}\nBody : ${JSON.stringify(req.body)}\n${haveImageString}`);
        }
      }

      res.json({ success: true, message: 'Customer Course updated successfully' });
    } else {
      res.json({ success: false, message: 'Error updating Customer Course' });
    }
  } catch (error) {
    console.log("Error in updateCustomerCourse2 : " + JSON.stringify(error));
    console.error('Error in updateCustomerCourse', error.stack);
    res.status(500).send(error);
  }
});

app.post('/uploadSlipImage', verifyToken, upload.single('slipImage'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded.' });
    }
    if (!req.user || !req.user.username) { // ตรวจสอบ req.user.username
        // หากไม่มี req.user.username อาจจะต้องกำหนดค่า default หรือส่ง error
        console.warn('[uploadSlipImage] req.user.username is missing. Using default or skipping user specific log.');
        // กำหนดค่า default หากจำเป็น เช่น req.user = { username: 'System' };
    }

    const fileStream = fs.createReadStream(req.file.path);
    let originalFileName = req.file.originalname;
    let fileExtension = originalFileName.split('.').pop();
    let fileNameWithoutExtension = originalFileName.substring(0, originalFileName.lastIndexOf('.'));
    let fileName = `slip_customer_course/${req.file.originalname}`;
    let params = {
      Bucket: 'istar', // ชื่อ Space ของคุณ
      Key: fileName, // ชื่อไฟล์ใน Space พร้อม path
      Body: fileStream,
      ACL: 'public-read', // ตั้งค่าให้ไฟล์สามารถเข้าถึงได้จากภายนอก
      ContentType: req.file.mimetype // เพิ่ม ContentType เพื่อให้แสดงผลถูกต้อง
    };

    // ตรวจสอบว่ามีไฟล์ที่มีชื่อเดียวกันอยู่หรือไม่ และเพิ่มลำดับไฟล์ถ้าชื่อไฟล์ซ้ำ
    let fileExists = true;
    let fileIndex = 1;
    let finalFileName = fileName;
    while (fileExists) {
      try {
        await s3Client.send(new HeadObjectCommand({ Bucket: params.Bucket, Key: params.Key }));
        // ถ้ามีไฟล์ที่มีชื่อเดียวกันอยู่แล้ว ให้เพิ่มลำดับไฟล์
        fileNameWithoutExtension = originalFileName.substring(0, originalFileName.lastIndexOf('.')); // คำนวณใหม่ทุกครั้ง
        fileExtension = req.file.originalname.split('.').pop();
        finalFileName = `slip_customer_course/${fileNameWithoutExtension}_${fileIndex}.${fileExtension}`;
        fileName = `slip_customer_course/${fileNameWithoutExtension}_${fileIndex}.${fileExtension}`;
        params.Key = finalFileName;
        fileIndex++;
      } catch (headErr) {
        if (headErr.name === 'NotFound') {
          // ถ้าไม่พบไฟล์ที่มีชื่อเดียวกัน
          fileExists = false;
        } else {
          // ถ้าเกิดข้อผิดพลาดอื่นๆ
          console.error('Error checking file existence:', headErr);
          throw headErr;
        }
      }
    }

    // อัพโหลดไฟล์ใหม่ (ต้องสร้าง ReadStream ใหม่หากมีการใช้งานไปแล้วในการ check หรือ Body เป็น Buffer)
    // ในกรณีนี้ `fileStream` ถูกสร้างครั้งเดียวและอาจจะถูก consume หาก HeadObjectCommand อ่าน stream
    // วิธีที่ปลอดภัยกว่าคือการอ่านไฟล์เข้า Buffer หรือสร้าง Stream ใหม่ทุกครั้งที่ PUT
    const fileBuffer = fs.readFileSync(req.file.path);
    params.Body = fileBuffer; // ใช้ Buffer แทน Stream เพื่อความแน่นอน

    const data = await s3Client.send(new PutObjectCommand(params));

    // ลบไฟล์ชั่วคราวหลังจากอัพโหลดเสร็จ
    fs.unlink(req.file.path, (err) => {
      if (err) console.error('Failed to delete temporary file:', err);
    });

    const slipImageUrl = `https://${params.Bucket}.sgp1.digitaloceanspaces.com/${params.Key}`;
    const courserefer = req.body.courserefer; // สมมติว่า courserefer ถูกส่งมาพร้อมกับ request

    // ตรวจสอบว่า req.user และ req.user.username มีค่าหรือไม่
    const username = req.user && req.user.username ? req.user.username : 'UnknownUser';

    const query = 'UPDATE tcustomer_course SET slip_image_url = ? WHERE courserefer = ?';
    await queryPromise(query, [slipImageUrl, courserefer]);

    // ส่ง log ไปยัง Discord พร้อมรูปภาพ
    logCourseToDiscord(
        'info',
        `✅ [uploadSlipImage][${username}]`, // ใช้ username ที่ตรวจสอบแล้ว
        `Uploaded Slip Image for course refer: ${JSON.stringify(courserefer)}\nSlip URL: ${slipImageUrl}`,
        slipImageUrl // ส่ง URL ของรูปภาพไปยังฟังก์ชัน log
    );
    res.json({ url: slipImageUrl });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post('/checkBeforeDeleteCustomerCourse', verifyToken, async (req, res) => {
  try {
    const { courserefer } = req.body;
    const query = 'SELECT * FROM tstudent WHERE courserefer = ?';
    const results = await queryPromise(query, [courserefer]);
    if (results.length > 0) {
      res.json({ success: false, message: 'This course is currently being used.', results });
    } else {
      res.json({ success: true, message: 'This course is not currently in use.' });
    }
  } catch (error) {
    console.error('Error in checkbeforeDeleteCustomerCourse', error.stack);
    res.status(500).send(error);
  }
});

app.post('/deleteCustomerCourse', verifyToken, async (req, res) => {
  try {
    const { courserefer } = req.body;
    const queryUpdateDelete = 'UPDATE tcustomer_course SET deleteby = ? WHERE courserefer = ?';
    const resultsUpdateDelete = await queryPromise(queryUpdateDelete, [req.user.username, courserefer]);
    if (resultsUpdateDelete.affectedRows > 0) {
      const queryMoveToHistory = 'INSERT INTO tcustomer_course_history SELECT * FROM tcustomer_course WHERE courserefer = ?';
      const resultsMoveToHistory = await queryPromise(queryMoveToHistory, [courserefer]);
      if (resultsMoveToHistory.affectedRows > 0) {

        const query = 'DELETE FROM tcustomer_course WHERE courserefer = ?';
        const results = await queryPromise(query, [courserefer]);
        if (results.affectedRows > 0) {
          await queryPromise('UPDATE tstudent SET courserefer = NULL, updateby = ? WHERE courserefer = ?', [req.user.username, courserefer]);
          await queryPromise('UPDATE tstudent SET courserefer2 = NULL, updateby = ? WHERE courserefer2 = ?', [req.user.username, courserefer]);
          //Send Log to Discord
          const logMessage = `ลบข้อมูล Customer Course courserefer: ${courserefer}`;
          await logCourseToDiscord('info', `[deleteCustomerCourse][${req.user.username}]`, logMessage);
          res.json({ success: true, message: 'Customer Course deleted successfully' });
        }
      } else {
        res.json({ success: false, message: 'Error deleting Customer Course' });
      }
    } else {
      res.json({ success: false, message: 'Error deleting Customer Course' });
    }
  } catch (error) {
    console.error('Error in deleteCustomerCourse', error.stack);
    res.status(500).send(error);
  }
});

app.get('/getStudentCourseDetail/:courserefer', verifyToken, async (req, res) => {
  const { courserefer } = req.params;
  try {
    let query = `
    SELECT cc.courserefer, GROUP_CONCAT(s.nickname SEPARATOR ', ') AS userlist, 
      COUNT(s.studentid) AS user, 
      CASE WHEN cc.coursetype = 'Monthly' THEN cc.coursetype ELSE cc.remaining END 'remaining', cc.expiredate
    FROM tcustomer_course cc 
    LEFT JOIN tstudent s ON cc.courserefer = s.courserefer 
    `;

    let queryParams = [];

    if (courserefer) {
      query += "WHERE cc.courserefer = ? ";
      queryParams.push(courserefer);
    }

    query += "GROUP BY cc.courserefer, cc.expiredate ";
    const results = await queryPromise(query, queryParams);
    const query2 = `SELECT a.classdate, a.classtime, CONCAT(IFNULL( b.firstname, ''), ' ', IFNULL( b.middlename, ''), IF( b.middlename<>'', ' ',''), IFNULL( b.lastname, ''), ' (', b.nickname,')') fullname 
                    , a.createby, a.updateby
                    FROM treservation a
                    LEFT JOIN tstudent b
                    ON a.studentid = b.studentid 
                    WHERE a.courserefer = ?  
                    order by a.classdate asc`;
    const courseDetail = await queryPromise(query2, [courserefer]);
    if (results.length > 0) {
      res.json({ success: true, message: 'Get Student Use Course successful', results, courseDetail });
    } else {
      res.json({ success: true, message: 'No Student Use Course' });
    }
  } catch (error) {
    console.error('Error in getStudentCourseDetail:', error.stack);
    res.status(500).send(error);
  }
});

app.get('/student/:studentid/profile-image', verifyToken, async (req, res) => {
  const { studentid } = req.params;
  console.log("get profile image for studentid : " + studentid)
  const query = 'SELECT profile_image, profile_image_url FROM tstudent WHERE studentid = ?';
  const results = await queryPromise(query, [studentid]);

  //console.log("get profile image results : " + JSON.stringify(results));
  if (results.length > 0) {
    res.json({ success: true, image: results[0].profile_image, imageUrl: results[0].profile_image_url });
  } else {
    res.json({ success: false, message: 'No profile image found' });
  }
});

app.get('/customer_course/:courserefer/slip-image', verifyToken, async (req, res) => {
  const { courserefer } = req.params;
  console.log("get slip image for customer_course : " + courserefer)
  const query = 'SELECT slip_image_url FROM tcustomer_course WHERE courserefer = ?';
  const results = await queryPromise(query, [courserefer]);

  //console.log("get slip image results : " + JSON.stringify(results));
  if (results.length > 0) {
    res.json({ success: true, image: results[0].slip_image, imageUrl: results[0].slip_image_url });
  } else {
    res.json({ success: false, message: 'No slip image found' });
  }
});

app.post('/getHolidayInformation', verifyToken, async (req, res) => {
  const { selectdate } = req.body;
  console.log("selectdate : " + selectdate);
  const formattedDate = selectdate.replace(/(\d{4})(\d{2})(\d{2})/, '$1-$2-$3');
  console.log("formattedDate : " + formattedDate);
  const month = new Date(formattedDate).getMonth() + 1; // คำนวณเดือน (0-11)

  // คำสั่ง SQL เพื่อค้นหาวันหยุดในเดือนที่กำหนด
  const sql = `
    SELECT DAY(holidaydate) AS day, description 
    FROM tholiday 
    WHERE MONTH(holidaydate) = ? AND YEAR(holidaydate) = ?
  `;
  const year = new Date(formattedDate).getFullYear();
  console.log('month:'+ month + ' year:'+ year);
  const results = await queryPromise(sql, [month, year])

  const result = results.map(holiday => {
    return `${holiday.day} ${holiday.description}`;
  });

  res.json(result);
});

app.get('/collectHolidays', verifyToken, async (req, res) => {
  try {
      const query = 'SELECT * FROM tholiday';
      const results = await queryPromise(query);

      res.json({
          success: true,
          data: results
      });
  } catch (error) {
      console.error('Error fetching holidays:', error);
      res.status(500).json({
          success: false,
          message: 'Failed to fetch holidays'
      });
  }
});

app.get('/holidaysList', verifyToken, async (req, res) => {
  try {
      const query = 'SELECT holidaydate FROM tholiday';
      const results = await queryPromise(query);
      // ดึงเฉพาะวันที่จากฐานข้อมูล
      const holidays = results.map(row => row.holidaydate);

      res.json({
          success: true,
          holidays: holidays
      });
  } catch (error) {
      console.error('Error fetching holidays:', error);
      res.status(500).json({
          success: false,
          message: 'Failed to fetch holidays'
      });
  }
});

app.post('/holidays', verifyToken, async (req, res) => {
  const { holidaydate, description } = req.body;
  try {
    const query = 'INSERT INTO tholiday (holidaydate, description) VALUES (?, ?)';
    const result = await queryPromise(query, [holidaydate, description]);
    if (result.affectedRows > 0) {
      res.json({ success: true, message: 'Holiday added successfully' });
    } else {
      res.json({ success: false, message: 'Error adding holiday' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error adding holiday' });
  }
});

app.put('/holidays/:id', async (req, res) => {
  const { holidaydate, description } = req.body;
  const { id } = req.params;
  try {
    await queryPromise('UPDATE tholiday SET holidaydate = ?, description = ? WHERE id = ?', [holidaydate, description, id]);
    res.json({ message: 'Holiday updated successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error updating holiday' });
  }
});

app.delete('/holidays/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await queryPromise('DELETE FROM tholiday WHERE id = ?', [id]);
    res.json({ message: 'Holiday deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error deleting holiday' });
  }
});

async function generateRefer(refertype) {
  let refer = '';
  const query = 'SELECT running, referdate  FROM trunning WHERE refertype = ? and referdate = curdate()';
  try {
    const results = await queryPromise(query, [refertype]);
    if (results.length > 0) {
      let referno = results[0].running;
      let referdate = results[0].referdate;
      referno = referno + 1;
      refer = refertype + "-" + momentTH(referdate).format('YYYYMMDD') + "-" + pad(4, referno, "0");
      const query2 = 'UPDATE trunning SET running = ? WHERE refertype = ? and referdate = curdate()';
      await queryPromise(query2, [referno, refertype]);
    } else {

      const query3 = 'INSERT INTO trunning (refertype, referdate, running) VALUES (?, curdate(), 1)';
      await queryPromise(query3, [refertype]);
      let referno = 1;
      refer = refertype + "-" + momentTH().format('YYYYMMDD') + "-" + pad(4, referno, "0");
    }
  } catch (error) {
    console.error('Error in generateRefer', error.stack);
    throw error;
  }
  console.log("generateRefer() Refer : " + refer);
  return refer;
}

function clearActiveSessions() {
  console.log("clearActiveSessions() : " + JSON.stringify(activeSessions));
  while (activeSessions.length > 0) {
    activeSessions.pop();
  }
}

const twilio = require('twilio');
const client = new twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
//start 2
async function createVerification(phoneNumber) {
  const verification = await client.verify.v2
    .services(process.env.TWILIO_SERVICE_SID)
    .verifications.create({
      channel: "sms",
      to: phoneNumber,
    });

  console.log("verification.sid : " + verification.sid);
  return verification;
}

async function createVerificationCheck(Sid,opt) {
  const verificationCheck = await client.verify.v2
    .services(process.env.TWILIO_SERVICE_SID)
    .verificationChecks.create({
      code: opt,
      verificationSid: Sid,
    });

  console.log("verificationCheck.status : " + verificationCheck.status);
  return verificationCheck;
}
const { parsePhoneNumberFromString } = require('libphonenumber-js');
function formatPhoneNumber(phoneNumber) {
  const phoneNumberObj = parsePhoneNumberFromString(phoneNumber, 'TH'); // 'TH' คือตัวระบุประเทศ (ประเทศไทย)
  if (phoneNumberObj && phoneNumberObj.isValid()) {
      return phoneNumberObj.format('E.164');
  } else {
      throw new Error('Invalid phone number format');
  }
}
// end 2

// start 1
const otpStorage = {}; // ใช้เก็บ OTP ชั่วคราว

// ฟังก์ชันส่ง OTP
function sendOTP(phoneNumber, otp) {
    return client.messages.create({
        body: `Your OTP code is ${otp}`,
        from: '+14067976350', // แทนที่ด้วยเบอร์ Twilio ของคุณ
        to: phoneNumber
    });
}
// end 1

// Endpoint ขอ OTP
app.post('/request-otp', async (req, res) => {
    let phoneNumber = req.body.phoneNumber;
    phoneNumber = formatPhoneNumber(phoneNumber);
    console.log("phoneNumber : " + phoneNumber);
    //const otp = Math.floor(100000 + Math.random() * 900000); // สร้าง OTP 6 หลัก

    // เก็บ OTP ไว้ใน otpStorage
    //otpStorage[phoneNumber] = otp;

    //sendOTP(phoneNumber, otp)
    try {
      const message = await createVerification(phoneNumber);
      res.status(200).send({ success: true, message });
    } catch (error) {
      res.status(500).send({ success: false, error });
    }
});

// Endpoint ยืนยัน OTP
app.post('/verify-otp', async (req, res) => {
    const { sid, otp } = req.body;
    try {
    const message = await createVerificationCheck(sid, otp);
    if (message.valid) {
      const token = jwt.sign({ sid: sid, otp: otp }, SECRET_KEY, { expiresIn: '10m' });
      res.status(200).send({ success: message.valid, token });
    } else {
      res.status(200).send({ success: message.valid, message });
    }
  } catch (error) {
    res.status(500).send({ success: false, error });
  }
});

app.post('/checkmobileno', async (req, res) => {
  const { username, mobileno } = req.body;
  const query = 'SELECT * FROM tuser WHERE username = ? and mobileno = ?';
  try {
    const results = await queryPromise(query, [username, mobileno]);
    if (results.length > 0) {
      res.json({ success: true, message: 'Mobile number matched' });
    } else {
      res.json({ success: false, message: 'Mobile number not matched' });
    }
  } catch (error) {
    console.error('Error in checkmobileno', error.stack);
    res.status(500).send(error);
  }
});

app.post('/change-password', verifyToken, async (req, res) => {
  const { username, password } = req.body;
  const query = 'UPDATE tuser SET userpassword = ? WHERE username = ?';
  try {
    const results = await queryPromise(query, [password, username]);
    if (results.affectedRows > 0) {
      res.json({ success: true, message: 'Password changed successfully' });
    } else {
      res.json({ success: false, message: 'Error changing password' });
    }
  } catch (error) {
    console.error('Error in chenge-password', error.stack);
    res.status(500).send(error);
  }
});

app.post('/uploadProfileImage', verifyToken, upload.single('profileImage'), async (req, res) => {
  try {
    const fileStream = fs.createReadStream(req.file.path);
    let fileName = `profile_image/${req.file.originalname}`;
    let params = {
      Bucket: 'istar', // ชื่อ Space ของคุณ
      Key: fileName, // ชื่อไฟล์ใน Space พร้อม path
      Body: fileStream,
      ACL: 'public-read', // ตั้งค่าให้ไฟล์สามารถเข้าถึงได้จากภายนอก
    };

    // ตรวจสอบว่ามีไฟล์ที่มีชื่อเดียวกันอยู่หรือไม่ และเพิ่มลำดับไฟล์ถ้าชื่อไฟล์ซ้ำ
    let fileExists = true;
    let fileIndex = 1;
    while (fileExists) {
      try {
        await s3Client.send(new HeadObjectCommand({ Bucket: params.Bucket, Key: params.Key }));
        // ถ้ามีไฟล์ที่มีชื่อเดียวกันอยู่แล้ว ให้เพิ่มลำดับไฟล์
        const fileExtension = req.file.originalname.split('.').pop();
        const fileNameWithoutExtension = req.file.originalname.replace(`.${fileExtension}`, '');
        fileName = `profile_image/${fileNameWithoutExtension}_${fileIndex}.${fileExtension}`;
        params.Key = fileName;
        fileIndex++;
      } catch (headErr) {
        if (headErr.name === 'NotFound') {
          // ถ้าไม่พบไฟล์ที่มีชื่อเดียวกัน
          fileExists = false;
        } else {
          // ถ้าเกิดข้อผิดพลาดอื่นๆ
          throw headErr;
        }
      }
    }

    // อัพโหลดไฟล์ใหม่
    const data = await s3Client.send(new PutObjectCommand(params));

    // ลบไฟล์ชั่วคราวหลังจากอัพโหลดเสร็จ
    fs.unlink(req.file.path, (err) => {
      if (err) console.error('Failed to delete temporary file:', err);
    });

    // อัพเดท URL ของรูปภาพในฐานข้อมูล
    const profileImageUrl = `https://${params.Bucket}.sgp1.digitaloceanspaces.com/${params.Key}`;
    const studentId = req.body.studentid; // สมมติว่า studentid ถูกส่งมาพร้อมกับ request

    const query = 'UPDATE tstudent SET profile_image_url = ? WHERE studentid = ?';
    await queryPromise(query, [profileImageUrl, studentId]);

    await deleteOldProfileImage(studentId);

    res.json({ url: profileImageUrl });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ฟังก์ชันลบรูปภาพเก่าจากฐานข้อมูล
async function deleteOldProfileImage(studentId) {
  const query = 'UPDATE tstudent SET profile_image = NULL WHERE studentid = ?';
  await queryPromise(query, [studentId]);
}

const { warn, log } = require('console');
async function uploadOrUpdateLogFile() {
  try {
    const logFilePath = logPath + logFileName;
    let fileName = `logs/${logFileName}`;
    let params = {
      Bucket: 'istar',
      Key: fileName,
      Body: fs.createReadStream(logFilePath),
      ACL: 'public-read',
      ContentType: 'text/plain'
    };

    // อัปโหลดไฟล์ (ใช้ Buffer เพื่อความชัวร์)
    const fileBuffer = fs.readFileSync(logFilePath);
    params.Body = fileBuffer;
    await s3Client.send(new PutObjectCommand(params));

    // (ไม่ต้องลบ log ในเครื่อง)
    const logUrl = `https://${params.Bucket}.sgp1.digitaloceanspaces.com/${params.Key}`;
    console.log('[Success] Log file uploaded to S3:', logUrl);
    // คุณสามารถ log ไป Discord หรืออื่นๆ ได้ที่นี่
  } catch (err) {
    console.error('Error uploading log file to S3:', err);
  }
}

async function scheduleRestartAtSpecificTime(hour, minute) {
  const now = new Date();
  const nextRestart = new Date();

  nextRestart.setHours(hour);
  nextRestart.setMinutes(minute);
  nextRestart.setSeconds(0);
  
  // ถ้าเวลาที่ตั้งน้อยกว่าเวลาปัจจุบัน ให้ตั้งเป็นวันถัดไป
  if (nextRestart <= now) {
    nextRestart.setDate(nextRestart.getDate() + 1);
  }

  const timeUntilNextRestart = nextRestart - now; // เวลาที่เหลือจนถึงการรีสตาร์ทในหน่วยมิลลิวินาที
  console.log(`Scheduled server restart at ${nextRestart}`);
  await new Promise(resolve => setTimeout(resolve, timeUntilNextRestart));

  console.log("###################################################################");
  console.log('############## upload log file before restart server ##############');
  console.log("###################################################################");
  console.log('####################### Server restarting... ######################');
  console.log("###################################################################");
  await uploadOrUpdateLogFile();
  server.close(() => {
    logSystemToDiscord('info', '✅ Server restarting... ['+format(new Date(), 'yyyy-MM-dd\'T\'HH-mm-ssXXX', { timeZone })+']');
    process.exit(0); // รีสตาร์ทแอป (App Platform จะเริ่มโปรเซสใหม่)
  });

  // เรียกใช้ฟังก์ชันใหม่เพื่อวางแผนการรีสตาร์ทครั้งถัดไป
  scheduleRestartAtSpecificTime(hour, minute);
}

// เรียกใช้ฟังก์ชันโดยตั้งเวลารีสตาร์ทที่ 01:30 น.
scheduleRestartAtSpecificTime(1, 30);
// ตั้งเวลาให้รันทุกๆ 55 นาที
const cron = require('node-cron');
cron.schedule('0,55 * * * *', () => {
  uploadOrUpdateLogFile() ;
});

const server = app.listen(port, () => {
  clearActiveSessions();
  console.log(`Server is running on port ${port}`);
  console.log("Start time : " + momentTH().format('YYYY-MM-DD HH:mm:ss.SSS'));
  logSystemToDiscord('info', '✅ ['+SERVER_TYPE+'] Server started successfully [' + momentTH().format('YYYY-MM-DD HH:mm:ss.SSS') + ']');
  setTimeout(() => {
    uploadOrUpdateLogFile();
  }, 1000); // รอ 1 วินาทีเพื่อให้ไฟล์ log ถูกสร้าง
});

// ทำให้ console.log ใช้ winston logger
console.log = (msg) => {
  logger.info("log " + msg);
};

console.error = (msg, error) => {
  const timestamp = new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' });
  logger.info('['+timestamp+'] : ' + msg + " : " + error);
  logSystemToDiscord('error', '❌ เกิดข้อผิดพลาด : ' + msg);
};

process.on('unhandledRejection', (reason, promise) => {
  logSystemToDiscord('error', `❌ [unhandledRejection] ${reason && reason.stack ? reason.stack : reason}`);
});

process.on('uncaughtException', (err) => {
  logSystemToDiscord('error', `❌ [uncaughtException] ${err && err.stack ? err.stack : err}`);
});