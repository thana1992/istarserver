require('dotenv').config()

const express = require('express');
const axios = require('axios');
const qs = require('qs');
const moment = require('moment');
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
const url = process.env.LINENOTIFY_URL;
const accessCode = process.env.LINENOTIFY_ACCESS_TOKEN;
const accessCode2 = process.env.LINENOTIFY_ACCESS_TOKEN_2;
const multer = require('multer');

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
const logFileName = `v1-server-${timestamp}.log`;
const logPath = './logs/';

// สร้าง winston logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({
      format: () => {
        const date = new Date();
        const formattedDate = date.toLocaleString('th-TH', {
          timeZone: 'Asia/Bangkok',
          hour12: false
        });
        const milliseconds = date.getMilliseconds().toString().padStart(3, '0');
        return `${formattedDate}.${milliseconds}`;
      }
    }),
    winston.format.printf(({ timestamp, level, message }) => `${timestamp} ${level}: ${message}`)
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: logPath+logFileName })
  ]
});


// ใช้ morgan เพื่อบันทึก log
app.use(morgan('combined', { stream: fs.createWriteStream(path.join(__dirname, logPath+logFileName), { flags: 'a' }) }));

// สร้าง middleware เพื่อ log response
app.use((req, res, next) => {
  // Log request
  logger.info(`-----> REQUEST : ${req.method} ${req.url}`);
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

    logger.info(`-----> RESPONSE : ${req.url} : ---> ${logBody}`);
    // Send the original body to the client
    originalSend.call(res, body);
  };

  next();
});



app.use(bodyParser.json({ limit: '5mb' }));
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  // other headers...
  next();
});
app.use(cors());

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
  const query = 'SELECT * FROM tuser WHERE username = ?';
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
        await queryPromise(logquery, [username]);
        console.log("user.id = " + user.id);

        if (userdata.usertype != '10') {
          const token = jwt.sign({ username: user.username ,adminflag: 1 }, SECRET_KEY, { expiresIn: '1h' });
          return res.json({ success: true, message: 'Login successful', token, userdata });
        } else {
          const token = jwt.sign({ username: user.username ,adminflag: 0 }, SECRET_KEY, { expiresIn: '10m' });
          return res.json({ success: true, message: 'Login successful', token, userdata });
        }

      } else {
        return res.json({ success: false, message: 'password is invalid' });
      }
    } else {
      return res.json({ success: false, message: 'username invalid' });
    }
  } catch (error) {
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

  res.json({ success: true, message: 'Logout successful' });
});

app.post('/register', async (req, res) => {
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
    const results = await queryPromise(query, [familyid])
      .then((results) => {
        if (results.length > 0) {
          res.json({ success: true, message: 'Get FamilyMember successful', results });
        } else {
          res.json({ success: true, message: 'Not found FamilyMember', results });
        }
      })
      .catch((error) => {
        res.status(500).send(error);
      });
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
    const results = await queryPromise(query, [familyid, familyid])
      .then((results) => {
        if (results.length > 0) {
          res.json({ success: true, message: 'Get Family Member successful', results });
        } else {
          res.json({ success: true, message: 'No Family Member', results });
        }
      })
      .catch((error) => {
        res.status(500).send(error);
      });
  } catch (error) {
    console.error("Error in getStudent", error.stack);
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

    res.json({ success: true, message: 'Family member was successfully added. Please wait for approval from the admin.' });
  } catch (error) {
    console.error("Error in addStudent", error.stack);
    res.status(500).send(error);
  }
});

app.post('/approveNewStudent', verifyToken, async (req, res) => {
  try {
    const { apprObj } = req.body;
    console.log("apprObj : " + JSON.stringify(apprObj));

    for (const item of apprObj) {
      const getQuery = 'SELECT * FROM jstudent WHERE studentid = ?';
      const results = await queryPromise(getQuery, [item.studentid]);

      if (results.length > 0) {
        const studentid = await generateRefer('S');
        let query = 'INSERT INTO tstudent (studentid, familyid, firstname, middlename, lastname, nickname, gender, dateofbirth, school, createby) \n' +
          ' SELECT ? as studentid, jstudent.familyid, firstname, middlename, lastname, nickname, gender, dateofbirth, school, a.username as createby \n' +
          ' FROM jstudent \n' +
          ' LEFT JOIN tfamily a ON a.familyid = jstudent.familyid \n' +
          ' WHERE jstudent.studentid = ? ';

        let params = [studentid, item.studentid];
        const results = await queryPromise(query, params);

        if(results.affectedRows > 0) {
          const deleteQuery = 'DELETE FROM jstudent WHERE studentid = ?';
          await queryPromise(deleteQuery, [item.studentid]);
        }
      }
    }

    res.json({ success: true, message: 'Family member approve successfully' });
  } catch (error) {
    console.error('Error in approveNewStudent', error.stack);
    
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

app.post('/addStudentByAdmin', verifyToken, async (req, res) => {
  const { firstname, middlename, lastname, nickname, gender, dateofbirth, familyid, courserefer, shortnote } = req.body;
  try {
    if (courserefer != null && courserefer != '') {
      const queryCheckCustomerCourse = 'SELECT * FROM tcustomer_course WHERE courserefer = ?';
      const resCheckCustomerCourse = await queryPromise(queryCheckCustomerCourse, [courserefer]);
      if (resCheckCustomerCourse.length <= 0) {
        return res.json({ success: false, message: 'Course not found' });
      } else {
        const coursetype = resCheckCustomerCourse[0].coursetype;
        if (coursetype == 'Monthly') {
          const queryCheckUserd = 'SELECT count(*) FROM tstudent WHERE courserefer = ? ';
          const resCheckUserd = await queryPromise(queryCheckUserd, [courserefer]);
          if (resCheckUserd.length > 0) {
            const count = resCheckUserd[0].count;
            if (count > 0) {
              return res.json({ success: false, message: 'Monthly course cannot share, Course already used!' });
            } else {
              const studentid = await generateRefer('S');
              const query = 'INSERT INTO tstudent (studentid, firstname, middlename, lastname, nickname, gender, dateofbirth, familyid, courserefer, shortnote, createby) ' +
                ' VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
                console.log("req : " + JSON.stringify(req.user));	
              await queryPromise(query, [studentid, firstname, middlename, lastname, nickname, gender, dateofbirth, familyid, courserefer, shortnote, req.user.username])
                .then((results) => {
                  const queryCheckCourseOwner = 'select * from tcustomer_course where courserefer = ?';
                  const resCheckCourseOwner = queryPromise(queryCheckCourseOwner, [courserefer]);
                  if (resCheckCourseOwner.length > 0) {
                    let owner = resCheckCourseOwner[0].owner;
                    if(owner != 'trial') {
                      let ownerList = owner ? owner.split(',') : []; // แปลง owner ให้เป็น array
                      if (!ownerList.includes(studentid)) { // ถ้า studentid ไม่อยู่ใน ownerList
                        ownerList.push(studentid); // เพิ่ม studentid เข้าไปใน list
                        let newOwner = ownerList.join(','); // แปลง array กลับเป็น string
                        
                        // ทำการอัปเดตค่า owner ในฐานข้อมูล
                        const queryUpdateOwner = 'UPDATE tcustomer_course SET owner = ? WHERE courserefer = ?';
                        queryPromise(queryUpdateOwner, [newOwner, courserefer]);
                      }
                    }
                  }
                  res.json({ success: true, message: 'Family member added successfully', studentid });
                })
                .catch((error) => {
                  res.status(500).send(error);
                });
            }
          }
        } else {
          const studentid = await generateRefer('S');
          const query = 'INSERT INTO tstudent (studentid, firstname, middlename, lastname, nickname, gender, dateofbirth, familyid, courserefer, shortnote, createby) ' +
            ' VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
          console.log("req : " + JSON.stringify(req.user));	
          await queryPromise(query, [studentid, firstname, middlename, lastname, nickname, gender, dateofbirth, familyid, courserefer, shortnote, req.user.username])
            .then((results) => {
              const queryCheckCourseOwner = 'select * from tcustomer_course where courserefer = ?';
              const resCheckCourseOwner = queryPromise(queryCheckCourseOwner, [courserefer]);
              if (resCheckCourseOwner.length > 0) {
                let owner = resCheckCourseOwner[0].owner;
                if(owner != 'trial') {
                  let ownerList = owner ? owner.split(',') : []; // แปลง owner ให้เป็น array
                  if (!ownerList.includes(studentid)) { // ถ้า studentid ไม่อยู่ใน ownerList
                    ownerList.push(studentid); // เพิ่ม studentid เข้าไปใน list
                    let newOwner = ownerList.join(','); // แปลง array กลับเป็น string
                    
                    // ทำการอัปเดตค่า owner ในฐานข้อมูล
                    const queryUpdateOwner = 'UPDATE tcustomer_course SET owner = ? WHERE courserefer = ?';
                    queryPromise(queryUpdateOwner, [newOwner, courserefer]);
                  }
                }
              }
              res.json({ success: true, message: 'Family member added successfully', studentid });
            })
            .catch((error) => {
              res.status(500).send(error);
            });
        }
      }
    } else {
      const studentid = await generateRefer('S');
      const query = 'INSERT INTO tstudent (studentid, firstname, middlename, lastname, nickname, gender, dateofbirth, familyid, shortnote, createby) ' +
        ' VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
      console.log("req : " + JSON.stringify(req.user));
      await queryPromise(query, [studentid, firstname, middlename, lastname, nickname, gender, dateofbirth, familyid, shortnote, req.user.username])
        .then((results) => {
          res.json({ success: true, message: 'Family member added successfully', studentid });
        })
        .catch((error) => {
          res.status(500).send(error);
        });
    }

  } catch (error) {
    console.error('Error in addStudentByAdmin', error.stack);
    
    res.status(500).send(error);
  }
});

app.post('/updateStudentByAdmin', verifyToken, async (req, res) => {
  try {
    const { studentid, firstname, middlename, lastname, nickname, gender, dateofbirth, familyid, courserefer, shortnote } = req.body;
    if (courserefer != null && courserefer != '') {
      const queryCheckCustomerCourse = 'SELECT * FROM tcustomer_course WHERE courserefer = ?';
      const resCheckCustomerCourse = await queryPromise(queryCheckCustomerCourse, [courserefer]);
      if (resCheckCustomerCourse.length <= 0) {
        return res.json({ success: false, message: 'Course not found' });
      } else {
        const coursetype = resCheckCustomerCourse[0].coursetype;
        if (coursetype == 'Monthly') {
          const queryCheckUserd = 'SELECT count(*) count FROM tstudent WHERE courserefer = ? AND studentid <> ?';
          const resCheckUserd = await queryPromise(queryCheckUserd, [courserefer, studentid]);
          if (resCheckUserd.length > 0) {
            const count = resCheckUserd[0].count;
            console.log("count : " + count);
            if (count > 0) {
              return res.json({ success: false, message: 'Monthly course cannot share, Course already used!' });
            } else {
              const query = 'UPDATE tstudent set firstname = ?, middlename = ?, lastname = ?, nickname = ?, gender = ?, dateofbirth = ?,  ' +
                'familyid = ?, courserefer = ?, shortnote = ?, updateby = ? ' +
                ' WHERE studentid = ?';
              const results = await queryPromise(query, [firstname, middlename, lastname, nickname, gender, dateofbirth, familyid, courserefer, shortnote, req.user.username, studentid])

              if (results.affectedRows > 0) {
                const queryCheckCourseOwner = 'select * from tcustomer_course where courserefer = ?';
                const resCheckCourseOwner = await queryPromise(queryCheckCourseOwner, [courserefer]);
                if (resCheckCourseOwner.length > 0) {
                  let owner = resCheckCourseOwner[0].owner;
                  if(owner != 'trial') {
                    let ownerList = owner ? owner.split(',') : []; // แปลง owner ให้เป็น array
                    if (!ownerList.includes(studentid)) { // ถ้า studentid ไม่อยู่ใน ownerList
                      ownerList.push(studentid); // เพิ่ม studentid เข้าไปใน list
                      let newOwner = ownerList.join(','); // แปลง array กลับเป็น string
                      
                      // ทำการอัปเดตค่า owner ในฐานข้อมูล
                      const queryUpdateOwner = 'UPDATE tcustomer_course SET owner = ? WHERE courserefer = ?';
                      await queryPromise(queryUpdateOwner, [newOwner, courserefer]);
                    }
                  }
                }
                return res.json({ success: true, message: 'แก้ไขข้อมูลสำเร็จ' });
              } else {
                return res.json({ success: false, message: 'แก้ไขข้อมูลไม่สำเร็จ' });
              }
            }
          }
        } else {
          const query = 'UPDATE tstudent set firstname = ?, middlename = ?, lastname = ?, nickname = ?, gender = ?, dateofbirth = ?,  ' +
            'familyid = ?, courserefer = ?, shortnote = ?, updateby = ? ' +
            ' WHERE studentid = ?';
          const results = await queryPromise(query, [firstname, middlename, lastname, nickname, gender, dateofbirth, familyid, courserefer, shortnote, req.user.username, studentid])

          if (results.affectedRows > 0) {
            const queryCheckCourseOwner = 'select * from tcustomer_course where courserefer = ?';
            const resCheckCourseOwner = await queryPromise(queryCheckCourseOwner, [courserefer]);
            if (resCheckCourseOwner.length > 0) {
              let owner = resCheckCourseOwner[0].owner;
              if(owner != 'trial') {
                let ownerList = owner ? owner.split(',') : []; // แปลง owner ให้เป็น array
                if (!ownerList.includes(studentid)) { // ถ้า studentid ไม่อยู่ใน ownerList
                  ownerList.push(studentid); // เพิ่ม studentid เข้าไปใน list
                  let newOwner = ownerList.join(','); // แปลง array กลับเป็น string
                  
                  // ทำการอัปเดตค่า owner ในฐานข้อมูล
                  const queryUpdateOwner = 'UPDATE tcustomer_course SET owner = ? WHERE courserefer = ?';
                  await queryPromise(queryUpdateOwner, [newOwner, courserefer]);
                }
              }
            }
            return res.json({ success: true, message: 'แก้ไขข้อมูลสำเร็จ' });
          } else {
            return res.json({ success: false, message: 'แก้ไขข้อมูลไม่สำเร็จ' });
          }
        }
      }
    } else {
      const query = 'UPDATE tstudent set firstname = ?, middlename = ?, lastname = ?, nickname = ?, gender = ?, dateofbirth = ?,  ' +
        'familyid = ?, shortnote = ?, courserefer = NULL, updateby = ?' +
        ' WHERE studentid = ?';
      const results = await queryPromise(query, [firstname, middlename, lastname, nickname, gender, dateofbirth, familyid, shortnote, req.user.username, studentid])
      return res.json({ success: true, message: 'แก้ไขข้อมูลสำเร็จ' });
    }

  } catch (error) {
    console.log("updateStudentByAdmin error : " + JSON.stringify(error));
    res.status(500).send(error);
  }
});

app.post('/addBookingByAdmin', verifyToken, async (req, res) => {
  try {
    const { studentid, classid, classdate, classtime, courseid, classday } = req.body;
    const checkDuplicateReservationQuery = 'select * from treservation where studentid = ? and classdate = ? and classtime = ?';
    const resCheckDuplicateReservation = await queryPromise(checkDuplicateReservationQuery, [studentid, classdate, classtime]);

    if (resCheckDuplicateReservation.length > 0) {
      return res.json({ success: false, message: 'You have already booked on this day' });
    }

    const checkClassFullQuery = 'select maxperson from tclassinfo where classid = ? and classday = ? and classtime = ?';
    const resCheck = await queryPromise(checkClassFullQuery, [classid, classday, classtime]);

    if (resCheck.length > 0) {
      const maxperson = resCheck[0].maxperson;
      const checkClassFullQueryCount = 'select count(*) as count from treservation where classid = ? and classdate = ? and classtime = ?';
      const results1 = await queryPromise(checkClassFullQueryCount, [classid, classdate, classtime]);

      if (results1.length > 0) {
        const count = results1[0].count;
        if (count >= maxperson) {
          return res.json({ success: false, message: 'Sorry, this class is full' });
        }

        const checkCourseQuery = 'select a.courserefer , b.coursetype, b.remaining, b.expiredate, b.period from tstudent a inner join tcustomer_course b on a.courserefer = b.courserefer where studentid = ?';
        const results2 = await queryPromise(checkCourseQuery, [studentid]);

        if (results2.length > 0) {
          const courserefer = results2[0].courserefer;
          const coursetype = results2[0].coursetype;
          let expiredate = results2[0].expiredate;
          const remaining = results2[0].remaining;
          if(expiredate == null) {
            const period = results2[0].period;
            expiredate = moment(classdate).add(period, 'M').format('YYYY-MM-DD');
            const updateExpireDateQuery = 'UPDATE tcustomer_course SET startdate = ?, expiredate = ? WHERE courserefer = ?';
            await queryPromise(updateExpireDateQuery, [classdate, expiredate, courserefer]);
          } else {
            const today = new Date();
            const todayDateOnly = new Date(today.getFullYear(), today.getMonth(), today.getDate());
            console.log(todayDateOnly);
            console.log("today : " + todayDateOnly);
            console.log("expiredate : " + expiredate);
            console.log(todayDateOnly > expiredate ? 'Expired' : 'Not Expired')

            if (todayDateOnly > expiredate) {
              return res.json({ success: false, message: 'Sorry, your course has expired' });
            }
            
            const cd = new Date(classdate);
            const classDate = new Date(cd.getFullYear(), cd.getMonth(), cd.getDate());
            console.log("classdate : " + classDate);
            if (classDate > expiredate) {
              return res.json({ success: false, message: 'Sorry, your course has expire in ' + moment(expiredate).format('DD/MM/YYYY') });
            }
          }

          if (coursetype != 'Monthly') {
            if (remaining <= 0) {
              return res.json({ success: false, message: 'Sorry, you have no remaining classes' });
            }
          }

          console.log("======= addBookingByAdmin =======");
          const query = 'INSERT INTO treservation (studentid, classid, classdate, classtime, courseid, courserefer, createby) VALUES (?, ?, ?, ?, ?, ?, ?)';
          const insertResult = await queryPromise(query, [studentid, classid, classdate, classtime, courseid, courserefer, req.user.username]);
          console.log("insertResult : " + JSON.stringify(insertResult));
          if (insertResult.affectedRows > 0) {
            const updateRemainingQuery = 'UPDATE tcustomer_course SET remaining = remaining - 1 WHERE courserefer = ?';
            const updateResult = await queryPromise(updateRemainingQuery, [courserefer]);

            try {
              // Format date for notification
              const queryNotifyData = 'SELECT a.nickname, CONCAT(IFNULL(a.firstname, \'\'), \' \', IFNULL(a.middlename, \'\'), IF(a.middlename<>\'\', \' \', \'\'), IFNULL( a.lastname, \'\')) fullname, a.dateofbirth, ' +
                ' c.course_shortname ' +
                ' FROM tstudent a ' +
                ' INNER JOIN tcustomer_course b ' +
                ' ON a.courserefer = b.courserefer ' +
                ' INNER JOIN tcourseinfo c ' +
                ' ON b.courseid = c.courseid ' +
                ' WHERE studentid = ?';
              const results = await queryPromise(queryNotifyData, [studentid]);
              if (results.length > 0 && req.user.username != 'tnpl') {
                const studentnickname = results[0].nickname;
                const studentname = results[0].fullname;
                const coursename = results[0].course_shortname;
                var a = moment(classdate, "YYYYMMDD");
                const bookdate = new Date(a).toLocaleDateString('th-TH', {
                  year: 'numeric',
                  month: 'short',
                  day: 'numeric',
                });

                // Function to calculate age in years and months
                const calculateAge = (dateOfBirth) => {
                  const dob = new Date(dateOfBirth);
                  const diff = Date.now() - dob.getTime();
                  const ageDate = new Date(diff);
                  const ageYears = ageDate.getUTCFullYear() - 1970;
                  const ageMonths = ageDate.getUTCMonth();
                  return parseFloat(`${ageYears}.${ageMonths}`);
                };
                // Prepare notification data
                const jsonData = {
                  message: coursename + '\n' + studentnickname + ' ' + studentname + '\nอายุ ' + calculateAge(results[0].dateofbirth) + 'ปี' + '\nวันที่ ' + bookdate + ' ' + classtime + '\nโดยแอดมิน ' + req.user.username,
                };

                sendNotification(jsonData);
              }
            } catch (error) {
              console.error('Error sending notification', error.stack);
              
            }

            return res.json({ success: true, message: 'Booking added successfully' });
          }
        } else {
          return res.json({ success: false, message: 'Not found customer\'s course' });
        }
      }
    } else {
      return res.json({ success: false, message: 'No class found' });
    }

  } catch (error) {
    console.log("addBookingByAdmin error : " + JSON.stringify(error));
    res.status(500).send(error);
  }
});


app.post('/updateBookingByAdmin', verifyToken, async (req, res) => {
  // todo : check duplicate booking on same day
  try {
    const { studentid, classid, classdate, classtime, courseid, classday, reservationid } = req.body;
    const checkDuplicateReservationQuery = 'select * from treservation where studentid = ? and classdate = ? and reservationid <> ? ';
    const resCheckDuplicateReservation = await queryPromise(checkDuplicateReservationQuery, [studentid, classdate, reservationid]);
    
    if (resCheckDuplicateReservation.length > 0) {
      return res.json({ success: false, message: 'You have already booked on this day' });
    }

    const checkClassFullQuery = 'select maxperson from tclassinfo where classid = ? and classday = ? and classtime = ?';
    const resCheck = await queryPromise(checkClassFullQuery, [classid, classday, classtime]);

    if (resCheck.length > 0) {
      const maxperson = resCheck[0].maxperson;
      const checkClassFullQueryCount = 'select count(*) as count from treservation where classid = ? and classdate = ? and classtime = ?';
      const results1 = await queryPromise(checkClassFullQueryCount, [classid, classdate, classtime]);

      if (results1.length > 0) {
        const count = results1[0].count;
        if (count >= maxperson) {
          return res.json({ success: false, message: 'Sorry, this class is full' });
        }

        const checkCourseQuery = 'select a.courserefer from tstudent a inner join tcustomer_course b on a.courserefer = b.courserefer where studentid = ?';
        const results2 = await queryPromise(checkCourseQuery, [studentid]);

        if (results2.length > 0) {
          const courserefer = results2[0].courserefer;
          const checkCourseExpiredQuery = 'select remaining, expiredate from tcustomer_course where courserefer = ?';
          const results3 = await queryPromise(checkCourseExpiredQuery, [courserefer]);

          if (results3.length > 0) {
            const expiredate = results3[0].expiredate;
            const today = new Date();
            const todayDateOnly = new Date(today.getFullYear(), today.getMonth(), today.getDate());
            console.log("today : " + todayDateOnly);
            console.log("expiredate : " + expiredate);
            console.log(todayDateOnly > expiredate ? 'Expired' : 'Not Expired')
            if (todayDateOnly > expiredate) {
              return res.json({ success: false, message: 'Sorry, your course has expired' });
            }

            const cd = new Date(classdate);
            console.log("classdate : " + cd);
            if (cd > expiredate) {
              return res.json({ success: false, message: 'Sorry, your course has expire in ' + moment(expiredate).format('DD/MM/YYYY') });
            } else {
              let oldClassdate = '';
              let oldClasstime = '';
              const queryOldReservation = 'SELECT * FROM treservation WHERE reservationid = ?';
              const results4 = await queryPromise(queryOldReservation, [reservationid]);
              if (results4.length > 0) {
                oldClassdate = results4[0].classdate;
                oldClasstime = results4[0].classtime;
              }
              var b = moment(oldClassdate, "YYYYMMDD");
              oldClassdate = new Date(b).toLocaleDateString('th-TH', {
                  year: 'numeric',
                  month: 'short',
                  day: 'numeric',
              });
                
              console.log("======= updateBookingByAdmin =======");
              const query = 'UPDATE treservation SET studentid = ?, classid = ?, classdate = ?, classtime = ?, courseid = ?, updateby = ? WHERE reservationid = ?';
              const insertResult = await queryPromise(query, [studentid, classid, classdate, classtime, courseid, req.user.username, reservationid]);

              if (insertResult.affectedRows > 0) {

                try {
                  // Format date for notification
                  const queryNotifyData = 'SELECT a.nickname, CONCAT(IFNULL(firstname, \'\'), \' \', IFNULL(a.middlename, \'\'), IF(a.middlename<>\'\', \' \', \'\'), IFNULL( a.lastname, \'\')) fullname, a.dateofbirth, ' +
                    ' c.course_shortname ' +
                    ' FROM tstudent a ' +
                    ' INNER JOIN tcustomer_course b ' +
                    ' ON a.courserefer = b.courserefer ' +
                    ' INNER JOIN tcourseinfo c ' +
                    ' ON b.courseid = c.courseid ' +
                    ' WHERE studentid = ?';
                  const results = await queryPromise(queryNotifyData, [studentid]);
                  if (results.length > 0) {
                    const studentnickname = results[0].nickname;
                    const studentname = results[0].fullname;
                    const coursename = results[0].course_shortname;
                    var a = moment(classdate, "YYYYMMDD");
                    const bookdate = new Date(a).toLocaleDateString('th-TH', {
                      year: 'numeric',
                      month: 'short',
                      day: 'numeric',
                    });

                    const calculateAge = (dateOfBirth) => {
                      const dob = new Date(dateOfBirth);
                      const diff = Date.now() - dob.getTime();
                      const ageDate = new Date(diff);
                      const ageYears = ageDate.getUTCFullYear() - 1970;
                      const ageMonths = ageDate.getUTCMonth();
                      return parseFloat(`${ageYears}.${ageMonths}`);
                    };
                    // Prepare notification data
                    const jsonData = {
                      message: coursename + '\n' + studentnickname + ' ' + studentname + '\nอายุ ' + calculateAge(results[0].dateofbirth) + 'ปี' + '\nจาก ' + oldClassdate + ' ' + oldClasstime + '\nเป็น ' + bookdate + ' ' + classtime +'\nโดยแอดมิน ' + req.user.username,
                    };

                    sendNotificationUpdate(jsonData);
                  }
                } catch (error) {
                  console.error('Error sending notification', error.stack);
                  
                }
                return res.json({ success: true, message: 'Booking added successfully' });
              }
            }
          }
        }
      }
    } else {
      return res.json({ success: false, message: 'No class found' });
    }
  } catch (error) {
    console.log("updateBookingByAdmin error : " + JSON.stringify(error));
    res.status(500).send(error);
  }
});

app.post("/cancelBookingByAdmin", verifyToken, async (req, res) => {
  try {
    const { reservationid, studentid, courserefer } = req.body;
    const query = 'DELETE FROM treservation WHERE reservationid = ?';
    const results = await queryPromise(query, [reservationid]);
    console.log("parameters : " + reservationid + " " + studentid + " " + courserefer);
    if (results.affectedRows > 0) {
        const updateRemainingQuery = 'UPDATE tcustomer_course SET remaining = remaining + 1 WHERE courserefer = ?';
        await queryPromise(updateRemainingQuery, [courserefer]);
        res.json({ success: true, message: 'ยกเลิกการจองสำเร็จ' });
        
    } else {
      res.json({ success: false, message: 'ไม่มีข้อมูลการจอง' });
    }
  } catch (error) {
    console.error("Error in deleteReservationByAdmin", error.stack);
    
    res.json({ success: false, message: error.message });
  }
});

app.post('/deleteStudent', verifyToken, async (req, res) => {
  const { familyid, studentid, journal } = req.body;
  console.log("deleteStudent : " + JSON.stringify(req.body));
  let queryDeleteStudent = 'UPDATE tstudent SET delflag = 1, courserefer = NULL, updateby = ? WHERE familyid = ? AND studentid = ?';
  if (journal === '1') {
    queryDeleteStudent = 'DELETE FROM jstudent WHERE familyid = ? AND studentid = ?';
  }
  try {
    const results = await queryPromise(queryDeleteStudent, [req.user.username, familyid, studentid]);
    if (results.affectedRows > 0) {
      // if (journal != '1') {
      //   const queryDeleteTreservation = 'DELETE FROM treservation WHERE studentid = ?';
      //   await queryPromise(queryDeleteTreservation, [studentid]);
      // }
      return res.json({ success: true, message: 'Family member deleted successfully' });
    } else {
      return res.json({ success: false, message: 'No Family member data' });
    }
  } catch (error) {
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
  await queryPromise(query, [studentid, courserefer])
    .then((results) => {
      if (results.length > 0) {
        res.json({ success: true, message: 'Get Reservation Detail successful', results });
      } else {
        res.json({ success: true, message: 'No Reservation Detail' });
      }
    })
    .catch((error) => {
      res.json({ success: false, message: error.message });
      console.error('Error in getMemberReservationDetail', error.stack);
    })
});

app.post('/createReservation', verifyToken, async (req, res) => {

  try {
    const { courseid, classid, classday, classdate, classtime, studentid } = req.body;
    const checkDuplicateReservationQuery = 'select * from treservation where studentid = ? and classdate = ? ';
    const resCheckDuplicateReservation = await queryPromise(checkDuplicateReservationQuery, [studentid, classdate]);

    if (resCheckDuplicateReservation.length > 0) {
      return res.json({ success: false, message: 'You have already booked on this day' });
    }

    const checkClassFullQuery = 'select maxperson from tclassinfo where classid = ? and classday = ? and classtime = ?';
    const resCheck = await queryPromise(checkClassFullQuery, [classid, classday, classtime]);

    if (resCheck.length > 0) {
      const maxperson = resCheck[0].maxperson;
      const checkClassFullQueryCount = 'select count(*) as count from treservation where classid = ? and classdate = ? and classtime = ?';
      const results1 = await queryPromise(checkClassFullQueryCount, [classid, classdate, classtime]);

      if (results1.length > 0) {
        const count = results1[0].count;
        if (count >= maxperson) {
          return res.json({ success: false, message: 'Sorry, this class is full' });
        }

        const checkCourseQuery = 'select a.courserefer , b.coursetype, b.remaining, b.expiredate, b.period from tstudent a inner join tcustomer_course b on a.courserefer = b.courserefer where studentid = ?';
        const results2 = await queryPromise(checkCourseQuery, [studentid]);

        if (results2.length > 0) {
          const courserefer = results2[0].courserefer;
          const coursetype = results2[0].coursetype;
          let expiredate = results2[0].expiredate;
          const remaining = results2[0].remaining;
          if(expiredate == null) {
            const period = results2[0].period;
            expiredate = moment(classdate).add(period, 'M').format('YYYY-MM-DD');
            const updateExpireDateQuery = 'UPDATE tcustomer_course SET startdate = ?, expiredate = ? WHERE courserefer = ?';
            await queryPromise(updateExpireDateQuery, [classdate, expiredate, courserefer]);
          } else {
            const today = new Date();
            const todayDateOnly = new Date(today.getFullYear(), today.getMonth(), today.getDate());
            console.log("today : " + todayDateOnly);
            console.log("expiredate : " + expiredate);
            console.log(todayDateOnly > expiredate ? 'Expired' : 'Not Expired')
            if (todayDateOnly > expiredate) {
              return res.json({ success: false, message: 'Sorry, your course has expired' });
            }

            const cd = new Date(classdate);
            console.log("classdate : " + cd);
            if (cd > expiredate) {
              return res.json({ success: false, message: 'Sorry, your course has expire in ' + moment(expiredate).format('DD/MM/YYYY') });
            }
          }

          if (coursetype != 'Monthly') {
            if (remaining <= 0) {
              return res.json({ success: false, message: 'Sorry, you have no remaining classes' });
            }
          }

          const query = 'INSERT INTO treservation (studentid, classid, classdate, classtime, courseid, courserefer, createby) VALUES (?, ?, ?, ?, ?, ?, ?)';
          const insertResult = await queryPromise(query, [studentid, classid, classdate, classtime, courseid, courserefer, req.user.username]);

          if (insertResult.affectedRows > 0) {
            const updateRemainingQuery = 'UPDATE tcustomer_course SET remaining = remaining - 1 WHERE courserefer = ?';
            const updateResult = await queryPromise(updateRemainingQuery, [courserefer]);

            try {
              // Format date for notification
              const queryNotifyData = 'SELECT a.nickname, CONCAT(IFNULL(a.firstname, \'\'), \' \', IFNULL(a.middlename, \'\'), IF(a.middlename<>\'\', \' \', \'\'), IFNULL( a.lastname, \'\')) fullname, a.dateofbirth,' +
                ' c.course_shortname ' +
                ' FROM tstudent a ' +
                ' INNER JOIN tcustomer_course b ' +
                ' ON a.courserefer = b.courserefer ' +
                ' INNER JOIN tcourseinfo c ' +
                ' ON b.courseid = c.courseid ' +
                ' WHERE studentid = ?';
              const results = await queryPromise(queryNotifyData, [studentid]);
              if (results.length > 0) {
                const studentnickname = results[0].nickname;
                const studentname = results[0].fullname;
                const coursename = results[0].course_shortname;
                var a = moment(classdate, "YYYYMMDD");
                const bookdate = new Date(a).toLocaleDateString('th-TH', {
                  year: 'numeric',
                  month: 'short',
                  day: 'numeric',
                });

                const calculateAge = (dateOfBirth) => {
                  const dob = new Date(dateOfBirth);
                  const diff = Date.now() - dob.getTime();
                  const ageDate = new Date(diff);
                  const ageYears = ageDate.getUTCFullYear() - 1970;
                  const ageMonths = ageDate.getUTCMonth();
                  return parseFloat(`${ageYears}.${ageMonths}`);
                };
                // Prepare notification data
                const jsonData = {
                  message: coursename + '\n' + studentnickname + ' ' + studentname + '\nอายุ ' + calculateAge(results[0].dateofbirth) + 'ปี' + '\nวันที่ ' + bookdate + ' ' + classtime + '\nโดยผู้ปกครอง ' + req.user.username,
                };

                sendNotification(jsonData);
              }
            } catch (error) {
              console.error('Error sending notification', error.stack);
            }
            return res.json({ success: true, message: 'Booking added successfully' });
          }
        }
      }
    }

    return res.json({ success: false, message: 'Error in processing booking' });
  } catch (error) {
    console.log("createReservation error : " + JSON.stringify(error));
    res.status(500).send(error);
  }
});

async function sendNotification(jsonData) {
  try {
    // Send notification
    const requestOption = {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        Authorization: `Bearer ` + accessCode,
      },
      data: qs.stringify(jsonData),
      url,
    };

    await axios(requestOption);
    console.log('Notification Sent Successfully');
  } catch (error) {
    console.error('Error sending notification', error.stack);
    throw error;
  }
}

async function sendNotificationUpdate(jsonData) {
  try {
    // Send notification
    const requestOption = {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        Authorization: `Bearer ` + accessCode2,
      },
      data: qs.stringify(jsonData),
      url,
    };

    await axios(requestOption);
    console.log('Notification Sent Successfully');
  } catch (error) {
    console.error('Error sending notification:', error.stack);
    throw error;
  }
}

app.post('/deleteReservation', verifyToken, async (req, res) => {
  const { reservationid } = req.body;
  const query = 'DELETE FROM treservation WHERE reservationid = ?';
  try {
    await queryPromise(query, [reservationid])
      .then((results) => {
        res.json({ success: true, message: 'Reservation deleted successfully' });
      })
      .catch((error) => {
        res.status(500).send(error);
      });
  } catch (error) {
    console.error('Error in deleteReservation', error.stack);
    res.status(500).send(error);
  }
});

app.post('/checkDuplicateReservation', verifyToken, async (req, res) => {
  const { studentid, classdate } = req.body;
  const query = 'SELECT * FROM treservation WHERE studentid = ? and classdate = ?';
  try {
    const results = await queryPromise(query, [studentid, classdate]);
    if (results.length > 0) {
      return res.json({ success: false, message: 'You have already reservation on this day' });
    } else {
      return res.json({ success: true, message: 'No Reservation on this day' });
    }
  } catch (error) {
    console.error('Error in checkDuplicateReservation', error.stack);
    return res.status(500).send(error);
  }
});

app.get('/getAllCourses', verifyToken, async (req, res) => {
  const query = 'SELECT * FROM tcourseinfo';
  try {
    await queryPromise(query, null)
      .then((results) => {
        if (results.length > 0) {
          return res.json({ success: true, message: 'Get All Course successful', results });
        } else {
          return res.json({ success: false, message: 'No Course' });
        }
      })
      .catch((error) => {
        return res.status(500).send(error);
      });
  } catch (error) {
    console.error('Error in getAllCourses', error.stack);
    return res.status(500).send(error);
  }
});

app.post('/addCourse', verifyToken, async (req, res) => {
  const { coursename, course_shortname } = req.body;
  const query = 'INSERT INTO tcourseinfo (coursename, course_shortname) VALUES (?, ?)';
  try {
    await queryPromise(query, [coursename, course_shortname])
      .then((results) => {
        res.json({ success: true, message: 'Course added successfully' });
      })
      .catch((error) => {
        res.status(500).send(error);
      });
  } catch (error) {
    console.error('Error in addCourse', error.stack);
    res.status(500).send(error);
  }
});

app.post('/updateCourse', verifyToken, async (req, res) => {
  const { coursename, course_shortname, courseid } = req.body;
  const query = 'UPDATE tcourseinfo SET coursename = ?, course_shortname = ? WHERE courseid = ?';
  try {
    await queryPromise(query, [coursename, course_shortname, courseid])
      .then((results) => {
        res.json({ success: true, message: 'Course updated successfully' });
      })
      .catch((error) => {
        res.status(500).send(error);
      });
  } catch (error) {
    console.error('Error in updateCourse', error.stack);
    res.status(500).send(error);
  }
});

app.post('/deleteCourse', verifyToken, async (req, res) => {
  const { courseid } = req.body;
  const deletetcourseinfoQuery = 'UPDATE tcourseinfo SET enableflag = 0 WHERE courseid = ?';
  try {
    await queryPromise(deletetcourseinfoQuery, [courseid])
      .then((results) => {
        const deleteTclassinfoQuery = 'UPDATE tclassinfo SET enableflag = 0 WHERE courseid = ?';
        queryPromise(deleteTclassinfoQuery, [courseid]);
        res.json({ success: true, message: 'Course disable successfully' });
      })
      .catch((error) => {
        res.status(500).send(error);
      });
  } catch (error) {
    console.error('Error in deleteCourse', error.stack);
    res.status(500).send(error);
  }
});

app.get('/getAllClasses', verifyToken, async (req, res) => {
  const { courseid } = req.body;
  const query = 'SELECT b.courseid, b.coursename, a.* FROM tclassinfo a inner join tcourseinfo b on a.courseid = b.courseid order by b.coursename , a.classday ';
  try {
    await queryPromise(query, null)
      .then((results) => {
        if (results.length > 0) {
          return res.json({ success: true, message: 'Get All Class successful', results });
        } else {
          return res.json({ success: true, message: 'No Class', results });
        }
      })
      .catch((error) => {
        return res.status(500).send(error);
      });
  }
  catch (error) {
    console.error('Error in getAllClasses', error.stack);
    return res.status(500).send(error);
  }
});

app.post('/addClass', verifyToken, async (req, res) => {
  const { courseid, classday, classtime, maxperson } = req.body;
  const query = 'INSERT INTO tclassinfo (courseid, classday, classtime, maxperson, adminflag) VALUES (?, ?, ?, ?, ?)';
  try {
    await queryPromise(query, [courseid, classday, classtime, maxperson])
      .then((results) => {
        return res.json({ success: true, message: 'Class added successfully' });
      })
      .catch((error) => {
        res.status(500).send(error);
      });
  } catch (error) {
    console.error('Error in addClass', error.stack);
    res.status(500).send(error);
  }
});

app.post('/updateClass', verifyToken, async (req, res) => {
  const { classid, courseid, classday, classtime, maxperson } = req.body;
  const query = 'UPDATE tclassinfo SET courseid = ?, classday = ?, classtime = ?, maxperson = ?, adminflag = ? WHERE classid = ?';
  try {
    await queryPromise(query, [courseid, classday, classtime, maxperson, adminflag, classid])
      .then((results) => {
        res.json({ success: true, message: 'Class updated successfully' });
      })
      .catch((error) => {
        res.status(500).send(error);
      });
  } catch (error) {
    console.error('Error in updateClass', error.stack);
    res.status(500).send(error);
  }
});

app.post('/deleteClass', verifyToken, async (req, res) => {
  const { classid } = req.body;
  const query = 'DELETE FROM tclassinfo WHERE classid = ?';
  try {
    await queryPromise(query, [classid])
      .then((results) => {
        const query2 = 'DELETE FROM treservation WHERE classid = ?';
        queryPromise(query2, [classid]);
        res.json({ success: true, message: 'Class deleted successfully' });
      })
      .catch((error) => {
        res.status(500).send(error);
      });
  } catch (error) {
    console.error('Error in deleteClass', error.stack);
    res.status(500).send(error);
  }
});

app.post('/getClassTime', verifyToken, async (req, res) => {
  const { classdate, classday, courseid } = req.body;
  let query = 'SELECT a.* , case when count(b.reservationid) > 0 then a.maxperson - count(b.reservationid) else a.maxperson end as available ' +
    'FROM tclassinfo a ' +
    'left join treservation b ' +
    'on a.classid = b.classid ' +
    'and b.classdate = ? ' +
    'WHERE a.classday = ? ' +
    'and a.courseid = ? ';
    if(req.user.adminflag != '1') {
      query += 'and a.adminflag = 0 ';
    }
    query += ' group by a.classid , a.classday , a.classtime , a.maxperson , a.courseid ';
  try {
    await queryPromise(query, [classdate, classday, courseid])
      .then((results) => {
        if (results.length > 0) {
          results.forEach((element, index) => {
            results[index].text = element.classtime + ' ว่าง ' + element.available + ' คน';
          });
          res.json({ success: true, message: 'Get Class Time successful', results });
        } else {
          res.json({ success: true, message: 'No Class Time', results: [] });
        }
      })
      .catch((error) => {
        res.status(500).send(error);
      });
  } catch (error) {
    console.error('Error in getClassTime', error.stack);
    res.status(500).send(error);
  }
});

app.get("/getNewStudentList", verifyToken, async (req, res) => {
  const query = "select a.*, CONCAT(IFNULL( a.firstname, ''), ' ', IFNULL( a.middlename, ''), IF( a.middlename<>'', ' ',''), IFNULL( a.lastname, ''), ' (', a.nickname,')') fullname, c.username, c.mobileno from jstudent a left join tfamily b on a.familyid = b.familyid left join tuser c on b.username = c.username";
  try {
    await queryPromise(query, null)
      .then((results) => {
        if (results.length > 0) {
          res.json({ success: true, message: 'Get New Students successful', results });
        } else {
          res.json({ success: true, message: 'No New Students', results });
        }
      })
      .catch((error) => {
        res.status(500).send(error);
      })
  } catch (error) {
    res.status(500).send(error);
    console.error('Error in getNewStudentList', error.stack);
  }
});

app.get("/courseLookup", verifyToken, async (req, res) => {
  const query = 'SELECT * FROM tcourseinfo WHERE enableflag = 1';
  await queryPromise(query, null)
    .then((results) => {
      if (results.length > 0) {
        res.json({ success: true, message: 'Get Course Lookup successful', results });
      } else {
        res.json({ success: true, message: 'No Course Lookup' });
      }
    })
    .catch((error) => {
      res.json({ success: false, message: error.message });
      console.error('Error in courseLookup', error.stack);
    })
});

app.get("/customerCourseLookup", verifyToken, async (req, res) => {
  const query = 'SELECT * FROM tcustomer_course where finish = 0';
  await queryPromise(query, null)
    .then((results) => {
      if (results.length > 0) {
        res.json({ success: true, message: 'Get Customer Course Lookup successful', results });
      } else {
        res.json({ success: true, message: 'No Customer Course Lookup' });
      }
    })
    .catch((error) => {
      res.json({ success: false, message: error.message });
      console.error('Error in customerCourseLookup', error.stack);
      
    })
});

app.post('/getCustomerCourseInfo', verifyToken, async (req, res) => {
  const { studentid } = req.body;
  const query = 'SELECT * from tcustomer_course where courserefer = (select courserefer from tstudent where studentid = ?)';
  try {
    await queryPromise(query, [studentid])
      .then((results) => {
        return res.json({ success: true, results });
      })
      .catch((error) => {
        res.status(500).send(error);
      });
  } catch (error) {
    console.error('Error in getCustomerCourseInfo', error.stack);
    res.status(500).send(error);
  }
});

app.post('/finishCustomerCourse', verifyToken, async (req, res) => {
  const { courserefer } = req.body;
  const query = 'UPDATE tcustomer_course SET finish = 1 WHERE courserefer = ?';
  try {
    await queryPromise(query, [courserefer])
      .then((results) => {
        const query2 = 'UPDATE tstudent SET courserefer = NULL WHERE courserefer = ?';
        queryPromise(query2, [courserefer]);
        
        return res.json({ success: true, message: 'Course finished successfully' });
      })
      .catch((error) => {
        res.status(500).send(error);
      });
  } catch (error) { 
    console.error('Error in finishCustomerCourse', error.stack);
    res.status(500).send(error);
  }
});

app.get("/getFinishedCourse", verifyToken, async (req, res) => {
  const query = 'SELECT * FROM tcustomer_course WHERE finish = 1';
  try {
    await queryPromise(query, null)
      .then((results) => {
        return res.json({ success: true, results });
      })
      .catch((error) => {
        res.status(500).send(error);
      });
  } catch (error) {
    console.error('Error in getFinishedCourse', error.stack);
    res.status(500).send(error);
  }
});

app.get("/familyLookup", verifyToken, async (req, res) => {
  const query = 'SELECT * FROM tfamily';
  await queryPromise(query, null)
    .then((results) => {
      if (results.length > 0) {
        res.json({ success: true, message: 'Get Family Lookup successful', results });
      } else {
        res.json({ success: true, message: 'No Family Lookup' });
      }
    })
    .catch((error) => {
      res.json({ success: false, message: error.message });
      console.error('Error in familyLookup', error.stack);
    })
});

app.post("/studentLookup", verifyToken, async (req, res) => {
  const { familyid } = req.body;
  const query = "SELECT studentid, CONCAT(IFNULL(nickname, ''), ' ', IFNULL(firstname, ''), ' ', IFNULL(middlename, ''), IF( middlename<>'', ' ', ''), IFNULL(lastname, '')) as name FROM tstudent where delflag = 0";
  if (familyid !== null && familyid !== undefined && familyid !== '') {
    query = query + ' WHERE familyid = ?';
  }

  await queryPromise(query, [familyid])
    .then((results) => {
      if (results.length > 0) {
        res.json({ success: true, message: 'Get Student Lookup successful', results });
      } else {
        res.json({ success: true, message: 'No Student Lookup' });
      }
    })
    .catch((error) => {
      res.json({ success: false, message: error.message });
      console.error('Error in queryPromise', error.stack);
    })
});

app.get("/getStudentList", verifyToken, async (req, res) => {
  try {
    const query = 'SELECT a.studentid, a.familyid, a.firstname, a.middlename, a.lastname, a.nickname, a.gender, a.dateofbirth, a.courserefer, a.shortnote, ' +
      '   CONCAT(IFNULL(a.firstname,\'\'), \' \', IFNULL(a.middlename,\'\'), IF(a.middlename<>\'\', \' \', \'\'), IFNULL(a.lastname,\'\'), \' (\', a.nickname,\')\') fullname, ' +
      '   CASE WHEN b.coursetype = \'Monthly\' THEN \'รายเดือน\' ' +
      '     WHEN b.coursetype IS NULL THEN \'ไม่มีคอร์ส\' ' +
      '     ELSE CONCAT(b.remaining, \' ครั้ง\') ' +
      '   END AS remaining_label, ' +
      ' b.remaining, b.expiredate, t.coursename, d.mobileno, a.shortnote ' +
      ' FROM tstudent a ' +
      ' LEFT JOIN tcustomer_course b ' +
      ' ON a.courserefer = b.courserefer ' +
      ' LEFT JOIN tcourseinfo t ' +
      ' ON b.courseid = t.courseid ' +
      ' LEFT JOIN tfamily c ' +
      ' ON a.familyid = c.familyid ' +
      ' LEFT JOIN tuser d ' +
      ' ON c.username = d.username' +
      ' WHERE a.delflag = 0';
    const results = await queryPromise(query);

    // มันมีรูป base64 ที่เก็บในฐานข้อมูล ทำให้ข้อมูลมีขนาดใหญ่ ทำให้การปริ้น log มันเยอะมาก
    //console.log("API getStudentlist result :" + JSON.stringify(results));

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
      SELECT a.*, b.coursename, CONCAT(IFNULL(c.firstname, ''), ' ', IFNULL(c.middlename,''), IF( c.middlename<>'', ' ', ''), IFNULL(c.lastname, ''), ' (', IFNULL(c.nickname,'') ,')') fullname, c.dateofbirth, case when c.gender = 'ชาย' then 'ช.' else 'ญ.' end as gender 
      FROM treservation a
      LEFT JOIN tcourseinfo b ON a.courseid = b.courseid
      LEFT JOIN tstudent c ON a.studentid = c.studentid
      WHERE a.classdate = ?
      ORDER BY a.classtime ASC
    `;

    const results = await queryPromise(query, [classdate]);
    //console.log("API getReservationList result: " + JSON.stringify(results));

    // Function to calculate age in years and months
    const calculateAge = (dateOfBirth) => {
      if(dateOfBirth === null) {
        return '';
      }
      const dob = new Date(dateOfBirth);
      const diff = Date.now() - dob.getTime();
      const ageDate = new Date(diff);
      const ageYears = ageDate.getUTCFullYear() - 1970;
      const ageMonths = ageDate.getUTCMonth();
      return parseFloat(`${ageYears}.${ageMonths}`);
    };

    // Add age field to each result
    results.forEach(result => {
      result.fullname = result.fullname + " (" + result.gender + " " + calculateAge(result.dateofbirth) + ")";
    });

    if (results.length > 0) {
      res.json({ success: true, message: 'Get Reservation list successful', results });
    } else {
      res.json({ success: true, message: 'No Reservation list', results });
    }
  } catch (error) {
    console.error("Error in getReservationList" + JSON.stringify(error));
    res.status(500).send(error);
  }
});

app.post("/checkinByAdmin", verifyToken, async (req, res) => {
  try {
    const { reservationid, studentid } = req.body;
    const query = 'UPDATE treservation SET checkedin = 1 WHERE reservationid = ? AND studentid = ?';
    const results = await queryPromise(query, [reservationid, studentid]);

    if (results.affectedRows > 0) {
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
    // Query 1
    const query1 = 'select count(*) as total from tstudent where delflag = 0';
    const results1 = await queryPromise(query1);
    if (results1.length > 0) {
      datacard.totalStudents = results1[0].total;
    }

    // Query 2
    const query2 = 'select count(*) as total from treservation where classdate = ?';
    const results2 = await queryPromise(query2, [today]);
    if (results2.length > 0) {
      datacard.totalBookingToday = results2[0].total;
    }

    // Query 3
    const query3 = 'select count(*) as total from treservation where classdate = ?';
    const results3 = await queryPromise(query3, [tomorrow]);
    if (results3.length > 0) {
      datacard.totalBookingTomorrow = results3[0].total;
    }

    // Query 4
    const query4 = 'select count(*) as total from jstudent';
    const results4 = await queryPromise(query4);
    if (results4.length > 0) {
      datacard.totalWaitingNewStudents = results4[0].total;
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

app.post('/getBookingList', verifyToken, async (req, res) => {
  console.log("getBookingList [request] : " + JSON.stringify(req.body));
  try {
    const { classday, classdate } = req.body;
    const query = 'SELECT DISTINCT a.classtime, a.courseid, CONCAT(a.classtime,\' (\',b.course_shortname,\')\') as class_label, a.classid FROM tclassinfo a join tcourseinfo b on a.courseid = b.courseid and b.enableflag = 1 where a.classday = ? and a.enableflag = 1 order by a.classtime'
    const results = await queryPromise(query, [classday]);
    //console.log("results : " + JSON.stringify(results));
    let bookinglist = {};
    if (results.length > 0) {
      for (let index = 0; index < results.length; index++) {
        let this_class = [];
        const element = results[index];
        const query2 = 'SELECT CONCAT(a.classtime,\' (\',b.course_shortname,\')\') as classtime, c.nickname, a.checkedin, c.dateofbirth, case when c.gender = \'ชาย\' then \'ช.\' else \'ญ.\' end as gender ' +
          'FROM treservation a ' +
          'join tcourseinfo b on  a.courseid = b.courseid ' +
          'left join tstudent c on a.studentid = c.studentid ' +
          'WHERE a.classdate = ? ' +
          'AND a.classid = ? ' +
          'order by a.classtime asc';

        const results2 = await queryPromise(query2, [classdate, element.classid]);
        //console.log("results2 : " + JSON.stringify(results2));

        // Function to calculate age in years and months
        const calculateAge = (dateOfBirth) => {
          if(dateOfBirth == null || dateOfBirth == undefined || dateOfBirth == ''){
            return '';
          }
          const dob = new Date(dateOfBirth);
          const diff = Date.now() - dob.getTime();
          const ageDate = new Date(diff);
          const ageYears = ageDate.getUTCFullYear() - 1970;
          const ageMonths = ageDate.getUTCMonth();
          return parseFloat(`${ageYears}.${ageMonths}`);
        };

        // Add age field to each result
        results2.forEach(results2 => {
          results2.nickname = results2.nickname + " (" + results2.gender + calculateAge(results2.dateofbirth) + ")";
        });

        if (results2.length > 0) {
          let studentlist = [];
          for (let index2 = 0; index2 < results2.length; index2++) {
            const element2 = results2[index2];
            if (element2.checkedin == 1) {
              studentlist.push(element2.nickname + "(" + element2.checkedin + ")");
            } else {
              studentlist.push(element2.nickname);
            }
          }
          bookinglist[element.class_label] = studentlist;
        } else {
          if(element.classtime.includes('แข่ง')) {
            delete bookinglist[element.class_label];
          } else {
            bookinglist[element.class_label] = [];
          }
        }
      }
      console.log("getBookingList [response] : " + JSON.stringify(bookinglist));
      res.json({ success: true, message: 'Get Booking list successful', bookinglist });
    } else {
      res.json({ success: true, message: 'No Booking list' });
    }
  } catch (error) {
    console.error('Error in getBookingList', error.stack);
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

app.post('/addCustomerCourse', verifyToken, async (req, res) => {
  try {
    const { coursetype, course, remaining, startdate, expiredate, period } = req.body;
    const courserefer = await generateRefer(course.refercode);
    let query = 'INSERT INTO tcustomer_course (courserefer, courseid ';
      if (coursetype) query += ', coursetype ';
      if (remaining) query += ', remaining ';
      if (startdate) query += ', startdate ';
      if (expiredate) query += ', expiredate ';
      if (period) query += ', period ';
      query += ') VALUES (?, ?';
      if (coursetype) query += ', ?';
      if (remaining) query += ', ?';
      if (startdate) query += ', ?';
      if (expiredate) query += ', ?';
      if (period) query += ', ?';
      query += ')';
      const params = [courserefer, course.courseid];
      if (coursetype) params.push(coursetype);
      if (remaining) params.push(remaining);
      if (startdate) params.push(startdate);
      if (expiredate) params.push(expiredate);
      if (period) params.push(period);

    const results = await queryPromise(query, params);
    if (results.affectedRows > 0) {
      res.json({ success: true, message: 'Successfully Course No :' + courserefer, courserefer });
    } else {
      res.json({ success: false, message: 'Error adding Customer Course' });
    }
  } catch (error) {
    console.error('Error in addCustomerCourse', error.stack);
    res.status(500).send(error);
  }
});

app.post('/updateCustomerCourse', verifyToken, async (req, res) => {
  try {
    const { courserefer, courseid, coursetype, remaining, startdate, expiredate, period } = req.body;
    const query = 'UPDATE tcustomer_course SET courseid = ?, coursetype = ?, remaining = ?, startdate = ?, expiredate = ?, period = ? WHERE courserefer = ?';
    const results = await queryPromise(query, [courseid, coursetype, remaining, startdate, expiredate, period, courserefer]);
    if (results.affectedRows > 0) {
      res.json({ success: true, message: 'Customer Course updated successfully' });
    } else {
      res.json({ success: false, message: 'Error updating Customer Course' });
    }
  } catch (error) {
    console.error('Error in updateCustomerCourse', error.stack);
    res.status(500).send(error);
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


app.put('/student/:studentid/profile-image', verifyToken, async (req, res) => {
  const { studentid } = req.params;
  const { image } = req.body;
  console.log("upload image for studentid : " + studentid)
  if (!image) {
    return res.status(400).send('No image provided.');
  }
  if (Buffer.byteLength(image, 'base64') > 4 * 1024 * 1024) {
    return res.status(400).send('Image size exceeds 5MB.');
  }
  // Update the gymnast's profile with the image URL in your database
  try {
    const query = 'UPDATE tstudent SET profile_image = ?, updateby = ? WHERE studentid = ?';
    const results = await queryPromise(query, [image, req.user.username, studentid]);
    if (results.affectedRows > 0) {
      res.json({ success: true, message: 'Profile image uploaded successfully' });
    } else {
      res.json({ success: false, message: 'Error uploading profile image' });
    }
  } catch (error) {
    res.status(500).send('Error updating profile image URL.');
    throw error;
  }
});

app.get('/student/:studentid/profile-image', verifyToken, async (req, res) => {
  const { studentid } = req.params;
  console.log("get profile image for studentid : " + studentid)
  const query = 'SELECT profile_image FROM tstudent WHERE studentid = ?';
  const results = await queryPromise(query, [studentid]);

  //console.log("get profile image results : " + JSON.stringify(results));
  if (results.length > 0) {
    res.json({ success: true, image: results[0].profile_image });
  } else {
    res.json({ success: false, message: 'No profile image found' });
  }
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

// DELETE holiday
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
      refer = refertype + "-" + moment(referdate).format('YYYYMMDD') + "-" + pad(4, referno, "0");
      const query2 = 'UPDATE trunning SET running = ? WHERE refertype = ? and referdate = curdate()';
      await queryPromise(query2, [referno, refertype]);
    } else {

      const query3 = 'INSERT INTO trunning (refertype, referdate, running) VALUES (?, curdate(), 1)';
      await queryPromise(query3, [refertype]);
      let referno = 1;
      refer = refertype + "-" + moment().format('YYYYMMDD') + "-" + pad(4, referno, "0");
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

  console.log(verification.sid);
  return verification;
}

async function createVerificationCheck(Sid,opt) {
  const verificationCheck = await client.verify.v2
    .services(process.env.TWILIO_SERVICE_SID)
    .verificationChecks.create({
      code: opt,
      verificationSid: Sid,
    });

  console.log(verificationCheck.status);
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
    console.log(phoneNumber);
    //const otp = Math.floor(100000 + Math.random() * 900000); // สร้าง OTP 6 หลัก

    // เก็บ OTP ไว้ใน otpStorage
    //otpStorage[phoneNumber] = otp;

    //sendOTP(phoneNumber, otp)
    createVerification(phoneNumber)
        .then(message => res.status(200).send({ success: true, message }))
        .catch(error => res.status(500).send({ success: false, error }));
});

// Endpoint ยืนยัน OTP
app.post('/verify-otp', async (req, res) => {
    const { sid, otp } = req.body;

    createVerificationCheck(sid, otp)
        .then(message => {
          
          if(message.valid) {
            const token = jwt.sign({ sid: sid, otp: otp }, SECRET_KEY, { expiresIn: '10m' });
            res.status(200).send({ success: message.valid, token })
          }else{
            res.status(200).send({ success: message.valid, message })
          }
        })
        .catch(error => res.status(500).send({ success: false, error }));

    // ตรวจสอบว่า OTP ตรงกับที่เก็บไว้หรือไม่
    // if (otpStorage[phoneNumber] && otpStorage[phoneNumber] == otp) {
    //     delete otpStorage[phoneNumber]; // ลบ OTP หลังการยืนยัน
    //     res.status(200).send({ success: true, message: 'OTP verified successfully' });
    // } else {
    //     res.status(400).send({ success: false, message: 'Invalid OTP' });
    // }
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
const cron = require('node-cron');
const { google } = require('googleapis');
const drive = google.drive('v3');
const serviceAccountKey = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_KEY);
const auth = new google.auth.GoogleAuth({
  credentials: serviceAccountKey,
  scopes: ['https://www.googleapis.com/auth/drive.file'],
});

const folderId = '1G5VdaeIpN36EQgFvoEbIivXK9vCKtAdv'; // ไอดีของโฟลเดอร์ใน Google Drive

async function uploadOrUpdateLogFile() {
  console.log('[Process] Log file upload... '+logFileName);
  const authClient = await auth.getClient();
  google.options({ auth: authClient });

  // ตรวจสอบว่าไฟล์มีอยู่หรือไม่
  const res = await drive.files.list({
    q: `name='${logFileName}' and '${folderId}' in parents`,
    fields: 'files(id, name)',
    spaces: 'drive',
  });

  const files = res.data.files;
  const fileMetadata = {
    name: logFileName,
    parents: [folderId],
  };
  const media = {
    mimeType: 'text/plain',
    body: fs.createReadStream(logPath+logFileName),
  };

  if (files.length > 0) {
    // ถ้าไฟล์มีอยู่แล้ว ให้ทำการอัพเดทไฟล์
    const fileId = files[0].id;
    drive.files.update({
      fileId: fileId,
      media: media,
      fields: 'id',
    }, (err, file) => {
      if (err) {
        console.error(err);
      } else {
        console.log('[Success] Update Log file and upload '+logFileName);
      }
    });
  } else {
    // ถ้าไฟล์ไม่มี ให้ทำการสร้างไฟล์ใหม่
    drive.files.create({
      resource: fileMetadata,
      media: media,
      fields: 'id',
    }, (err, file) => {
      if (err) {
        console.error(err);
      } else {
        console.log('[Success] Create Log file and upload '+logFileName);
      }
    });
  }
}

uploadOrUpdateLogFile();
// ตั้งเวลาให้รันทุกๆ 30 นาที
cron.schedule('0,30 * * * *', () => {
  uploadOrUpdateLogFile();
});

const mysql2 = require('mysql2/promise');
const { log } = require('console');

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
  queueLimit: 0
});

async function queryPromise(query, params, showparams) {
  let connection;
  try {
    console.log("Query : " + query);
    // Clone params and mask values of keys containing "image"
    connection = await pool.getConnection();
    const [results] = await connection.query(query, params);
    
    if(showparams){
      const maskedParams = { ...params };
      for (const key in maskedParams) {
        if (key.includes('image') || key.includes('password')) {
          maskedParams[key] = '[HIDDEN]';
        }
      }
      console.log("Params : " + JSON.stringify(maskedParams));
      if (Array.isArray(results)) {
        // Clone results and mask values of keys containing "image"
        const maskedResults = results.map(result => {
          const maskedResult = { ...result };
          for (const key in maskedResult) {
            if (key.includes('image') || key.includes('password')) {
              maskedResult[key] = '[HIDDEN]';
            }
          }
          return maskedResult;
        });
        
        console.log("Results : " + JSON.stringify(maskedResults));
      } else {
        console.log("Results is not an array! ");
        console.log("Results : " + JSON.stringify(results));
      }
    }

    return results;
  } catch (error) {
    console.error('Error in queryPromise:', error);
    throw error;
  } finally {
    if (connection) connection.release();
  }
}

app.listen(port, '0.0.0.0', () => {
  clearActiveSessions();
  console.log(`Server is running on port ${port}`);
  console.log("Start time : " + format(new Date(), 'yyyy-MM-dd\'T\'HH-mm-ssXXX', { timeZone }));
});

// ทำให้ console.log ใช้ winston logger
console.log = (msg) => {
  logger.info(msg);
};

console.error = (msg, error) => {
  logger.info(msg + " : " + error);
};
