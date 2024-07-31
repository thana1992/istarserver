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
const logFileName = `server-${timestamp}.log`;
const logPath = './logs/';
// สร้าง winston logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
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
  logger.info(`Request: ${req.method} ${req.url} ${JSON.stringify(req.headers)}`);

  // Log response
  const originalSend = res.send;
  res.send = function (body) {
    logger.info(`Response: ${body}`);
    logger.info('### ================== end ================== ###')
    originalSend.apply(res, arguments);
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
    const token = req.headers.authorization; // Assuming the token is included in the Authorization header
    console.log('Received token:', token);
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    jwt.verify(token.replace('Bearer ', ''), SECRET_KEY, (err, decoded) => {
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
    console.error('Error in verifyToken:', error);
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
});

app.post('/login', async (req, res) => {
  console.log("login : " + JSON.stringify(req.body));
  const { username, password } = req.body;
  const query = 'SELECT *, b.familyid FROM tuser a left join tfamily b on a.username = b.username WHERE a.username = ?';
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
          const token = jwt.sign({ username: user.username, userpassword: user.userpassword }, SECRET_KEY, { expiresIn: '1h' });
          return res.json({ success: true, message: 'Login successful', token, userdata });
        } else {
          const token = jwt.sign({ username: user.username, userpassword: user.userpassword }, SECRET_KEY, { expiresIn: '10m' });
          return res.json({ success: true, message: 'Login successful', token, userdata });
        }

      } else {
        return res.json({ success: false, message: 'password is invalid' });
      }
    } else {
      return res.json({ success: false, message: 'username invalid' });
    }
  } catch (error) {
    console.error("Error logging in:", error);
    return res.status(500).send(error);
  }
});

app.post('/logout', verifyToken, (req, res) => {
  // Remove the user from activeSessions
  const userIndex = activeSessions.findIndex((user) => user.username === req.user.username);
  if (userIndex !== -1) {
    activeSessions.splice(userIndex, 1);
  }

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
    console.error("Error registering user:", error);
    return res.status(500).send(error);
  }
});

app.post("/getFamilyMember", verifyToken, async (req, res) => {
  const { familyid } = req.body;
  const query = 'select a.studentid, a.familyid, a.firstname, a.middlename, a.lastname, a.nickname, a.gender, a.dateofbirth, ' +
    ' a.courserefer, c.coursename, c.course_shortname, b.courseid, ' +
    ' b.coursetype, b.remaining, b.expiredate, ' +
    ' CONCAT(IFNULL(a.firstname, \'\'), \' \', IFNULL(a.middlename, \'\'), IF( a.middlename<>\'\', \' \', \'\'), IFNULL( a.lastname, \'\'), \' (\', a.nickname,\')\') fullname ' +
    ' from tstudent a ' +
    ' left join tcustomer_course b ' +
    ' on a.courserefer = b.courserefer ' +
    ' left join tcourseinfo c ' +
    ' on b.courseid = c.courseid ' +
    ' where a.familyid = ?';
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
    console.error("getFamilyMember error:", error);
    res.status(500).send(error);
  }
});

app.post("/getFamilyList", verifyToken, async (req, res) => {
  const { familyid } = req.body;
  const query = 'select a.studentid, a.familyid, a.firstname, a.middlename, a.lastname, a.nickname, a.gender, a.dateofbirth, ' +
    ' CONCAT(IFNULL(firstname, \'\'), \' \', IFNULL(a.middlename, \'\'), IF(a.middlename<>\'\', \' \', \'\'), IFNULL( a.lastname, \'\'), \' (\', a.nickname,\')\') fullname, \'0\' journal ' +
    ' from tstudent a ' +
    ' where a.familyid = ? ' +
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
    console.error("getStudent error:", error);
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
    console.error("addStudent error:", error);
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
        const query = 'INSERT INTO tstudent (studentid, familyid, firstname, middlename, lastname, nickname, gender, dateofbirth, school) ' +
          ' VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';
        await queryPromise(query, [studentid, item.familyid, item.firstname, item.middlename, item.lastname, item.nickname, item.gender, item.dateofbirth, item.school]);

        const deleteQuery = 'DELETE FROM jstudent WHERE studentid = ?';
        console.log("delete jstudent studentid : " + item.studentid);
        await queryPromise(deleteQuery, [item.studentid]);
      }
    }

    res.json({ success: true, message: 'Family member approve successfully' });
  } catch (error) {
    console.error('Error in approveNewStudent:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

app.post('/deleteNewStudent', verifyToken, async (req, res) => {
  const { studentid } = req.body;
  const deleteQuery = 'DELETE FROM jstudent WHERE studentid = ?';
  try {
    await queryPromise(deleteQuery, [studentid])
      .then((results) => {
        res.json({ success: true, message: 'New student deleted successfully' });
      })
      .catch((error) => {
        res.status(500).send(error);
      });
  } catch (error) {
    console.log("deleteNewStudent error : " + JSON.stringify(error));
    res.status(500).send(error);
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
              const query = 'INSERT INTO tstudent (studentid, firstname, middlename, lastname, nickname, gender, dateofbirth, familyid, courserefer, shortnote) ' +
                ' VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
              await queryPromise(query, [studentid, firstname, middlename, lastname, nickname, gender, dateofbirth, familyid, courserefer, shortnote])
                .then((results) => {
                  res.json({ success: true, message: 'Family member added successfully', studentid });
                })
                .catch((error) => {
                  res.status(500).send(error);
                });
            }
          }
        } else {
          const studentid = await generateRefer('S');
          const query = 'INSERT INTO tstudent (studentid, firstname, middlename, lastname, nickname, gender, dateofbirth, familyid, courserefer, shortnote) ' +
            ' VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
          await queryPromise(query, [studentid, firstname, middlename, lastname, nickname, gender, dateofbirth, familyid, courserefer, shortnote])
            .then((results) => {
              res.json({ success: true, message: 'Family member added successfully', studentid });
            })
            .catch((error) => {
              res.status(500).send(error);
            });
        }
      }
    } else {
      const studentid = await generateRefer('S');
      const query = 'INSERT INTO tstudent (studentid, firstname, middlename, lastname, nickname, gender, dateofbirth, familyid, shortnote) ' +
        ' VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';
      await queryPromise(query, [studentid, firstname, middlename, lastname, nickname, gender, dateofbirth, familyid, shortnote])
        .then((results) => {
          res.json({ success: true, message: 'Family member added successfully', studentid });
        })
        .catch((error) => {
          res.status(500).send(error);
        });
    }

  } catch (error) {
    console.error('Error in addStudentByAdmin:', error);
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
                'familyid = ?, courserefer = ?, shortnote = ? ' +
                ' WHERE studentid = ?';
              const results = await queryPromise(query, [firstname, middlename, lastname, nickname, gender, dateofbirth, familyid, courserefer, shortnote, studentid])
              return res.json({ success: true, message: 'Update Student successfully' });
            }
          }
        } else {
          const query = 'UPDATE tstudent set firstname = ?, middlename = ?, lastname = ?, nickname = ?, gender = ?, dateofbirth = ?,  ' +
            'familyid = ?, courserefer = ?, shortnote = ? ' +
            ' WHERE studentid = ?';
          const results = await queryPromise(query, [firstname, middlename, lastname, nickname, gender, dateofbirth, familyid, courserefer, shortnote, studentid])
          return res.json({ success: true, message: 'Update Student successfully' });
        }
      }
    } else {
      const query = 'UPDATE tstudent set firstname = ?, middlename = ?, lastname = ?, nickname = ?, gender = ?, dateofbirth = ?,  ' +
        'familyid = ?, shortnote = ?, courserefer = NULL' +
        ' WHERE studentid = ?';
      const results = await queryPromise(query, [firstname, middlename, lastname, nickname, gender, dateofbirth, familyid, shortnote, studentid])
      return res.json({ success: true, message: 'Update Student successfully' });
    }

  } catch (error) {
    console.log("updateStudentByAdmin error : " + JSON.stringify(error));
    res.status(500).send(error);
  }
});

app.post('/addBookingByAdmin', verifyToken, async (req, res) => {
  try {
    const { studentid, classid, classdate, classtime, courseid, classday } = req.body;
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

        const checkCourseQuery = 'select a.courserefer , b.coursetype, b.remaining, b.expiredate from tstudent a inner join tcustomer_course b on a.courserefer = b.courserefer where studentid = ?';
        const results2 = await queryPromise(checkCourseQuery, [studentid]);

        if (results2.length > 0) {
          const courserefer = results2[0].courserefer;
          const coursetype = results2[0].coursetype;
          const expiredate = results2[0].expiredate;
          const remaining = results2[0].remaining;
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
          console.log("classdate : " + cd);
          if (cd > expiredate) {
            return res.json({ success: false, message: 'Sorry, your course has expire in ' + moment(expiredate).format('DD/MM/YYYY') });
          }

          if (coursetype != 'Monthly') {
            if (remaining <= 0) {
              return res.json({ success: false, message: 'Sorry, you have no remaining classes' });
            }
          }

          console.log("======= addBookingByAdmin =======");
          const query = 'INSERT INTO treservation (studentid, classid, classdate, classtime, courseid, courserefer) VALUES (?, ?, ?, ?, ?, ?)';
          const insertResult = await queryPromise(query, [studentid, classid, classdate, classtime, courseid, courserefer]);
          console.log("insertResult : " + JSON.stringify(insertResult));
          if (insertResult.affectedRows > 0) {
            const updateRemainingQuery = 'UPDATE tcustomer_course SET remaining = remaining - 1 WHERE courserefer = ?';
            const updateResult = await queryPromise(updateRemainingQuery, [courserefer]);

            try {
              // Format date for notification
              const queryNotifyData = 'SELECT a.nickname, CONCAT(IFNULL(a.firstname, \'\'), \' \', IFNULL(a.middlename, \'\'), IF(a.middlename<>\'\', \' \', \'\'), IFNULL( a.lastname, \'\')) fullname, a.dateofbirth, ' +
                ' c.course_shortename ' +
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
                const coursename = results[0].course_shortename;
                var a = moment(classdate, "YYYYMMDD");
                const bookdate = new Date(a).toLocaleDateString('th-TH', {
                  year: 'numeric',
                  month: 'long',
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
              console.error('Error sending notification:', error);
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
                  month: 'long',
                  day: 'numeric',
              });
                
              console.log("======= updateBookingByAdmin =======");
              const query = 'UPDATE treservation SET studentid = ?, classid = ?, classdate = ?, classtime = ?, courseid = ? WHERE reservationid = ?';
              const insertResult = await queryPromise(query, [studentid, classid, classdate, classtime, courseid, reservationid]);

              if (insertResult.affectedRows > 0) {

                try {
                  // Format date for notification
                  const queryNotifyData = 'SELECT a.nickname, CONCAT(IFNULL(firstname, \'\'), \' \', IFNULL(a.middlename, \'\'), IF(a.middlename<>\'\', \' \', \'\'), IFNULL( a.lastname, \'\')) fullname, a.dateofbirth, ' +
                    ' c.course_shortename ' +
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
                    const coursename = results[0].course_shortename;
                    var a = moment(classdate, "YYYYMMDD");
                    const bookdate = new Date(a).toLocaleDateString('th-TH', {
                      year: 'numeric',
                      month: 'long',
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
                      message: coursename + '\n' + studentnickname + ' ' + studentname + '\nอายุ ' + calculateAge(results[0].dateofbirth) + 'ปี' + '\nจาก[' + oldClassdate + ' ' + oldClasstime + ']\nเป็น[' + bookdate + ' ' + classtime +']\nโดยแอดมิน ' + req.user.username,
                    };

                    sendNotificationUpdate(jsonData);
                  }
                } catch (error) {
                  console.error('Error sending notification:', error);
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
    const { reservationid, studentid } = req.body;
    const query = 'DELETE FROM treservation WHERE reservationid = ?';
    const results = await queryPromise(query, [reservationid]);
    if (results.affectedRows > 0) {
      const getCourseReferQuery = 'SELECT courserefer FROM tstudent WHERE studentid = ?';
      const results1 = await queryPromise(getCourseReferQuery, [studentid]);
      if (results1.length > 0) {
        const courserefer = results1[0].courserefer;
        const updateRemainingQuery = 'UPDATE tcustomer_course SET remaining = remaining + 1 WHERE courserefer = ?';
        const results2 = await queryPromise(updateRemainingQuery, [courserefer]);
        if (results2.affectedRows > 0) {
          res.json({ success: true, message: 'Reservation deleted successfully' });
        }
      }
    } else {
      res.json({ success: false, message: 'No Booking data' });
    }
  } catch (error) {
    console.error("API deleteReservationByAdmin error: " + JSON.stringify(error));
    res.json({ success: false, message: error.message });
  }
});

app.post('/deleteStudent', verifyToken, async (req, res) => {
  const { familyid, studentid, journal } = req.body;
  console.log("deleteStudent : " + JSON.stringify(req.body));
  let queryDeleteStudent = 'DELETE FROM tstudent WHERE familyid = ? AND studentid = ?';
  if (journal === '1') {
    queryDeleteStudent = 'DELETE FROM jstudent WHERE familyid = ? AND studentid = ?';
  }
  try {
    const results = await queryPromise(queryDeleteStudent, [familyid, studentid]);
    if (results.affectedRows > 0) {
      if (journal != '1') {
        const queryDeleteTreservation = 'DELETE FROM treservation WHERE studentid = ?';
        await queryPromise(queryDeleteTreservation, [studentid]);
      }
      return res.json({ success: true, message: 'Family member deleted successfully' });
    } else {
      return res.json({ success: false, message: 'No Family member data' });
    }
  } catch (error) {
    console.error('Error in deleteStudent:', error);
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
    console.error('Error in getMemberInfo:', error);
    res.status(500).send(error);
  }
});

app.post('/getMemberReservationDetail', verifyToken, async (req, res) => {
  const { studentid, courserefer } = req.body;
  const query = 'SELECT * FROM treservation WHERE studentid = ? and courserefer = ? order by classdate asc';
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
      console.error('Error in queryPromise:', error);
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

        const checkCourseQuery = 'select a.courserefer , b.coursetype, b.remaining, b.expiredate from tstudent a inner join tcustomer_course b on a.courserefer = b.courserefer where studentid = ?';
        const results2 = await queryPromise(checkCourseQuery, [studentid]);

        if (results2.length > 0) {
          const courserefer = results2[0].courserefer;
          const coursetype = results2[0].coursetype;
          const expiredate = results2[0].expiredate;
          const remaining = results2[0].remaining;
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

          if (coursetype != 'Monthly') {
            if (remaining <= 0) {
              return res.json({ success: false, message: 'Sorry, you have no remaining classes' });
            }
          }

          const query = 'INSERT INTO treservation (studentid, classid, classdate, classtime, courseid, courserefer) VALUES (?, ?, ?, ?, ?, ?)';
          const insertResult = await queryPromise(query, [studentid, classid, classdate, classtime, courseid, courserefer]);

          if (insertResult.affectedRows > 0) {
            const updateRemainingQuery = 'UPDATE tcustomer_course SET remaining = remaining - 1 WHERE courserefer = ?';
            const updateResult = await queryPromise(updateRemainingQuery, [courserefer]);

            try {
              // Format date for notification
              const queryNotifyData = 'SELECT a.nickname, CONCAT(IFNULL(a.firstname, \'\'), \' \', IFNULL(a.middlename, \'\'), IF(a.middlename<>\'\', \' \', \'\'), IFNULL( a.lastname, \'\')) fullname, a.dateofbirth,' +
                ' c.course_shortename ' +
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
                const coursename = results[0].course_shortename;
                var a = moment(classdate, "YYYYMMDD");
                const bookdate = new Date(a).toLocaleDateString('th-TH', {
                  year: 'numeric',
                  month: 'long',
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
              console.error('Error sending notification:', error);
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
    console.error('Error sending notification:', error);
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
    console.error('Error sending notification:', error);
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
    console.error('Error in deleteReservation:', error);
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
    console.error('Error in checkDuplicateReservation:', error);
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
    console.error('Error in getAllCourses:', error);
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
    console.error('Error in addCourse:', error);
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
    console.error('Error in updateCourse:', error);
    res.status(500).send(error);
  }
});

app.post('/deleteCourse', verifyToken, async (req, res) => {
  const { courseid } = req.body;
  const deletetcourseinfoQuery = 'DELETE FROM tcourseinfo WHERE courseid = ?';
  try {
    await queryPromise(deletetcourseinfoQuery, [courseid])
      .then((results) => {
        const deleteTclassinfoQuery = 'DELETE FROM tclassinfo WHERE courseid = ?';
        queryPromise(deleteTclassinfoQuery, [courseid]);
        res.json({ success: true, message: 'Course deleted successfully' });
      })
      .catch((error) => {
        res.status(500).send(error);
      });
  } catch (error) {
    console.error('Error in deleteCourse:', error);
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
    console.error('Error in getAllClasses:', error);
    return res.status(500).send(error);
  }
});

app.post('/addClass', verifyToken, async (req, res) => {
  const { courseid, classday, classtime, maxperson } = req.body;
  const query = 'INSERT INTO tclassinfo (courseid, classday, classtime, maxperson) VALUES (?, ?, ?, ?)';
  try {
    await queryPromise(query, [courseid, classday, classtime, maxperson])
      .then((results) => {
        return res.json({ success: true, message: 'Class added successfully' });
      })
      .catch((error) => {
        res.status(500).send(error);
      });
  } catch (error) {
    console.error('Error in addClass:', error);
    res.status(500).send(error);
  }
});

app.post('/updateClass', verifyToken, async (req, res) => {
  const { classid, courseid, classday, classtime, maxperson } = req.body;
  const query = 'UPDATE tclassinfo SET courseid = ?, classday = ?, classtime = ?, maxperson = ? WHERE classid = ?';
  try {
    await queryPromise(query, [courseid, classday, classtime, maxperson, classid])
      .then((results) => {
        res.json({ success: true, message: 'Class updated successfully' });
      })
      .catch((error) => {
        res.status(500).send(error);
      });
  } catch (error) {
    console.error('Error in updateClass:', error);
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
    console.error('Error in deleteClass:', error);
    res.status(500).send(error);
  }
});

app.post('/getClassTime', verifyToken, async (req, res) => {
  const { classdate, classday, courseid } = req.body;
  const query = 'SELECT a.* , case when count(b.reservationid) > 0 then a.maxperson - count(b.reservationid) else a.maxperson end as available ' +
    'FROM tclassinfo a ' +
    'left join treservation b ' +
    'on a.classid = b.classid ' +
    'and b.classdate = ? ' +
    'WHERE a.classday = ? ' +
    'and a.courseid = ? ' +
    'group by a.classid , a.classday , a.classtime , a.maxperson , a.courseid ';
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
    console.error('Error in getClassTime:', error);
    res.status(500).send(error);
  }
});

app.get("/getNewStudentList", verifyToken, async (req, res) => {
  const query = "select a.*, CONCAT(IFNULL( a.firstname, ''), ' ', IFNULL( a.middlename, ''), IF( a.middlename<>'', ' ',''), IFNULL( a.lastname, ''), ' (', a.nickname,')') fullname, c.username from jstudent a left join tfamily b on a.familyid = b.familyid left join tuser c on b.username = c.username";
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
        console.error('Error in queryPromise:', error);
        res.json({ success: false, message: error.message });
      })
  } catch (error) {
    res.status(500).send(error);
    console.error('Error in getNewStudentList:', error);
    
  }
});

app.get("/courseLookup", verifyToken, async (req, res) => {
  const query = 'SELECT * FROM tcourseinfo';
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
      console.error('Error in queryPromise:', error);
    })
});

app.get("/customerCourseLookup", verifyToken, async (req, res) => {
  const query = 'SELECT * FROM tcustomer_course';
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
      console.error('Error in queryPromise:', error);
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
    console.error('Error in getCustomerCourseInfo:', error);
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
      console.error('Error in queryPromise:', error);
    })
  // if(results) {
  //   if(results.length > 0){
  //     res.json({ success: true, message: 'Get Family Lookup successful', results });
  //   } else {
  //     res.json({ success: true, message: 'No Family Lookup' });
  //   }
  // } else {
  //   res.json({ success: true, message: 'No Family Lookup' });
  // }
});

app.post("/studentLookup", verifyToken, async (req, res) => {
  const { familyid } = req.body;
  const query = "SELECT studentid, CONCAT(IFNULL(nickname, ''), ' ', IFNULL(firstname, ''), ' ', IFNULL(middlename, ''), IF( middlename<>'', ' ', ''), IFNULL(lastname, '')) as name FROM tstudent"
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
      console.error('Error in queryPromise:', error);
    })
});

app.get("/getStudentList", verifyToken, async (req, res) => {
  try {
    const query = 'SELECT a.studentid, a.familyid, a.firstname, a.middlename, a.lastname, a.nickname, a.gender, a.dateofbirth, a.courserefer, a.shortnote, ' +
      '   CONCAT(IFNULL(a.firstname,\'\'), \' \', IFNULL(a.middlename,\'\'), IF(a.middlename<>\'\', \' \', \'\'), IFNULL(a.lastname,\'\'), \' (\', a.nickname,\')\') fullname, ' +
      '   CASE WHEN b.coursetype = \'Monthly\' THEN \'รายเดือน\' ' +
      '     WHEN b.coursetype IS NULL THEN \'ไม่มีคอร์ส\' ' +
      '     ELSE CONCAT(b.remaining, \' ครั้ง\') ' +
      '   END AS remaining, ' +
      ' b.expiredate, t.coursename, d.mobileno, a.shortnote ' +
      ' FROM tstudent a ' +
      ' LEFT JOIN tcustomer_course b ' +
      ' ON a.courserefer = b.courserefer ' +
      ' LEFT JOIN tcourseinfo t ' +
      ' ON b.courseid = t.courseid ' +
      ' LEFT JOIN tfamily c ' +
      ' ON a.familyid = c.familyid ' +
      ' LEFT JOIN tuser d ' +
      ' ON c.username = d.username';
    const results = await queryPromise(query);

    // มันมีรูป base64 ที่เก็บในฐานข้อมูล ทำให้ข้อมูลมีขนาดใหญ่ ทำให้การปริ้น log มันเยอะมาก
    //console.log("API getStudentlist result :" + JSON.stringify(results));

    if (results.length > 0) {
      res.json({ success: true, message: 'Get Student list successful', results });
    } else {
      res.json({ success: true, message: 'No Student list', results });
    }
  } catch (error) {
    console.error("API getStudentlist error :" + JSON.stringify(error));
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

    console.log("API getReservationList result: " + JSON.stringify(results));

    // Function to calculate age in years and months
    const calculateAge = (dateOfBirth) => {
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
    console.error("API getReservationList error: " + JSON.stringify(error));
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
      res.json({ success: false, message: 'No Reservation data' });
    }
  }
  catch (error) {
    console.error("API checkinByAdmin error: " + JSON.stringify(error));
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
    const query1 = 'select count(*) as total from tstudent';
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

    console.error("API refreshCardDashboard error: " + JSON.stringify(error));
    res.status(500).send(error);
    throw error;
  }
});

app.post('/getBookingList', verifyToken, async (req, res) => {
  console.log("getBookingList [request] : " + JSON.stringify(req.body));
  try {
    const { classday, classdate } = req.body;
    const query = 'SELECT DISTINCT a.classtime, a.courseid, CONCAT(a.classtime,\' (\',b.course_shortname,\')\') as class_label, a.classid FROM tclassinfo a join tcourseinfo b on  a.courseid = b.courseid where a.classday = ? order by a.classtime'
    const results = await queryPromise(query, [classday]);
    console.log("results : " + JSON.stringify(results));
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
        console.log("results2 : " + JSON.stringify(results2));

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
          console.log("bookinglist : " + JSON.stringify(bookinglist));
        } else {
          bookinglist[element.class_label] = [];
        }
      }
      console.log("getBookingList [response] : " + JSON.stringify(bookinglist));
      res.json({ success: true, message: 'Get Booking list successful', bookinglist });
    } else {
      res.json({ success: true, message: 'No Booking list' });
    }
  } catch (error) {
    console.error('Error in getBookingList:', JSON.stringify(error));
    res.status(500).send(error);
  }
});

app.post('/getCustomerCourseList', verifyToken, async (req, res) => {
  try {
    const { username } = req.body;
    const query = 'SELECT a.*, b.coursename FROM tcustomer_course a left join tcourseinfo b on a.courseid = b.courseid';
    const results = await queryPromise(query, null);
    if (results.length > 0) {
      res.json({ success: true, message: 'Get Customer Course List successful', results });
    } else {
      res.json({ success: true, message: 'No Customer Course List' });
    }
  } catch (error) {
    console.error('Error in getCustomerCourseList:', JSON.stringify(error));
    res.status(500).send(error);
  }
});

app.get('/getCustomerCourseLookup', verifyToken, async (req, res) => {
  try {
    const query = 'SELECT a.* FROM tcustomer_course a';
    const results = await queryPromise(query, null);
    if (results.length > 0) {
      res.json({ success: true, message: 'Get Customer Course List successful', results });
    } else {
      res.json({ success: true, message: 'No Customer Course List' });
    }
  } catch (error) {
    console.error('Error in getCustomerCourseLookup:', JSON.stringify(error));
    res.status(500).send(error);
  }
});

app.post('/addCustomerCourse', verifyToken, async (req, res) => {
  try {

    const { coursetype, course, remaining, startdate, expiredate } = req.body;
    const courserefer = await generateRefer(course.refercode);
    if (startdate == null || startdate == undefined || startdate == '') {
      const query = 'INSERT INTO tcustomer_course (courserefer, courseid, coursetype, remaining) VALUES (?, ?, ?, ?)';
      const results = await queryPromise(query, [courserefer, course.courseid, coursetype, remaining]);
      if (results.affectedRows > 0) {
        res.json({ success: true, message: 'Successfully Course No :' + courserefer });
      } else {
        res.json({ success: false, message: 'Error adding Customer Course' });
      }
    } else {
      if (expiredate == null || expiredate == undefined || expiredate == '') {
        res.json({ success: false, message: 'Please enter expire date' });
      } else {
        const query = 'INSERT INTO tcustomer_course (courserefer, courseid, coursetype, remaining, startdate, expiredate) VALUES (?, ?, ?, ?, ?, ?)';
        const results = await queryPromise(query, [courserefer, course.courseid, coursetype, remaining, startdate, expiredate]);
        if (results.affectedRows > 0) {
          res.json({ success: true, message: 'Successfully Course No :' + courserefer });
        } else {
          res.json({ success: false, message: 'Error adding Customer Course' });
        }
      }
    }

  } catch (error) {
    console.error('Error in addCustomerCourse:', JSON.stringify(error));
    res.status(500).send(error);
  }
});

app.post('/updateCustomerCourse', verifyToken, async (req, res) => {
  try {
    const { courserefer, courseid, coursetype, remaining, startdate, expiredate } = req.body;
    const query = 'UPDATE tcustomer_course SET courseid = ?, coursetype = ?, remaining = ?, startdate = ?, expiredate = ? WHERE courserefer = ?';
    const results = await queryPromise(query, [courseid, coursetype, remaining, startdate, expiredate, courserefer]);
    if (results.affectedRows > 0) {
      res.json({ success: true, message: 'Customer Course updated successfully' });
    } else {
      res.json({ success: false, message: 'Error updating Customer Course' });
    }
  } catch (error) {
    console.error('Error in updateCustomerCourse:', JSON.stringify(error));
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
    console.error('Error in checkbeforeDeleteCustomerCourse:', JSON.stringify(error));
    res.status(500).send(error);
  }
});

app.post('/deleteCustomerCourse', verifyToken, async (req, res) => {
  try {
    const { courserefer } = req.body;
    const query = 'DELETE FROM tcustomer_course WHERE courserefer = ?';
    const results = await queryPromise(query, [courserefer]);
    if (results.affectedRows > 0) {
      await queryPromise('UPDATE tstudent SET courserefer = NULL WHERE courserefer = ?', [courserefer]);
      res.json({ success: true, message: 'Customer Course deleted successfully' });
    }
  } catch (error) {
    console.error('Error in deleteCustomerCourse:', JSON.stringify(error));
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
                    FROM treservation a
                    LEFT JOIN tstudent b
                    ON a.studentid = b.studentid 
                    WHERE  a.courserefer = ?  
                    order by a.classdate asc`;
    const courseDetail = await queryPromise(query2, [courserefer]);
    if (results.length > 0) {
      res.json({ success: true, message: 'Get Student Use Course successful', results, courseDetail });
    } else {
      res.json({ success: true, message: 'No Student Use Course' });
    }
  } catch (error) {
    console.error('Error in getStudentUseCourse:', JSON.stringify(error));
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
    const query = 'UPDATE tstudent SET profile_image = ? WHERE studentid = ?';
    const results = await queryPromise(query, [image, studentid]);
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
    console.error('Error in generateRefer:', error);
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
    console.error('Error in checkmobileno:', error);
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
    console.error('Error in chenge-password:', error);
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
        console.log('File Upload... '+logFileName);
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
        console.log('File Upload... '+logFileName);
      }
    });
  }
}

uploadOrUpdateLogFile();
// ตั้งเวลาให้รันทุกๆ 30 นาที
cron.schedule('*/30 * * * *', () => {
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
    const maskedParams = { ...params };
    for (const key in maskedParams) {
      if (key.includes('image')) {
        maskedParams[key] = '[HIDDEN]';
      }
    }
    console.log("Params : " + JSON.stringify(maskedParams));

    connection = await pool.getConnection();
    const [results] = await connection.query(query, params);
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
  console.log(" Start time : " + timestamp)
});

// ทำให้ console.log ใช้ winston logger
console.log = (msg) => {
  logger.info(msg);
};

console.error = (msg, error) => {
  logger.info(msg);
  //throw error;
};
