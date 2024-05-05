require('dotenv').config()

const express = require('express');
const axios = require('axios');
const qs = require('qs');
const moment = require('moment');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const app = express();
const port = 3000;
const jwt = require('jsonwebtoken');
const SECRET_KEY = "your-secret-key";
const db = mysql.createConnection(process.env.DATABASE_URL)
const activeSessions = [];
const url = 'https://notify-api.line.me/api/notify'
const accessCode = 'tggzxbTM0Ixias1nhlqTjwcg65ENMrJAOHL5h9LxxkS'
const accessCode2 = '3bviOJYg6u2T5vQYEtaKUdsZ3L6apeoVtZJSrzzTT30'
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

db.connect(err => {
  if (err) {
    console.error('Error connecting to the database:', err);
  } else {
    console.log('Connected to MySQL');
  }
});

app.use(bodyParser.json());
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  // other headers...
  next();
});
app.use(cors());
app.get('/', function(req, res, next) {
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
    console.log(item.username + " : " + iat.toLocaleString() + " : " + exp.toLocaleString())
  });
  res.json({ activeSessions });
});

app.post('/login', async (req, res) => {
  console.log("login : " + JSON.stringify(req.body));
  const { username, password } = req.body;
  const query = 'SELECT *, b.familyid FROM tuser a left join tfamily b on a.username = b.username WHERE a.username = ?';
  try {
    await queryPromise(query, [username])
    .then((results) => {
      if (results.length > 0) {
        const storedPassword = results[0].userpassword;
        //console.log("storedPassword : " + storedPassword);
        if (storedPassword === password) {
          //res.status(200).json({ message: "Login successful" });
          const user = results[0];
          const userdata = {
              username: results[0].username,
              fullname: results[0].fullname,
              address: results[0].address,
              email: results[0].email,
              mobileno: results[0].mobileno,
              usertype: results[0].usertype,
              familyid: results[0].familyid,
          }
          if (userdata.usertype == '1') {
            const token = jwt.sign({ userId: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
            res.json({ success: true, message: 'Login successful', token, userdata });
          }else{ 
            const token = jwt.sign({ userId: user.id, username: user.username }, SECRET_KEY, { expiresIn: '10m' });
            res.json({ success: true, message: 'Login successful', token, userdata });
          }

          const logquery = 'INSERT INTO llogin (username) VALUES (?)';
          db.query(logquery, [username]);
          
        } else {
          res.json({ success: false, message: 'password is invalid' });
        }
      }else{
        res.json({ success: false, message: 'username invalid' });
      }
    })
    .catch((error) => {
      res.status(500).send(error);
    });
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).send(error);
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
  const { username, password, fullname, address, email, mobileno, lineid } = req.body;
  
  try {
      // Check if the username is already taken
      const checkUsernameQuery = 'SELECT * FROM tuser WHERE username = ?';
      const existingUser = await queryPromise(checkUsernameQuery, [username]);

      if (existingUser.length > 0) {
          return res.json({ success: false, message: 'Username is already taken' });
      } else {
          // Insert new user
          const insertUserQuery = 'INSERT INTO tuser (username, userpassword, fullname, address, email, mobileno, lineid) VALUES (?, ?, ?, ?, ?, ?, ?)';
          await queryPromise(insertUserQuery, [username, password, fullname, address, email, mobileno, lineid]);

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
  const query = 'select a.childid, a.familyid, a.firstname, a.lastname, a.nickname, a.gender, a.dateofbirth, a.photo, a.remaining, a.courseid, b.coursename, b.course_shortname' +
                  ' from tfamilymember a ' +
                  ' left join tcoursetype b ' +
                  ' on a.courseid = b.courseid ' +
                  ' where a.familyid = ?';
  try {
    const results = await queryPromise(query, [familyid])
    .then((results) => {
      if(results.length > 0){
        res.json({ success: true, message: 'Get Family Member successful', results });
      } else {
        res.json({ success: true, message: 'No Family Member', results });
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

app.post('/addFamilyMember', verifyToken, async (req, res) => {
  try {
      const { familyid, firstname, lastname, nickname, gender, dateofbirth } = req.body;
      const query = 'INSERT INTO jfamilymember (familyid, firstname, lastname, nickname, gender, dateofbirth, photo) ' +
                    ' VALUES (?, ?, ?, ?, ?, ?, ?)';
      const defaultPhotoUrl = 'https://cdn3.iconfinder.com/data/icons/family-member-flat-happy-family-day/512/Son-512.png';

      await queryPromise(query, [familyid, firstname, lastname, nickname, gender, dateofbirth, defaultPhotoUrl]);
      
      res.json({ success: true, message: 'Family member was successfully added. Please wait for approval from the admin.' });
  } catch (error) {
      console.error("addFamilyMember error:", error);
      res.status(500).send(error);
  }
});

app.post('/approveNewStudent', verifyToken, async (req, res) => {
  try {
    const { apprObj } = req.body;
    console.log("apprObj : " + JSON.stringify(apprObj));

    for (const item of apprObj) {
      const getQuery = 'SELECT * FROM jfamilymember WHERE childid = ?';
      const results = await queryPromise(getQuery, [item.childid]);

      if (results.length > 0) {
        const query = 'INSERT INTO tfamilymember (familyid, firstname, lastname, nickname, gender, dateofbirth, courseid, remaining, photo) ' +
                      ' VALUES (?, ?, ?, ?, ?, ?, ?, ?, \'https://cdn3.iconfinder.com/data/icons/family-member-flat-happy-family-day/512/Son-512.png\')';
        await queryPromise(query, [item.familyid, item.firstname, item.lastname, item.nickname, item.gender, item.dateofbirth, item.courseid, item.remaining]);

        const deleteQuery = 'DELETE FROM jfamilymember WHERE childid = ?';
        console.log("delete jfamilymember childid : " + item.childid);
        await queryPromise(deleteQuery, [item.childid]);
      }
    }

    res.json({ success: true, message: 'Family member approve successfully' });
  } catch (error) {
    console.error('Error in approveNewStudent:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

app.post('/deleteNewStudent', verifyToken, async (req, res) => {
  const { childid } = req.body;
  const deleteQuery = 'DELETE FROM jfamilymember WHERE childid = ?';
  try {
    await queryPromise(deleteQuery, [childid])
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
  const { familyid, firstname, lastname, nickname, gender, dateofbirth, courseid, remaining } = req.body;
  const query = 'INSERT INTO tfamilymember (familyid, firstname, lastname, nickname, gender, dateofbirth, courseid, remaining, photo) ' +
                ' VALUES (?, ?, ?, ?, ?, ?, ?, ?, \'https://cdn3.iconfinder.com/data/icons/family-member-flat-happy-family-day/512/Son-512.png\')';
  try {
    await queryPromise(query, [familyid, firstname, lastname, nickname, gender, dateofbirth, courseid, remaining])
    .then((results) => {
      res.json({ success: true, message: 'Family member added successfully' });
    })
    .catch((error) => {
      res.status(500).send(error);
    });
  } catch (error) {
    console.error('Error in addStudentByAdmin:', error);
    res.status(500).send(error);
  }
});

app.post('/updateStudentByAdmin', verifyToken, async (req, res) => {
  try {
    const { familyid, childid, firstname, lastname, nickname, gender, dateofbirth, courseid, remaining } = req.body;
    const query = 'UPDATE tfamilymember set firstname = ?, lastname = ?, nickname = ?, gender = ?, dateofbirth = ?,  ' +
                  ' courseid = ?, remaining = ?, familyid = ?' +
                  ' WHERE childid = ?';
    const results = await queryPromise(query, [ firstname, lastname, nickname, gender, dateofbirth, courseid, remaining, familyid, childid])
    res.json({ success: true, message: 'Update Student successfully' });

  } catch (error) {
    console.log("updateStudentByAdmin error : " + JSON.stringify(error));
    res.status(500).send(error);
  }
});

app.post('/addBookingByAdmin', verifyToken, async (req, res) => {
  try {
    const { childid, classid, classdate, classtime, courseid, classday } = req.body;
    const checkDuplicateReservationQuery = 'select * from treservation where childid = ? and classdate = ? ';
    const resCheckDuplicateReservation = await queryPromise(checkDuplicateReservationQuery, [childid, classdate])
    if (resCheckDuplicateReservation.length > 0) {
      return res.json({ success: false, message: 'You have already booking on this day' });
    }else{
      let checkClassFullQuery = 'select maxperson from tclass where classid = ? and classday = ? and classtime = ?';
      const resCheck = await queryPromise(checkClassFullQuery, [classid, classday, classtime])
      if (resCheck.length > 0) {
        const maxperson = resCheck[0].maxperson;
        checkClassFullQuery = 'select count(*) as count from treservation where classid = ? and classdate = ? and classtime = ?';
        const resCheck2 = await queryPromise(checkClassFullQuery, [classid, classdate, classtime])
        if (resCheck2.length > 0) {
          const count = resCheck2[0].count;
          if (count >= maxperson) {
            return res.json({ success: false, message: 'Sorry, This class is full' });
          }else{
            const checkRemainingQuery = 'select remaining from tfamilymember where childid = ?';
            const resCheck3 = await queryPromise(checkRemainingQuery, [childid])
            if (resCheck3.length > 0) {
              const remaining = resCheck3[0].remaining;
              if (remaining <= 0) {
                return res.json({ success: false, message: 'ขอโทษค่ะ จำนวนคลาสคงเหลือของท่านหมดแล้ว' });
              }else{
                console.log("======= addBookingByAdmin =======")
                const query = 'INSERT INTO treservation (childid, classid, classdate, classtime, courseid) VALUES (?, ?, ?, ?, ?)';
                const results = await queryPromise(query, [childid, classid, classdate, classtime, courseid])
                if(results.affectedRows > 0) {
                  const updateRemainingQuery = 'UPDATE tfamilymember SET remaining = remaining - 1 WHERE childid = ?';
                  await queryPromise(updateRemainingQuery, [childid])
                }
                return res.json({ success: true, message: 'Add Booking successfully' });
              }
            }else{
              return res.json({ success: false, message: 'ไม่พบข้อมูลของท่าน' });
            }
          }
        }
      }else{  
        return res.json({ success: false, message: 'ไม่พบคลาสที่ท่านเลือก' });
      }
    }
  } catch (error) {
    console.log("addBookingByAdmin error : " + JSON.stringify(error));
    res.status(500).send(error);
  }
});

app.post('/updateBookingByAdmin', verifyToken, async (req, res) => {
  // todo : check duplicate booking on same day
  try {
    const { childid, classid, classdate, classtime, courseid, classday, reservationid } = req.body;
    const checkDuplicateReservationQuery = 'select * from treservation where childid = ? and classdate = ? and reservationid <> ?';
    const resCheckDuplicateReservation = await queryPromise(checkDuplicateReservationQuery, [childid, classdate, reservationid])
    if (resCheckDuplicateReservation.length > 0) {
      return res.json({ success: false, message: 'You have already booking on this day' });
    }else{
      const checkClassFullQuery = 'select maxperson from tclass where classid = ? and classday = ? and classtime = ? and courseid = ?';
      const resCheck = await queryPromise(checkClassFullQuery, [classid, classday, classtime, courseid])
      console.log(resCheck.length+"resCheck : " + JSON.stringify(resCheck));
      if (resCheck.length > 0) {
        const maxperson = resCheck[0].maxperson;
        const checkClassFullQuery2 = 'select count(*) as count from treservation where classid = ? and classdate = ? and classtime = ? and courseid = ?';
        const resCheck2 = await queryPromise(checkClassFullQuery2, [classid, classdate, classtime, courseid])
        console.log("resCheck2 : " + JSON.stringify(resCheck2));
        if(resCheck2.length > 0) {
          const count = resCheck2[0].count;
          if (count >= maxperson) {
            return res.json({ success: false, message: 'Sorry, This class is full' });
          }else{
            const query = 'UPDATE treservation set classid = ?, classdate = ?, classtime = ?, courseid = ?  ' +
                          ' WHERE reservationid = ?' +
                          ' and childid = ?';
            const results = await queryPromise(query, [ classid, classdate, classtime, courseid, reservationid, childid])
            return res.json({ success: true, message: 'Update Booking successfully' });
          }
        }
      }else{
        return res.json({ success: false, message: 'ไม่พบคลาสที่ท่านเลือก' });
      }
    }
  } catch (error) {
    console.log("updateBookingByAdmin error : " + JSON.stringify(error));
    res.status(500).send(error);
  }
});

app.post("/cancelBookingByAdmin", verifyToken, async (req, res) => {
  try {
    const { reservationid, childid } = req.body;
    const query = 'DELETE FROM treservation WHERE reservationid = ?';
    const results = await queryPromise(query, [reservationid, childid]);
    if (results.affectedRows > 0) {
      const updateRemainingQuery = 'UPDATE tfamilymember SET remaining = remaining + 1 WHERE childid = ?';
      const results2 = await queryPromise(updateRemainingQuery, [childid]);
      if (results2.affectedRows > 0) {
        res.json({ success: true, message: 'Reservation deleted successfully' });
      }
    } else {
      res.json({ success: false, message: 'No Booking data' });
    }
  } catch (error) {
    console.error("API deleteReservationByAdmin error: " + JSON.stringify(error));
    res.json({ success: false, message: error.message });
  }
});

app.post('/deleteFamilyMember', verifyToken, async (req, res) => {
  const { familyid, childid } = req.body;
  const queryDeleteTfamilymember = 'DELETE FROM tfamilymember WHERE familyid = ? AND childid = ?';
  db.query(queryDeleteTfamilymember, [familyid, childid], (err) => {
    if (err) {
      res.status(500).send(err);
    } else {
      const queryDeleteTfamilymember = 'DELETE FROM treservation WHERE childid = ?';
      db.query(queryDeleteTfamilymember, [childid]);
      res.json({ success: true, message: 'Family member deleted successfully' });
    }
  });
});

app.post('/getMemberInfo', verifyToken, async (req, res) => {
  const { childid } = req.body;
  const query = 'SELECT * FROM tfamilymember WHERE childid = ?';
  try {
    const results = await queryPromise(query, [childid]);
    if (results.length > 0) {
      res.json({ success: true, message: 'Get Member Info successful', results });
    } else {
      res.json({ success: false, message: 'No Member Info' });
    }
  } catch (error) {
    console.error('Error in getMemberInfo:', error);
    res.status(500).send(error, message);
  }
});

app.post('/getMemberReservationDetail', verifyToken, async (req, res) => {
  const { childid } = req.body;
  const query = 'SELECT * FROM treservation WHERE childid = ? order by classdate asc';
  await queryPromise(query, [childid])
  .then((results) => {
    if(results.length > 0) {
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
    console.log("addReservation : " + JSON.stringify(req.body));
    const { courseid, classid, classday, classdate, classtime, childid, studentname, studentnickname, coursename } = req.body;

    // Query to check max person for the class
    const checkClassFullQuery = 'SELECT maxperson FROM tclass WHERE classid = ? AND classday = ? AND classtime = ?';
    const maxPersonResults = await queryPromise(checkClassFullQuery, [classid, classday, classtime]);
    console.log("checkClassFullQuery results 1 : " + JSON.stringify(maxPersonResults));

    if (maxPersonResults.length > 0) {
      const maxperson = maxPersonResults[0].maxperson;
      
      // Query to count reservations for the class
      const countReservationsQuery = 'SELECT COUNT(*) AS count FROM treservation WHERE classid = ? AND classdate = ? AND classtime = ?';
      const countResults = await queryPromise(countReservationsQuery, [classid, classdate, classtime]);
      console.log("checkClassFullQuery results 2 : " + JSON.stringify(countResults));

      const count = countResults[0].count;
      
      if (count >= maxperson) {
        return res.json({ success: false, message: 'Sorry, This class is full' });
      }

      // Query to check remaining class slots for the user
      const checkRemainingQuery = 'SELECT remaining FROM tfamilymember WHERE childid = ?';
      const remainingResults = await queryPromise(checkRemainingQuery, [childid]);
      console.log("checkRemainingQuery results : " + JSON.stringify(remainingResults));

      const remaining = remainingResults[0].remaining;

      if (remaining <= 0) {
        return res.json({ success: false, message: 'ขอโทษค่ะ จำนวนคลาสคงเหลือของท่านหมดแล้ว' });
      }

      // Insert reservation into database
      const insertReservationQuery = 'INSERT INTO treservation (courseid, classid, classdate, classtime, childid) VALUES (?, ?, ?, ?, ?)';
      await queryPromise(insertReservationQuery, [courseid, classid, classdate, classtime, childid]);

      // Update remaining class slots for the user
      const updateRemainingQuery = 'UPDATE tfamilymember SET remaining = remaining - 1 WHERE childid = ?';
      await queryPromise(updateRemainingQuery, [childid]);

      // Format date for notification
      var a = moment(classdate, "YYYYMMDD");
      const bookdate = new Date(a).toLocaleDateString('th-TH', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
      });

      // Prepare notification data
      const jsonData = {
        message: coursename + '\n' + studentnickname + ' ' + studentname + '\nวันที่ ' + bookdate + ' ' + classtime,
      };

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
      console.log('Notification Success');
      return res.json({ success: true, message: 'Reservation added successfully' });
    } else {
      return res.json({ success: false, message: 'ไม่พบคลาสที่ท่านเลือก' });
    }
  } catch (error) {
    console.error("Error occurred: ", error);
    return res.status(500).send(error.message);
  }
});

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
    res.status(500).send(error, message);
  }
});

app.post('/checkDuplicateReservation', verifyToken, async (req, res) => {
  const { childid, classdate } = req.body;
  const query = 'SELECT * FROM treservation WHERE childid = ? and classdate = ?';
  try {
    const results = await queryPromise(query, [childid, classdate]);
    if (results.length > 0) {
      return res.json({ success: false, message: 'You have already reservation on this day' });
    } else {
      return res.json({ success: true, message: 'No Reservation on this day' });
    }
  } catch (error) {
    console.error('Error in checkDuplicateReservation:', error);
    return res.status(500).send(error, message);
  }
});

app.get('/getAllCourses', verifyToken, async (req, res) => {
  const query = 'SELECT * FROM tcoursetype';
  try {
    await queryPromise(query, null)
    .then((results) => {
      if(results.length > 0){
        return res.json({ success: true, message: 'Get All Course successful', results });
      } else {
        return res.json({ success: false, message: 'No Course' });
      }
    })
    .catch((error) => {
      return res.status(500).send(error, message);
    });
  } catch (error) {
    console.error('Error in getAllCourses:', error);
    return res.status(500).send(error, message);
  }
});

app.post('/addCourse', verifyToken, async (req, res) => {
  const { coursename, course_shortname } = req.body;
  const query = 'INSERT INTO tcoursetype (coursename, course_shortname) VALUES (?, ?)';
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
    res.status(500).send(error, message);
  }
});

app.post('/updateCourse', verifyToken, async (req, res) => {
  const { coursename, course_shortname, courseid } = req.body;
  const query = 'UPDATE tcoursetype SET coursename = ?, course_shortname = ? WHERE courseid = ?';
  try {
    await queryPromise(query, [coursename, course_shortname, courseid])
    .then((results) => {
      res.json({ success: true, message: 'Course updated successfully' });
    })
    .catch((error) => {
      res.status(500).send(error, message);
    });
  } catch (error) {
    console.error('Error in updateCourse:', error);
    res.status(500).send(error, message);
  }
});

app.post('/deleteCourse', verifyToken, async (req, res) => {
  const { courseid } = req.body;
  const deletetcoursetypeQuery = 'DELETE FROM tcoursetype WHERE courseid = ?';
  try {
    await queryPromise(deletetcoursetypeQuery, [courseid])
    .then((results) => {
      const deleteTclassQuery = 'DELETE FROM tclass WHERE courseid = ?';
      db.query(deleteTclassQuery, [courseid]);
      res.json({ success: true, message: 'Course deleted successfully' });
    })
    .catch((error) => {
      res.status(500).send(error);
    });
  } catch (error) {
    console.error('Error in deleteCourse:', error);
    res.status(500).send(error, message);
  }
});

app.get('/getAllClasses', verifyToken, async (req, res) => {
  const { courseid } = req.body;
  const query = 'SELECT b.courseid, b.coursename, a.* FROM tclass a inner join tcoursetype b on a.courseid = b.courseid order by b.coursename , a.classday ';
  try {
    await queryPromise(query, null)
    .then((results) => {
      if(results.length > 0){
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
  const query = 'INSERT INTO tclass (courseid, classday, classtime, maxperson) VALUES (?, ?, ?, ?)';
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
  const query = 'UPDATE tclass SET courseid = ?, classday = ?, classtime = ?, maxperson = ? WHERE classid = ?';
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
    res.status(500).send(error, message);
  }
});

app.post('/deleteClass', verifyToken, async(req, res) => {
  const { classid } = req.body;
  const query = 'DELETE FROM tclass WHERE classid = ?';
  try {
    await queryPromise(query, [classid])
    .then((results) => {
      const query2 = 'DELETE FROM treservation WHERE classid = ?';
      db.query(query2, [classid]);
      res.json({ success: true, message: 'Class deleted successfully' });
    })
    .catch((error) => {
      res.status(500).send(error);
    });
  } catch (error) {
    console.error('Error in deleteClass:', error);
    res.status(500).send(error, message);
  }
});

app.post('/getClassTime', verifyToken, async (req, res) => {
  const { classdate, classday, courseid } = req.body;
  const query = 'SELECT a.* , case when count(b.reservationid) > 0 then a.maxperson - count(b.reservationid) else a.maxperson end as available '+
  'FROM tclass a ' +
  'left join treservation b ' +
  'on a.classid = b.classid ' +
  'and b.classdate = ? ' +
  'WHERE a.classday = ? ' +
  'and a.courseid = ? ' +
  'group by a.classid , a.classday , a.classtime , a.maxperson , a.courseid ';
  try {
    await queryPromise(query, [classdate, classday, courseid])
    .then((results) => {
      if(results.length > 0){
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
    res.status(500).send(error, message);
  }
});

app.get("/getNewStudentList", verifyToken, async (req, res) => {
  const query = 'select jfamilymember.*, CONCAT(firstname, \' \', lastname, \' (\', nickname,\')\') fullname, c.username from jfamilymember left join tfamily b on jfamilymember.familyid = b.familyid left join tuser c on b.username = c.username';
  try {
    await queryPromise(query, null)
    .then((results) => {
      if(results.length > 0) {
        res.json({ success: true, message: 'Get New Students successful', results });
      } else {
        res.json({ success: true, message: 'No New Students' , results});
      }
    })
    .catch((error) => {
      res.json({ success: false, message: error.message });
      console.error('Error in queryPromise:', error);
    })
  } catch (error) {
    console.error('Error in getNewStudentList:', error);
    res.status(500).send(error, message);
  }
});

app.get("/courseLookup", verifyToken, async (req, res) => {
  const query = 'SELECT * FROM tcoursetype';
  await queryPromise(query, null)
  .then((results) => {
    if(results.length > 0) {
      res.json({ success: true, message: 'Get Course Lookup successful', results });
    } else {
      res.json({ success: true, message: 'No Course Lookup' });
    }
  })
  .catch((error) => {
    res.json({ success: false, message: error.message });
    console.error('Error in queryPromise:', error);
  })

  // if(results.length > 0){
  //   res.json({ success: true, message: 'Get Course Lookup successful', results });
  // } else {
  //   res.json({ success: true, message: 'No Course Lookup' });
  // }
});

app.get("/familyLookup", verifyToken, async (req, res) => {
  const query = 'SELECT * FROM tfamily';
  await queryPromise(query, null)
  .then((results) => {
    if(results.length > 0) {
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
  const query = 'SELECT *, CONCAT(nickname, \' \', firstname, \' \', lastname) as name FROM tfamilymember'
  if(familyid !== null && familyid !== undefined && familyid !== '') {
    query = query + ' WHERE familyid = ?';
  }

  await queryPromise(query, [familyid])
  .then((results) => {
    if(results.length > 0) {
      res.json({ success: true, message: 'Get Student Lookup successful', results });
    } else {
      res.json({ success: true, message: 'No Student Lookup' });
    }
  })
  .catch((error) => {
    res.json({ success: false, message: error.message });
    console.error('Error in queryPromise:', error);
  })

  // if(results.length > 0){
  //   res.json({ success: true, message: 'Get Student Lookup successful', results });
  // } else {
  //   res.json({ success: true, message: 'No Student Lookup' });
  // }
});

app.get("/getStudentList", verifyToken, async (req, res) => {
  try {
    const query = 'SELECT a.*, CONCAT(a.firstname, \' \', a.lastname, \' (\', a.nickname,\')\') fullname, b.coursename, d.mobileno FROM tfamilymember a LEFT JOIN tcoursetype b ON a.courseid = b.courseid LEFT JOIN tfamily c ON a.familyid = c.familyid LEFT JOIN tuser d ON c.username = d.username';
    const results = await queryPromise(query);

    console.log("API getStudentlist result :" + JSON.stringify(results));

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
      SELECT a.*, b.coursename, CONCAT(c.firstname, ' ', c.lastname, ' (', c.nickname,')') fullname
      FROM treservation a
      LEFT JOIN tcoursetype b ON a.courseid = b.courseid
      LEFT JOIN tfamilymember c ON a.childid = c.childid
      WHERE a.classdate = ?
      ORDER BY a.classtime ASC
    `;

    const results = await queryPromise(query, [classdate]);

    console.log("API getReservationList result: " + JSON.stringify(results));

    if (results.length > 0) {
      res.json({ success: true, message: 'Get Reservation list successful', results });
    } else {
      res.json({ success: true, message: 'No Reservation list' , results });
    }
  } catch (error) {
    console.error("API getReservationList error: " + JSON.stringify(error));
    res.status(500).send(error);
  }
});

app.post("/checkinByAdmin", verifyToken, async (req, res) => {
  try {
    const { reservationid, childid } = req.body;
    const query = 'UPDATE treservation SET checkedin = 1 WHERE reservationid = ? AND childid = ?';
    const results = await queryPromise(query, [reservationid, childid]);

    if (results.affectedRows > 0) {
      res.json({ success: true, message: 'Checkin successful' });
    } else {
      res.json({ success: false, message: 'No Reservation data' });
    }
  }
  catch (error) {
    console.error("API checkinByAdmin error: " + JSON.stringify(error));
    res.status(500).send
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
    const query1 = 'select count(*) as total from tfamilymember';
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
    const query4 = 'select count(*) as total from jfamilymember';
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
    const query = 'SELECT DISTINCT a.classtime, a.courseid, CONCAT(a.classtime,\'(\',b.course_shortname,\')\') as class_label, a.classid FROM tclass a join tcoursetype b on  a.courseid = b.courseid where a.classday = ? order by a.classtime'
    const results = await queryPromise(query, [ classday ]);
    console.log("results : " + JSON.stringify(results));
    let bookinglist = {};
    if (results.length > 0) {
        for (let index = 0; index < results.length; index++) {
            let this_class = [];
            const element = results[index];
            const query2 = 'SELECT CONCAT(a.classtime,\'(\',b.course_shortname,\')\') as classtime, c.nickname, a.checkedin  ' +
                'FROM treservation a ' +
                'join tcoursetype b on  a.courseid = b.courseid ' +
                'left join tfamilymember c on a.childid = c.childid ' +
                'WHERE a.classdate = ? ' +
                'AND a.classid = ? ' +
                'order by a.classtime asc';

            const results2 = await queryPromise(query2, [ classdate, element.classid ]);
            console.log("results2 : " + JSON.stringify(results2));

            if (results2.length > 0) {
                let studentlist = [];
                for (let index2 = 0; index2 < results2.length; index2++) {
                    const element2 = results2[index2];
                    if(element2.checkedin == 1) {
                      studentlist.push(element2.nickname+"("+element2.checkedin+")");
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
  } catch (err) {
      res.status(500).send(err);
  }
});


// Utility function to promisify the database queries
// async function queryPromise(query, params) {
//   return new Promise((resolve, reject) => {
//     await db.query(query, params, (err, results) => {
//       console.log("Query : " + query);
//       console.log("Params : " + params);
//       if (err) {
//         console.log("Query error: " + JSON.stringify(err));
//         reject(err);
//       } else {
//         console.log("Query results: " + JSON.stringify(results));
//         resolve(results);
//       }
//     });
//   });
// }

const mysql2 = require('mysql2/promise');

// Create a connection pool
const pool = mysql2.createPool({
  host: 'istardb-do-user-15700861-0.c.db.ondigitalocean.com',
  port: 25060,
  user: 'doadmin',
  password: 'AVNS_WXj7F6yfu4VzF5b4St-',
  database: 'istardb',
  waitForConnections: true,
  connectionLimit: 0,
  queueLimit: 0
  // ssl: {
  //   ca: fs.readFileSync('./ca-certificate.crt')
  // }
});

// Function to execute queries using the connection pool
async function queryPromise(query, params) {
  let connection;
  try {
    console.log("Query : " + query);
    console.log("Params : " + params);
    connection = await pool.getConnection();
    const [results] = await connection.query(query, params);
    return results;
  } catch (error) {
    throw error;
  } finally {
    if (connection) connection.release();
  }
}

app.listen(port, '0.0.0.0', () => {
    console.log(`Server is running on port ${port}`);
  });
