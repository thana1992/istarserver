const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
const port = 3000;
const jwt = require('jsonwebtoken');
const db = mysql.createConnection({
  host: '0.0.0.0',
  user: 'root',
  password: 'password',
  database: 'istar',
});

db.connect(err => {
  if (err) {
    console.log(err);
  } else {
    console.log('Connected to MySQL');
  }
});

app.use(cors());
app.use(bodyParser.json());

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const query = 'SELECT *, b.familyid FROM tuser a left join tfamily b on a.username = b.username WHERE a.username = ?';

  db.query(query, [username], (err, results) => {
    if (err) {
      res.status(500).send(err);
    } else {
      if (results.length > 0) {
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
        bcrypt.hash(password, 10, (err, hashedPassword) => {
          bcrypt.compare(password, hashedPassword, (err, match) => {
            if (match) {
              const logquery = 'INSERT INTO llogin (username) VALUES (?)';
              db.query(logquery, [username]);
              const token = jwt.sign({ userId: user.id, username: user.username }, 'your-secret-key', { expiresIn: '1h' });
              res.json({ success: true, message: 'Login successful', token, userdata });
            } else {
              res.json({ success: false, message: 'Username or Password is invalid' });
            }
          });
        });
      } else {
        res.json({ success: false, message: 'Invalid credentials' });
      }
    }
  });
});

app.post('/register', (req, res) => {
    const { username, password, fullname, address, email, mobileno, lineid } = req.body;
    const checkUsernameQuery = 'SELECT * FROM tuser WHERE username = ?';
    db.query(checkUsernameQuery, [username], (err, results) => {
      if (err) {
        return res.status(500).send(err);
      }

      if (results.length > 0) {
        return res.json({ success: false, message: 'Username is already taken' });
      }
      bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
          res.status(500).send(err);
        } else {
          const query = 'INSERT INTO tuser (username, userpassword, fullname, address, email, mobileno, lineid) VALUES (?, ?, ?, ?, ?, ?, ?)';
          db.query(query, [username, hashedPassword, fullname, address, email, mobileno, lineid], (err) => {
            if (err) {
              res.status(500).send(err);
            } else {
              const createFamilyQuery = 'INSERT INTO tfamily (username) VALUES (?)';
              db.query(createFamilyQuery, [username], (err2) => {
                  res.json({ success: true, message: 'User registered successfully' });
                  if(err2){
                    res.status(500).send(err2);
                  }
              });
            }
          });
        }
      });
    });
  });

  app.post("/getFamilyMember", (req, res) => {
    const { familyid } = req.body;
    const query = 'select a.childid, a.familyid, a.firstname, a.lastname, a.nickname, a.gender, a.dateofbirth, a.photo, a.remaining, a.courseid, b.coursename, b.course_shortname' +
                    ' from tfamilymember a ' +
                    ' left join tcourse b ' +
                    ' on a.courseid = b.courseid ' +
                    ' where a.familyid = ?';
    db.query(query, [familyid], (err, results) => {
      console.log("API getFamilyMember result :" + JSON.stringify(results));
      if(results){
        if(results.length > 0){
          res.json({ success: true, message: 'Get Family Member successful', results });
        } else {
          res.json({ success: false, message: 'No Family Member' });
        }
      }

      if(err){
        res.status(500).send(err);
      }
    });
  });

  app.post('/addFamilyMember', (req, res) => {
    const { familyid, firstname, lastname, nickname, gender, dateofbirth, courseid } = req.body;
    const query = 'INSERT INTO tfamilymember (familyid, firstname, lastname, nickname, gender, dateofbirth, courseid, remaining, photo) ' +
                  ' VALUES (?, ?, ?, ?, ?, ?, 1, 0, \'https://cdn3.iconfinder.com/data/icons/family-member-flat-happy-family-day/512/Son-512.png\')';
    db.query(query, [familyid, firstname, lastname, nickname, gender, dateofbirth, courseid], (err) => {
      if (err) {
        res.status(500).send(err);
      } else {
        res.json({ success: true, message: 'Family member added successfully' });
      }
    });
  });

  app.post('/deleteFamilyMember', (req, res) => {
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

  app.post('/getMemberInfo', (req, res) => {
    const { childid } = req.body;
    const query = 'SELECT * FROM tfamilymember WHERE childid = ?';
    db.query(query, [childid], (err, infomation) => {
      if(infomation.length > 0){
        res.json({ success: true, message: 'Get Member Info successful', infomation });
      } else {
        res.json({ success: false, message: 'No Member Info' });
      }

      if(err){
        res.status(500).send(err);
      }
    });
  });

  app.post('/getMemberReservationDetail', (req, res) => {
    const { childid } = req.body;
    const query = 'SELECT * FROM treservation WHERE childid = ? order by classdate asc';
    db.query(query, [childid], (err, results) => {
      if(results.length > 0){
        res.json({ success: true, message: 'Get Reservation Detail successful', results });
      } else {
        res.json({ success: false, message: 'No Reservation Detail' });
      }

      if(err){
        res.status(500).send(err);
      }
    });
  });

  app.post('/addReservation', (req, res) => {
    console.log("addReservation : " + JSON.stringify(req.body));
    const { courseid, classid, classday, classdate, classtime, childid } = req.body;
    let checkClassFullQuery = 'select maxperson from tclass where classid = ? and classday = ? and classtime = ?';
    db.query(checkClassFullQuery, [classid, classday, classtime], (err, results) => {
      console.log("checkClassFullQuery results 1 : " + JSON.stringify(results));
      if (results.length > 0) {
        const maxperson = results[0].maxperson;
        checkClassFullQuery = 'select count(*) as count from treservation where classid = ? and classdate = ? and classtime = ?';
        db.query(checkClassFullQuery, [classid, classdate, classtime], (err, results) => {
          console.log("checkClassFullQuery results 2 : " + JSON.stringify(results));
          if (err) {
            return res.status(500).send(err);
          }else if (results.length > 0) {
            const count = results[0].count;
            if (count >= maxperson) {
              return res.json({ success: false, message: 'ขอโทษค่ะ คลาสที่ท่านเลือกเต็มแล้ว' });
            }else{
              const checkRemainingQuery = 'select remaining from tfamilymember where childid = ?';
              db.query(checkRemainingQuery, [childid], (err, results) => {
                console.log("checkRemainingQuery results : " + JSON.stringify(results));
                if (err) {
                  return res.status(500).send(err);
                }else if (results.length > 0) {
                  const remaining = results[0].remaining;
                  if (remaining <= 0) {
                    return res.json({ success: false, message: 'ขอโทษค่ะ จำนวนคลาสคงเหลือของท่านหมดแล้ว' });
                  }else{
                    console.log("======= addReservation =======")
                    const query = 'INSERT INTO treservation (courseid, classid, classdate, classtime, childid) VALUES (?, ?, ?, ?, ?)';
                    db.query(query, [courseid, classid, classdate, classtime, childid], (err) => {
                      console.log("addReservation err : " + JSON.stringify(err));
                      if (err) {
                        return res.status(500).send(err);
                      } else {
                        const updateRemainingQuery = 'UPDATE tfamilymember SET remaining = remaining - 1 WHERE childid = ?';
                        db.query(updateRemainingQuery, [childid], err => {
                          if (err) {
                            return res.status(500).send(err);
                          }
                        });
                        return res.json({ success: true, message: 'Reservation added successfully' });
                      }
                    });
                  }
                }else{
                  return res.json({ success: false, message: 'ไม่พบข้อมูลของท่าน' });
                }
              });
            }
          }else{
            return res.json({ success: false, message: 'ไม่สามารถจองคลาสได้ กรุณาลองใหม่อีกครั้ง' });
          }
        });
      }else{
        return res.json({ success: false, message: 'ไม่พบคลาสที่ท่านเลือก' });
      }
      
      
    });
  });

  app.post('/deleteReservation', (req, res) => {
    const { reservationid } = req.body;
    const query = 'DELETE FROM treservation WHERE reservationid = ?';
    db.query(query, [reservationid], (err) => {
      if (err) {
        res.status(500).send(err);
      } else {
        res.json({ success: true, message: 'Reservation deleted successfully' });
      }
    });
  });

  app.post('/checkDuplicateReservation', (req, res) => {
    const { childid, classdate } = req.body;
    const query = 'SELECT * FROM treservation WHERE childid = ? and classdate = ?';
    db.query(query, [childid, classdate], (err, results) => {
      if(results.length > 0){
        res.json({ success: false, message: 'You have already reservation on this day' });
      } else {
        res.json({ success: true, message: 'No Reservation on this day' });
      }

      if(err){
        res.status(500).send(err);
      }
    });
  });

  app.get('/getAllCourses', (req, res) => {
    const query = 'SELECT * FROM tcourse';
    db.query(query, (err, results) => {
      if(results.length > 0){
        res.json({ success: true, message: 'Get All Course successful', results });
      } else {
        res.json({ success: false, message: 'No Course' });
      }

      if(err){
        res.status(500).send(err);
      }
    });
  });

  app.post('/addCourse', (req, res) => {
    const { coursename, course_shortname } = req.body;
    const query = 'INSERT INTO tcourse (coursename, course_shortname) VALUES (?, ?)';
    db.query(query, [coursename, course_shortname], (err) => {
      if (err) {
        res.status(500).send(err);
      } else {
        res.json({ success: true, message: 'Course added successfully' });
      }
    });
  });

  app.post('/updateCourse', (req, res) => {
    const { coursename, course_shortname, courseid } = req.body;
    const query = 'UPDATE tcourse SET coursename = ?, course_shortname = ? WHERE courseid = ?';
    db.query(query, [ coursename, course_shortname, courseid ], (err) => {
      if (err) {
        res.status(500).send(err);
      } else {
        res.json({ success: true, message: 'Course updated successfully' });
      }
    });
  });

  app.post('/deleteCourse', (req, res) => {
    const { courseid } = req.body;
    const deleteTcouseQuery = 'DELETE FROM tcourse WHERE courseid = ?';
    db.query(deleteTcouseQuery, [courseid], (err) => {
      if (err) {
        res.status(500).send(err);
      } else {
        const deleteTclassQuery = 'DELETE FROM tclass WHERE courseid = ?';
        db.query(deleteTclassQuery, [courseid], (err) => {
          if (err) {
            res.status(500).send(err);
          } else {
            res.json({ success: true, message: 'Course deleted successfully' });
          }
        });
      }
    });
  });

  app.get('/getAllClasses', (req, res) => {
    const { courseid } = req.body;
    const query = 'SELECT b.courseid, b.coursename, a.* FROM tclass a inner join tcourse b on a.courseid = b.courseid order by b.coursename , a.classday ';
    db.query(query, [courseid], (err, results) => {
      if(results.length > 0){
        res.json({ success: true, message: 'Get All Class successful', results });
      } else {
        res.json({ success: false, message: 'No Class' });
      }

      if(err){
        res.status(500).send(err);
      }
    });
  });

  app.post('/addClass', (req, res) => {
    const { courseid, classday, classtime, maxperson } = req.body;
    const query = 'INSERT INTO tclass (courseid, classday, classtime, maxperson) VALUES (?, ?, ?, ?)';
    db.query(query, [courseid, classday, classtime, maxperson], (err) => {
      if (err) {
        res.status(500).send(err);
      } else {
        res.json({ success: true, message: 'Class added successfully' });
      }
    });
  });

  app.post('/updateClass', (req, res) => {
    const { classid, courseid, classday, classtime, maxperson } = req.body;
    const query = 'UPDATE tclass SET courseid = ?, classday = ?, classtime = ?, maxperson = ? WHERE classid = ?';
    db.query(query, [courseid, classday, classtime, maxperson, classid], (err) => {
      if (err) {
        res.status(500).send(err);
      } else {
        res.json({ success: true, message: 'Class updated successfully' });
      }
    });
  });

  app.post('/deleteClass', (req, res) => {
    const { classid } = req.body;
    const query = 'DELETE FROM tclass WHERE classid = ?';
    db.query(query, [classid], (err) => {
      if (err) {
        res.status(500).send(err);
      } else {
        res.json({ success: true, message: 'Class deleted successfully' });
      }

      if(err){
        res.status(500).send(err);
      }
    });
  });

  app.post('/getClassTime', (req, res) => {
    const { classdate, classday, courseid } = req.body;
    const query = 'SELECT a.* , case when count(b.reservationid) > 0 then a.maxperson - count(b.reservationid) else a.maxperson end as available '+
    'FROM tclass a ' +
    'left join treservation b ' +
    'on a.classid = b.classid ' +
    'and b.classdate = ? ' +
    'WHERE a.classday = ? ' +
    'and a.courseid = ? ' +
    'group by a.classid , a.classday , a.classtime , a.maxperson , a.courseid ';
    db.query(query, [classdate, classday, courseid], (err, results) => {
      if(results) {
        if(results.length > 0){
          results.forEach((element, index) => {  
            results[index].text = element.classtime + ' ว่าง ' + element.available + ' คน';  
        }); 
          res.json({ success: true, message: 'Get Class Time successful', results });
        } else {
          res.json({ success: false, message: 'No Class Time' });
        }
      }

      if(err){
        res.status(500).send(err);
      }
    });
  });

  app.get("/courseLookup", (req, res) => {
    const query = 'SELECT * FROM tcourse';
    db.query(query, (err, results) => {
      if(results.length > 0){
        res.json({ success: true, message: 'Get Course Lookup successful', results });
      } else {
        res.json({ success: false, message: 'No Course Lookup' });
      }

      if(err){
        res.status(500).send(err);
      }
    });
  });

  app.get("/getTotalStudents", (req, res) => {
    const query = 'select count(*) as total from tfamilymember';
    db.query(query, (err, results) => {
      if(results.length > 0){
        res.json({ success: true, message: 'Get Total Students successful', results });
      } else {
        let results = [{ total: 0 }];
        res.json({ success: true, message: 'No Total Students', results });
      }

      if(err){
        res.status(500).send(err);
      }
    });
  });

  app.get("/getTotalReservationToday", (req, res) => {
    const query = 'select count(*) as total from treservation where classdate = curdate()';
    db.query(query, (err, results) => {
      if(results.length > 0){
        res.json({ success: true, message: 'Get Total Reservation Today successful', results });
      } else {
        let results = [{ total: 0 }];
        res.json({ success: true, message: 'No Total Reservation Today', results });
      }

      if(err){
        res.status(500).send(err);
      }
    });
  });

  app.post("/getReservationList", (req, res) => {
    const { classdate } = req.body;
    const query = 'SELECT a.*, b.coursename, CONCAT(c.firstname, \' \', c.lastname, \' (\', c.nickname,\')\') fullname ' +
                  'FROM treservation a left join tcourse b on a.courseid = b.courseid ' +
                  'left join tfamilymember c on a.childid = c.childid ' +
                  'WHERE a.classdate = ? ' +
                  'order by a.classtime asc';
    db.query(query, [classdate], (err, results) => {
      console.log("API getReservationList result :" + JSON.stringify(results));
      if(results.length > 0){
        res.json({ success: true, message: 'Get Reservation list successful', results });
      } else {
        res.json({ success: false, message: 'No Reservation list'});
      }

      if(err){
        res.status(500).send(err);
      }
    });
  });

app.listen(port, '0.0.0.0', () => {
    console.log(`Server is running on port ${port}`);
  });