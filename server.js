const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
const port = 3000;
const jwt = require('jsonwebtoken');
const db = mysql.createConnection({
  host: 'localhost',
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
              db.query(createFamilyQuery, [username], (err) => {
                if(err){
                  res.status(500).send(err);
                } else {
                  res.json({ success: true, message: 'User registered successfully' });
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
                    ' on a.courseid = b.courseid  ';
    db.query(query, [familyid], (err, results) => {
      if(results.length > 0){
        res.json({ success: true, message: 'Get Family Member successful', results });
      } else {
        res.json({ success: false, message: 'No Family Member' });
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

  app.post('/addReservation', (req, res) => {
    const { courseid, classid, classday, classdate, classtime, childid } = req.body;
    let checkClassFullQuery = 'select maxperson from tclass where classid = ? and classday = ? and classtime = ?';
    db.query(checkClassFullQuery, [classid, classday, classtime], (err, results) => {
      if (results.length > 0) {
        const maxperson = results[0].maxperson;
        checkClassFullQuery = 'select count(*) as count from treservation where classid = ? and classdate = ? and classtime = ?';
        db.query(checkClassFullQuery, [classid, classdate, classtime], (err, results) => {
          if (err) {
            return res.status(500).send(err);
          }else if (results.length > 0) {
            const count = results[0].count;
            if (count >= maxperson) {
              return res.json({ success: false, message: 'Class is already full' });
            }else{
              const query = 'INSERT INTO treservation (courseid, classid, classdate, classtime, childid) VALUES (?, ?, ?, ?, ?)';
              db.query(query, [courseid, classid, classdate, classtime, childid], (err) => {
                if (err) {
                  return res.status(500).send(err);
                } else {
                  return res.json({ success: true, message: 'Reservation added successfully' });
                }
              });
            }
          }
        });
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

  app.post('/addCourse', (req, res) => {
    const { coursename } = req.body;
    const query = 'INSERT INTO tcourse (coursename) VALUES (?, ?, ?, ?)';
    db.query(query, [coursename, coursedesc, courseprice, coursestatus], (err) => {
      if (err) {
        res.status(500).send(err);
      } else {
        res.json({ success: true, message: 'Course added successfully' });
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

  app.post('/deleteClass', (req, res) => {
    const { classid } = req.body;
    const query = 'DELETE FROM tclass WHERE classid = ?';
    db.query(query, [classid], (err) => {
      if (err) {
        res.status(500).send(err);
      } else {
        res.json({ success: true, message: 'Class deleted successfully' });
      }
    });
  });

  app.post('/getClassTime', (req, res) => {
    const { courseid, classday } = req.body;
    const query = 'SELECT * FROM tclass WHERE courseid = ? and classday = ?';
    db.query(query, [courseid, classday], (err, results) => {
      if(results.length > 0){
        res.json({ success: true, message: 'Get Class Time successful', results });
      } else {
        res.json({ success: false, message: 'No Class Time' });
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
  
  app.post('/getAllClasses', (req, res) => {
    const { courseid } = req.body;
    const query = 'SELECT b.coursename, a.* FROM tclass a inner join tcourse b on a.courseid = b.courseid order by b.coursename , a.classday ';
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
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
