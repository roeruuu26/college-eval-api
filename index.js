const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const app = express();
const mysql = require('mysql');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 3, // limit each IP to 3 requests
    message: 'Too many login attempts from this IP, please try again after 15 minutes',
    standardHeaders: true,
    legacyHeaders: false,
});

app.use(express.json());
app.use(cors({
    origin: 'http://localhost:5173', // Adjust this to your React app's origin
    credentials: true
}));

app.use(session({
    key: 'userId',
    secret: 'try_natin_to_ahh',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false, // Set to true if using HTTPS
        maxAge: 24 * 60 * 60 * 1000 // 1 day
    }
}));

app.listen(3002, '0.0.0.0', () => {
    console.log('Server is running on port 3002');
});

// Database connection
const db = mysql.createConnection({
    user: 'root',
    host: 'localhost',
    password: '',
    database: 'college_eval_db'
});

// Routes
app.post('/register', async (req, res) => {
    const { idno, email, username, password, section } = req.body;

    // Check if the ID number exists in the student_list_data table for the academic year 2024-2025
    const checkIDSQL = "SELECT * FROM student_list_data WHERE idno = ? AND academic_year = '2024-2025'";
    db.query(checkIDSQL, [idno], async (err, result) => {
        if (err) {
            res.send({ error: err });
        } else if (result.length > 0) {
            // Check if the ID number is already used in the users table
            const checkUserSQL = "SELECT * FROM users WHERE idno = ?";
            db.query(checkUserSQL, [idno], async (err, result) => {
                if (err) {
                    res.send({ error: err });
                } else if (result.length > 0) {
                    res.send({ message: 'ID number is already used.' });
                } else {
                    try {
                        const hashedPassword = await bcrypt.hash(password, 10);
                        const SQL = "INSERT INTO users (idno, email, username, password, section, role) VALUES (?, ?, ?, ?, ?, ?)";
                        const values = [idno, email, username, hashedPassword, section, "student"];

                        db.query(SQL, values, (err, result) => {
                            if (err) {
                                res.send({ error: err });
                            } else {
                                res.send({ message: 'User added!' });
                                console.log('User added!');
                            }
                        });
                    } catch (error) {
                        res.status(500).send({ error: 'Error hashing password' });
                    }
                }
            });
        } else {
            res.send({ message: 'ID number not found in student list data for the academic year 2024-2025.' });
            console.log('ID number not found in student list data for the academic year 2024-2025.');
        }
    });
});

app.post('/login', loginLimiter, (req, res) => {
    const { loginuserr, loginpasss } = req.body;

    const SQL = "SELECT * FROM users WHERE username = ?";
    db.query(SQL, [loginuserr], async (err, result) => {
        if (err) {
            res.status(500).send({ error: 'Database error' });
        } else {
            if (result.length > 0) {
                const user = result[0];
                const isPasswordValid = await bcrypt.compare(loginpasss, user.password);
                if (isPasswordValid) {
                    req.session.user = {
                        id: user.id,
                        idno: user.idno, // Include idno in session
                        username: user.username,
                        role: user.role,
                    };
                    console.log('Session set:', req.session.user);
                    res.send({ loggedIn: true, user: req.session.user });
                    console.log('Logged in!');
                } else {
                    res.status(401).send({ message: 'Wrong username or password' });
                }
            } else {
                res.status(401).send({ message: 'Wrong username or password' });
            }
        }
    });
});

app.get('/getuser', (req, res) => {
    console.log('Get user session:', req.session.user); // Debug log
    if (req.session.user) {
        res.send({ loggedIn: true, user: req.session.user });
    } else {
        res.send({ loggedIn: false });
    }
});

app.get('/subjects', (req, res) => {
    const { idno, academic_year } = req.query;

    const SQL = `
        SELECT ss.subjects, ss.section, cs.subject_desc, cs.prof_name 
        FROM student_subjects ss
        JOIN course_subject cs ON ss.subjects = cs.subject_code
        WHERE ss.idno = ? AND ss.academic_year = ?
    `;
    db.query(SQL, [idno, academic_year], (err, result) => {
        if (err) {
            res.status(500).send({ error: 'Database error' });
            console.log('Database error');
        } else {
            res.send(result);
            console.log('Subjects Loaded!');
        }
    });
});


app.post('/logout', (req, res) => {
    if (req.session.user) {
        req.session.destroy(err => {
            if (err) {
                return res.send({ error: 'Logout failed!' });
            }
            res.clearCookie('userId');
            res.send({ message: 'Logged out successfully!' });
            console.log('Logged out successfully!');
        });
    } else {
        res.send({ message: 'No user to log out!' });
    }
});

// Load questions
app.get('/questions', (req, res) => {
    const SQL = "SELECT question_id, question FROM evaluation_question";
    db.query(SQL, (err, result) => {
        if (err) {
            res.status(500).send({ error: 'Database error' });
            console.log('Database error');
        } else {
            res.send(result);
            console.log('Questions Loaded!');
        }
    });
});


app.post('/saveRating', (req, res) => {
    const { questionId, rating, profName, subjectCode, section, comments, academicYear } = req.body;

    // Ensure the user is authenticated
    if (!req.session.user) {
        return res.status(401).send({ message: 'User not authenticated' });
    }

    // Create an array for rating columns initialized to 0
    const ratings = [0, 0, 0, 0, 0];
    ratings[rating - 1] = 1; // Set the selected rating to 1

    // First, check if an entry already exists
    const checkSQL = `
        SELECT * FROM faculty_performance 
        WHERE prof_name = ? AND subject_code = ? AND section = ? AND question_id = ? AND academic_year = ?
    `;
    const checkValues = [profName, subjectCode, section, questionId, academicYear];

    db.query(checkSQL, checkValues, (err, results) => {
        if (err) {
            res.status(500).send({ error: 'Database error' });
            console.log('Database error:', err);
        } else {
            if (results.length > 0) {
                // If an entry exists, update the relevant rating column
                const updateSQL = `
                    UPDATE faculty_performance 
                    SET \`${rating}\` = \`${rating}\` + 1, created_at = NOW()
                    WHERE prof_name = ? AND subject_code = ? AND section = ? AND question_id = ? AND academic_year = ?
                `;
                const updateValues = [profName, subjectCode, section, questionId, academicYear];
                db.query(updateSQL, updateValues, (err, result) => {
                    if (err) {
                        res.status(500).send({ error: 'Database error' });
                        console.log('Database error:', err);
                    } else {
                        res.send({ message: 'Rating updated!' });
                        console.log('Rating updated!');
                    }
                });
            } else {
                // If no entry exists, insert a new row
                const insertSQL = `
                    INSERT INTO faculty_performance (prof_name, subject_code, section, question_id, \`1\`, \`2\`, \`3\`, \`4\`, \`5\`, academic_year, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
                `;
                const insertValues = [profName, subjectCode, section, questionId, ...ratings, academicYear];
                db.query(insertSQL, insertValues, (err, result) => {
                    if (err) {
                        res.status(500).send({ error: 'Database error' });
                        console.log('Database error:', err);
                    } else {
                        res.send({ message: 'Rating saved!' });
                        console.log('Rating saved!');
                    }
                });
            }
        }
    });
});

app.post('/saveComment', (req, res) => {
    const { profName, subjectCode, section, academicYear, comments } = req.body;

    // Ensure the user is authenticated
    if (!req.session.user) {
        return res.status(401).send({ message: 'User not authenticated' });
    }

    const userId = req.session.user.idno;

    const insertCommentSQL = `
        INSERT INTO faculty_comments (prof_name, subject_code, section, academic_year, created_at, comments)
        VALUES (?, ?, ?, ?, NOW(), ?)
    `;
    const values = [profName, subjectCode, section, academicYear, comments];

    db.query(insertCommentSQL, values, (err, result) => {
        if (err) {
            res.status(500).send({ error: 'Database error' });
            console.log('Database error:', err);
        } else {
            res.send({ message: 'Comment saved!' });
            console.log('Comment saved!');
        }
    });
});

app.post('/saveEvaluationLog', (req, res) => {
    const { idno, section, subject, academicYear, subject_evaluated } = req.body;
  
    const insertLogSQL = `
      INSERT INTO evaluation_log (idno, section, subject, academic_year, subject_evaluated)
      VALUES (?, ?, ?, ?, ?)
    `;
    const logValues = [idno, section, subject, academicYear, subject_evaluated];
  
    db.query(insertLogSQL, logValues, (err, result) => {
      if (err) {
        res.status(500).send({ error: 'Database log error' });
        console.log('Database log error:', err);
      } else {
        res.send({ message: 'Evaluation log saved!' });
        console.log('Evaluation log saved!');
      }
    });
  });
  


// Route to get the evaluation log for a user
app.get('/evaluationLog', (req, res) => {
    const { idno, academic_year } = req.query;

    const SQL = `
        SELECT subject, section, subject_evaluated 
        FROM evaluation_log 
        WHERE idno = ? AND academic_year = ?
    `;
    db.query(SQL, [idno, academic_year], (err, result) => {
        if (err) {
            res.status(500).send({ error: 'Database error' });
            console.log('Database error:', err);
        } else {
            res.send(result);
            console.log('Evaluation log loaded!');
        }
    });
});

app.get('/evaluationStats', async (req, res) => {
    const { academic_year } = req.query;

    try {
        // Get total students per subject
        const totalQuery = `
            SELECT subjects, COUNT(idno) AS totalStudents
            FROM student_subjects
            WHERE academic_year = ?
            GROUP BY subjects;
        `;
        const totalStudents = await new Promise((resolve, reject) => {
            db.query(totalQuery, [academic_year], (err, result) => {
                if (err) reject(err);
                else resolve(result);
            });
        });

        // Get evaluated students per subject
        const evaluatedQuery = `
            SELECT subject, COUNT(DISTINCT idno) AS evaluatedStudents
            FROM evaluation_log
            WHERE academic_year = ? AND subject_evaluated = true
            GROUP BY subject;
        `;
        const evaluatedStudents = await new Promise((resolve, reject) => {
            db.query(evaluatedQuery, [academic_year], (err, result) => {
                if (err) reject(err);
                else resolve(result);
            });
        });

        // Combine data to calculate percentages
        const stats = totalStudents.map(subject => {
            const evaluation = evaluatedStudents.find(e => e.subject === subject.subjects) || { evaluatedStudents: 0 };
            const percentage = (evaluation.evaluatedStudents / subject.totalStudents) * 100;
            return {
                subject: subject.subjects,
                percentage: percentage.toFixed(2) // round to two decimal places
            };
        });

        res.json(stats);
    } catch (error) {
        res.status(500).send({ error: 'Database error' });
    }
});

// Check if subject is already evaluated


module.exports = app;

