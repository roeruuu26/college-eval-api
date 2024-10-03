require('dotenv').config(); // Load environment variables from a .env file if it exists (for local development)

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const mysql = require('mysql');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();

// Rate Limiter for Login Attempts
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 3, // limit each IP to 3 requests
    message: 'Too many login attempts from this IP, please try again after 15 minutes',
    standardHeaders: true,
    legacyHeaders: false,
});

// Middleware
app.use(express.json());
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:5173', // Allow requests from your frontend origin
    credentials: true
}));

app.use(session({
    key: 'userId',
    secret: process.env.SESSION_SECRET || 'try_natin_to_ahh',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
        maxAge: 24 * 60 * 60 * 1000 // 1 day
    }
}));

// Database connection
const db = mysql.createConnection({
    user: process.env.DB_USER || 'root',
    host: process.env.DB_HOST || 'localhost',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'college_eval_db'
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

// Add other routes...

// Logout Route
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

// Set the server to listen on the dynamic port assigned by Railway
const PORT = process.env.PORT || 3002;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on port ${PORT}`);
});

module.exports = app;
