const express = require('express');
const router = express.Router();
const db = require('../db');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

function createKeyFromPassword(password) {
    return crypto.createHash('sha256').update(password).digest();
}

let key = createKeyFromPassword(process.env.api_key);

router.post('/generatetoken', (req, res) => {
    const refreshToken = req.body.token;
    if (refreshToken == null) return res.sendStatus(401);

    const sqlCheckToken = 'SELECT EXISTS(SELECT 1 FROM refreshtokens WHERE token = ?) AS `Exists`';
    db.query(sqlCheckToken, [refreshToken], (err, result) => {
        if (err) {
            console.error('Error checking refresh token: ', err);
            return res.status(500).json({ error: 'Internal server error' });
        }

        const tokenExists = result[0].Exists;
        if (!tokenExists) return res.sendStatus(403);

        jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
            if (err) {
                if (err.name === 'TokenExpiredError') return res.sendStatus(401); // handle token expiration here
                return res.sendStatus(403); // handle other token errors here
            }
            const accessToken = generateAccessToken({ id: user.id });
            res.json({ accessToken: accessToken });
        });
    });
});



function logUserActivity(logData) {
    // Prepare the SQL query to insert the log into the userlogs table
    const query = 'INSERT INTO userlogs (logData, created_at) VALUES (?, NOW())';
    const values = [logData, null];
  
    // Execute the query
    db.query(query, values, (error, result) => {
      if (error) {
        console.error('Error logging user activity:', error);
      } else {
        console.log('User activity logged successfully');
      }
    });
  }

router.delete('/logout', (req, res) => {
    const sqlDeleteToken = 'DELETE FROM refreshtokens WHERE token = ?';
    db.query(sqlDeleteToken, [req.body.token], (err, result) => {
        if (err) {
            console.error('Error deleting refresh token: ', err);
            return res.status(500).json({ error: 'Internal server error' });
        }
        res.sendStatus(204);
    });
});



router.get('/', authenticateToken, (req, res) => {
    const userID = req.user.id;

    // Existing queries to get user details and notification count
    db.query('SELECT * FROM users WHERE userid =?', [userID], (error, userResults) => {
        if (error) {
            console.error('Error retrieving user details: ', error);
            res.status(500).json({ error: 'Internal server error' });
        } else {
            // Query to count notifications for the user
            db.query('SELECT COUNT(*) as notificationCount FROM notifications WHERE userid =?', [userID], (error, notificationResults) => {
                if (error) {
                    console.error('Error retrieving notification count: ', error);
                    res.status(500).json({ error: 'Internal server error' });
                } else {
                    // New query to count leave requests
                    db.query('SELECT COUNT(CASE WHEN request_status = \'Approved\' THEN 1 END) AS approvedRequests, COUNT(CASE WHEN request_status = \'Denied\' THEN 1 END) AS deniedRequests, COUNT(CASE WHEN request_status = \'Pending\' THEN 1 END) AS pendingRequests FROM leaverequests', (error, leaveRequestResults) => {
                        if (error) {
                            console.error('Error retrieving leave request counts: ', error);
                            res.status(500).json({ error: 'Internal server error' });
                        } else {
                            // Combine user details, notification count, and leave request counts into the response
                            res.json({
                                user: userResults[0],
                                notificationCount: notificationResults[0].notificationCount,
                                leaveRequests: {
                                    approvedRequests: leaveRequestResults[0].approvedRequests,
                                    deniedRequests: leaveRequestResults[0].deniedRequests,
                                    pendingRequests: leaveRequestResults[0].pendingRequests
                                }
                            });
                        }
                    });
                }
            });
        }
    });
});




router.get('/profile', authenticateToken, (req, res) => {
    const userID = req.user.id;
  
    db.query('SELECT userid, lastname, firstname, middlename, department, position, salary, contactnumber FROM users WHERE users.UserID = ?', [userID], (error, results) => {
      if (error) {
        console.error('Error retrieving user profile: ', error);
        res.status(500).json({ error: 'Internal server error' });
      } else {
        // Decrypt each field of the user
        results[0].lastname = decryptData(results[0].lastname, key);
        results[0].firstname = decryptData(results[0].firstname, key);
        results[0].middlename = decryptData(results[0].middlename, key);
        results[0].contactnumber = decryptData(results[0].contactnumber, key);
        res.json(results[0]);
      }
    });
});
  



router.post('/login', (req, res) => {
    const userID = req.body.userid;
    const password = req.body.password;

    db.query('SELECT * FROM users WHERE userid = ? AND password = ?', [userID, password], (error, results) => {
        if (error) {
            console.error('Error fetching user: ', error);
            return res.status(500).json({ error: 'Internal server error' });
        }

        if (results.length === 0) {
            return res.status(400).json({ error: 'User not found' });
        }

        const user = { id: userID };
        const accessToken = generateAccessToken(user);
        const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);

       // Improved log message for user login activity using "Employee"
        const logData = `Employee with ID of ${userID} has successfully logged in.`;

        // Call to logUserActivity with the improved log message
        logUserActivity(logData);


        const sqlInsertToken = 'INSERT INTO refreshtokens (userid, token) VALUES (?, ?)';
        db.query(sqlInsertToken, [userID, refreshToken], (err, result) => {
            if (err) {
                console.error('Error inserting refresh token: ', err);
                return res.status(500).json({ error: 'Internal server error' });
            }

            res.status(200).json({ 
                accessToken: accessToken, 
                refreshToken: refreshToken, 
                message: 'Login Success' 
              });
              
        });
    });
});


function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if (token == null) return res.sendStatus(401)

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403)
        req.user = user
        next()
    })
}

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '3d' });
}


function encryptData(data, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = Buffer.concat([cipher.update(data), cipher.final()]);

    if (typeof data === 'number') {
        data = data.toString();
    }

    return iv.toString('hex') + ':' + encrypted.toString('base64');
}

function decryptData(data, key) {
    const textParts = data.split(':');
    const iv = Buffer.from(textParts[0], 'hex');
    const encryptedText = Buffer.from(textParts[1], 'base64');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString().split(',');
}




router.get('/leavebalance', authenticateToken, (req, res) => {
    const userID = req.user.id;

    db.query('SELECT vacation, sickleave, forcedleave, special_privilege_leave, solo_parent_leave, updated_at FROM leavebalances WHERE userid = ?', [userID], (error, results) => {
        if (error) {
            console.error('Error retrieving user leave balances: ', error);
            res.status(500).json({ error: 'Internal server error' });
        } else {
            res.json(results);
        }
    });
});

router.post('/leaverequest', authenticateToken, (req, res) => {
    const userID = req.user.id;
    const { leaveid, reasonid, inclusivedates, duration, description, commutation } = req.body;
   
    // Please ensure proper data validation before inserting into database
    if (!leaveid) {
        return res.status(400).json({ error: 'Required fields' });
    }
    
    db.query('SELECT u.userid, vacation, sickleave, forcedleave, special_privilege_leave, solo_parent_leave, updated_at FROM leavebalances lb join users u on lb.userid = u.userid WHERE u.userid = ?', [userID], (error, results) => {
        if (error) {
            console.error('Error querying leave balances: ', error);
            res.status(500).json({ error: 'Internal server error-' });
        } else {
            const vacationCreds = results[0].vacation;
            const sickCreds = results[0].sickleave;

            const leaveRequestQuery = 'INSERT INTO leaverequests (userid, leaveid, reasonid, inclusivedates, duration, description, commutation, vacationCreds, sickCreds) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';
            const leaveRequestValues = [userID, leaveid, reasonid, inclusivedates, duration, description, commutation, vacationCreds, sickCreds];

            db.query(leaveRequestQuery, leaveRequestValues, (error, results) => {
                if (error) {
                    console.error('Error inserting leave request: ', error);
                    res.status(500).json({ error: 'Internal server error--' });
                } else {
                    const logData = `Employee with ID ${userID} has submitted a new leave request.`;
                    logUserActivity(logData);

                    res.status(201).json({ message: 'Leave Request added successfully' });
                }
            });
        }
    });
});



router.get('/pendingrequest', authenticateToken, (req, res) => {
    const userID = req.user.id;

    db.query('SELECT leaveid, reasonid, inclusivedates, duration, description, datefiled, process_no FROM leaverequests WHERE userid = ? AND request_status = ? ORDER BY datefiled DESC', [userID, 'Pending'], (error, results) => {
        if (error) {
            console.error('Error retrieving pending requests: ', error);
            res.status(500).json({ error: 'Internal server error' });
        } else {
            res.json(results);
        }
    });
});



router.get('/history', authenticateToken, (req, res) => {
    const userID = req.user.id;

    db.query('SELECT leaveid, reasonid, inclusivedates, duration, description, datefiled, request_status, datereceived FROM leaverequests WHERE userid = ? AND request_status IN (?, ?) ORDER BY datefiled DESC', [userID, 'Approved', 'Denied'], (error, results) => {
        if (error) {
            console.error('Error retrieving requests: ', error);
            res.status(500).json({ error: 'Internal server error' });
        } else {
            res.json(results);
        }
    });
});



router.get('/notifications', authenticateToken, (req, res) => {
    const userID = req.user.id;

    db.query('SELECT created_at, message, notificationid FROM notifications WHERE userid = ? ORDER BY created_at DESC', [userID], (error, results) => {
        if (error) {
            console.error('Error retrieving notifications: ', error);
            res.status(500).json({ error: 'Internal server error' });
        } else {
            res.json(results);
        }
    });
});


module.exports = router;
