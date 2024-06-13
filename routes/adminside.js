const express = require('express');
const router = express.Router();
const db = require('../db');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { request } = require('http');


function createKeyFromPassword(password) {
    return crypto.createHash('sha256').update(password).digest();
}
let key = createKeyFromPassword(process.env.api_key);

router.post('/generatetoken', (req, res) => {
    const refreshToken = req.body.token;
    if (refreshToken == null) return res.sendStatus(401);

    const sqlCheckToken = 'SELECT EXISTS(SELECT 1 FROM admintokens WHERE token = ?) AS `Exists`';
    db.query(sqlCheckToken, [refreshToken], (err, result) => {
        if (err) {
            console.error('Error checking refresh token: ', err);
            return res.status(500).json({ error: 'Internal server error' });
        }

        const tokenExists = result[0].Exists;
        if (!tokenExists) return res.sendStatus(403);

        const logData = `Admin-token generated successfully`;
        logUserActivity(logData);

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

router.delete('/logout', (req, res) => {
    const sqlDeleteToken = 'DELETE FROM admintokens WHERE token = ?';
    db.query(sqlDeleteToken, [req.body.token], (err, result) => {
        if (err) {
            console.error('Error deleting refresh token: ', err);
            return res.status(500).json({ error: 'Internal server error' });
        }

        const logData = `Admin-token deleted successfully`;
        logUserActivity(logData);

        res.sendStatus(204);
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

router.get('/', authenticateToken, (req, res) => {
    const adminID = req.admin.id;

    db.query('SELECT * FROM admins WHERE adminid = ?', [adminID], (error, results) => {
        if (error) {
            console.error('Error retrieving users: ', error);
            res.status(500).json({ error: 'Internal server error' });
        } else {
            res.json(results);
        }
    });
});

router.post('/login', (req, res) => {
    const adminID = req.body.adminid;
    const password = req.body.password;

    db.query('SELECT * FROM admins WHERE adminid = ? AND password = ?', [adminID, password], (error, results) => {
        if (error) {
            console.error('Error fetching user: ', error);
            return res.status(500).json({ error: 'Internal server error' });
        }

        if (results.length === 0) {
            return res.status(400).json({ error: 'User not found' });
        }

        const admin = { id: adminID };
        const accessToken = generateAccessToken(admin);
        const refreshToken = jwt.sign(admin, process.env.REFRESH_TOKEN_SECRET);

         let responseJson = { 
           accessToken: accessToken, 
           refreshToken: refreshToken, 
           message: 'Login Success' 
       };

       if ((results[0].access_level === 2)) {
           responseJson.accessLevel = "admin";
       }

        // Log user activity
        const logData = `Admin  -- ${adminID} -- logged in successfully`;
        logUserActivity(logData);

        const sqlInsertToken = 'INSERT INTO admintokens (adminid, token) VALUES (?, ?)';
        db.query(sqlInsertToken, [adminID, refreshToken], (err, result) => {
            if (err) {
                console.error('Error inserting refresh token: ', err);
                return res.status(500).json({ error: 'Internal server error' });
            }

           res.status(200).json(responseJson)
              
        });
    });
});


function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if (token == null) return res.sendStatus(401)

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, admin) => {
        if (err) return res.sendStatus(403)
        req.admin = admin
        next()
    })
}

function generateAccessToken(admin) {
    return jwt.sign(admin, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1d' });
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

//Leeeeave Requests

router.get('/pendingrequest', authenticateToken, (req, res) => {
    const adminID = req.admin.id;

    // First, check the user's access level and department
    db.query('SELECT access_level, department FROM admins WHERE adminid = ?', [adminID], (error, results) => {
        if (error) {
            console.error('Error retrieving user access level: ', error);
            res.status(500).json({ error: 'Internal server error' });
        } else {
            // If the user's access level is 5, perform the first query
            if (results[0].access_level === 1) {
                // If the user's access level is not 5, perform the second query
                db.query(`SELECT lr.userid, requestid, firstname, lastname, department, leaveid, reasonid, DATE_FORMAT(datefiled, '%m-%d-%Y') AS datefiled, middlename, salary, position, description, duration, inclusivedates, commutation, vacation, sickleave, deducted_vacation, deducted_sick, process_no, request_status, vacationCreds, sickCreds, datereceived, DATE_FORMAT(lb.updated_at, '%m-%d-%Y') AS updated_at FROM leaverequests lr join users u on lr.userid = u.userid join leavebalances lb on lr.userid = lb.userid WHERE process_no = 1 AND request_status = ? AND department = ? ORDER BY datefiled DESC LIMIT 300`, ['Pending', results[0].department], (error, results) => {
                    if (error) {
                        console.error('Error retrieving pending requests: ', error);
                        res.status(500).json({ error: 'Internal server error' });
                    } else {
                           // Decrypt each field of each user
                           results.forEach(user => {
                            user.lastname = decryptData(user.lastname, key);
                            user.firstname = decryptData(user.firstname, key);
                            user.middlename = decryptData(user.middlename, key);
                        });
                        res.json(results);
                    }
                });
            } else {
                db.query(`SELECT lr.userid, requestid, firstname, lastname, department, leaveid, reasonid, DATE_FORMAT(datefiled, '%m-%d-%Y') AS datefiled, middlename, salary, position, description, duration, inclusivedates, commutation, vacation, sickleave, deducted_vacation, deducted_sick, process_no, request_status, vacationCreds, sickCreds, datereceived, DATE_FORMAT(lb.updated_at, '%m-%d-%Y') AS updated_at FROM leaverequests lr join users u on lr.userid = u.userid join leavebalances lb on lr.userid = lb.userid WHERE request_status = ? AND process_no = 2 ORDER BY datefiled DESC LIMIT 300`, ['Pending'], (error, results) => {
                    if (error) {
                        console.error('Error retrieving pending requests: ', error);
                        res.status(500).json({ error: 'Internal server error' });
                    } else {
                           // Decrypt each field of each user
                           results.forEach(user => {
                            user.lastname = decryptData(user.lastname, key);
                            user.firstname = decryptData(user.firstname, key);
                            user.middlename = decryptData(user.middlename, key);
                        });

                        res.json(results);
                    }
                });
            }
        }
    });
});


router.get('/approvedrequest', authenticateToken, (req, res) => {
    const adminID = req.admin.id;

    // First, check the user's access level and department
    db.query('SELECT access_level, department FROM admins WHERE adminid = ?', [adminID], (error, results) => {
        if (error) {
            console.error('Error retrieving user access level: ', error);
            res.status(500).json({ error: 'Internal server error' });
        } else {
            // If the user's access level is 5, perform the first query
            if (results[0].access_level === 2) {
                db.query(`SELECT lr.userid, requestid, firstname, lastname, department, leaveid, reasonid, DATE_FORMAT(datefiled, '%m-%d-%Y') AS datefiled, middlename, salary, position, description, duration, inclusivedates, commutation, vacation, sickleave, deducted_vacation, deducted_sick, process_no, request_status, vacationCreds, sickCreds, datereceived, DATE_FORMAT(lb.updated_at, '%m-%d-%Y') AS updated_at FROM leaverequests lr join users u on lr.userid = u.userid join leavebalances lb on lr.userid = lb.userid WHERE request_status = ? ORDER BY datefiled DESC LIMIT 300`, ['Approved'], (error, results) => {
                    if (error) {
                        console.error('Error retrieving pending requests: ', error);
                        res.status(500).json({ error: 'Internal server error' });
                    } else {
                         // Decrypt each field of each user
                         results.forEach(user => {
                            user.lastname = decryptData(user.lastname, key);
                            user.firstname = decryptData(user.firstname, key);
                            user.middlename = decryptData(user.middlename, key);
                        });
                        res.json(results);
                    }
                });
            } else if (results[0].access_level === 1) {
                // If the user's access level is not 5, perform the second query
                db.query(`SELECT lr.userid, requestid, firstname, lastname, department, leaveid, reasonid, DATE_FORMAT(datefiled, '%m-%d-%Y') AS datefiled, middlename, salary, position, description, duration, inclusivedates, commutation, vacation, sickleave, deducted_vacation, deducted_sick, process_no, request_status, vacationCreds, sickCreds, datereceived, DATE_FORMAT(lb.updated_at, '%m-%d-%Y') AS updated_at FROM leaverequests lr join users u on lr.userid = u.userid join leavebalances lb on lr.userid = lb.userid WHERE request_status = ? AND department = ? ORDER BY datefiled DESC LIMIT 300`, ['Approved', results[0].department], (error, results) => {
                    if (error) {
                        console.error('Error retrieving pending requests: ', error);
                        res.status(500).json({ error: 'Internal server error' });
                    } else {
                         // Decrypt each field of each user
                         results.forEach(user => {
                            user.lastname = decryptData(user.lastname, key);
                            user.firstname = decryptData(user.firstname, key);
                            user.middlename = decryptData(user.middlename, key);
                        });
                        res.json(results);
                    }
                });
            }
        }
    });
});


router.get('/deniedrequest', authenticateToken, (req, res) => {
    const adminID = req.admin.id;

    // First, check the user's access level and department
    db.query('SELECT access_level, department FROM admins WHERE adminid = ?', [adminID], (error, results) => {
        if (error) {
            console.error('Error retrieving user access level: ', error);
            res.status(500).json({ error: 'Internal server error' });
        } else {
            // If the user's access level is 5, perform the first query
           if (results[0].access_level === 1) {
                // If the user's access level is not 5, perform the second query
                db.query(`SELECT lr.userid, requestid, firstname, lastname, department, leaveid, reasonid, DATE_FORMAT(datefiled, '%m-%d-%Y') AS datefiled, middlename, salary, position, description, duration, inclusivedates, commutation, vacation, sickleave, deducted_vacation, deducted_sick, process_no, request_status, vacationCreds, sickCreds, datereceived, DATE_FORMAT(lb.updated_at, '%m-%d-%Y') AS updated_at FROM leaverequests lr join users u on lr.userid = u.userid join leavebalances lb on lr.userid = lb.userid WHERE request_status = ? AND department = ? ORDER BY datefiled DESC`, ['Denied', results[0].department], (error, results) => {
                    if (error) {
                        console.error('Error retrieving pending requests: ', error);
                        res.status(500).json({ error: 'Internal server error' });
                    } else {
                         // Decrypt each field of each user
                         results.forEach(user => {
                            user.lastname = decryptData(user.lastname, key);
                            user.firstname = decryptData(user.firstname, key);
                            user.middlename = decryptData(user.middlename, key);
                        });
                        res.json(results);
                    }
                });
            } else {
                
                    db.query(`SELECT lr.userid, requestid, firstname, lastname, department, leaveid, reasonid, DATE_FORMAT(datefiled, '%m-%d-%Y') AS datefiled, middlename, salary, position, description, duration, inclusivedates, commutation, vacation, sickleave, deducted_vacation, deducted_sick, process_no, request_status, vacationCreds, sickCreds, datereceived, DATE_FORMAT(lb.updated_at, '%m-%d-%Y') AS updated_at FROM leaverequests lr join users u on lr.userid = u.userid join leavebalances lb on lr.userid = lb.userid WHERE request_status = ? ORDER BY datefiled DESC`, ['Denied'], (error, results) => {
                        if (error) {
                            console.error('Error retrieving pending requests: ', error);
                            res.status(500).json({ error: 'Internal server error' });
                        } else {
                             // Decrypt each field of each user
                           results.forEach(user => {
                            user.lastname = decryptData(user.lastname, key);
                            user.firstname = decryptData(user.firstname, key);
                            user.middlename = decryptData(user.middlename, key);
                        });
                            res.json(results);
                        }
                    });
               
            }
        }
    });
});

//Leave Request Filters
router.post('/reqdeptfilter', authenticateToken, (req, res) => {
    
    const {department, reqStatus} = req.body
    const adminID = req.admin.id;
 
    // First, check the user's access level and department
    db.query('SELECT access_level, department FROM admins WHERE adminid = ?', [adminID], (error, results) => {
        if (error) {
            console.error('Error retrieving user access level: ', error);
            res.status(500).json({ error: 'Internal server error' });
        } else {
            let sqlQuery = `SELECT requestid, firstname, lastname, department, leaveid, reasonid, DATE_FORMAT(datefiled, '%m-%d-%Y') AS datefiled, middlename, salary, position, description, duration, inclusivedates, commutation, vacation, sickleave, deducted_vacation, deducted_sick, process_no, request_status, vacationCreds, sickCreds, datereceived, DATE_FORMAT(lb.updated_at, '%m-%d-%Y') AS updated_at FROM leaverequests lr join users u on lr.userid = u.userid join leavebalances lb on lr.userid = lb.userid WHERE process_no = 2 AND request_status = ? AND department = ?`;
            let params = [reqStatus, department];
 
 
            if (results[0].access_level === 2) {
                sqlQuery += ' ORDER BY datefiled DESC';
                db.query(sqlQuery, params, (error, results) => {
                    if (error) {
                        console.error('Error retrieving filtered requests: ', error);
                        res.status(500).json({ error: 'Internal server error' });
                    } else {
                         // Decrypt each field of each user
                         results.forEach(user => {
                            user.lastname = decryptData(user.lastname, key);
                            user.firstname = decryptData(user.firstname, key);
                            user.middlename = decryptData(user.middlename, key);
                        });
                        res.json(results); // Add this line
                    }
                });
            } else if (results[0].access_level === 1) {
                // sqlQuery += ' AND department = ? ORDER BY datefiled DESC';
                sqlQuery += ' ORDER BY datefiled DESC';
                params.push(results[0].department);
                db.query(sqlQuery, params, (error, results) => {
                    if (error) {
                        console.error('Error retrieving filtered requests: ', error);
                        res.status(500).json({ error: 'Internal server error' });
                    } else {
                         // Decrypt each field of each user
                         results.forEach(user => {
                            user.lastname = decryptData(user.lastname, key);
                            user.firstname = decryptData(user.firstname, key);
                            user.middlename = decryptData(user.middlename, key);
                                });
                        res.json(results); // Add this line
                    }
                });
            }
        }
    });
 });
 

//request---EDIT
router.put('/update_req', authenticateToken, (req, res) => {
    const { requestid, leaveid, reasonid, description, inclusivedates, commutation, duration, request_status, datefiled, revert } = req.body;
    let updateRequestQueries = [];
    let requestQueryParams = [];

    if (leaveid !== undefined) {
        updateRequestQueries.push('leaveid = ?');
        requestQueryParams.push(leaveid);
    }
    if (reasonid !== undefined) {
        updateRequestQueries.push('reasonid = ?');
        requestQueryParams.push(reasonid);
    }
    if (description !== undefined) {
        updateRequestQueries.push('description = ?');
        requestQueryParams.push(description);
    }
    if (inclusivedates !== undefined) {
        updateRequestQueries.push('inclusivedates = ?');
        requestQueryParams.push(inclusivedates);
    }
    if (commutation !== undefined) {
        updateRequestQueries.push('commutation = ?');
        requestQueryParams.push(commutation);
    }
    if (duration !== undefined) {
        updateRequestQueries.push('duration = ?');
        requestQueryParams.push(duration);
    }
    if (request_status !== undefined) {
        updateRequestQueries.push('request_status = ?');
        requestQueryParams.push(request_status);
    }
    if (datefiled !== undefined) {
        updateRequestQueries.push('datefiled = ?');
        requestQueryParams.push(datefiled);
    }


    requestQueryParams.push(requestid);
    if (revert !== undefined) {
        let deleteQuery = `DELETE FROM leavecard WHERE requestid = ?`;
        db.query(deleteQuery, [requestid], (error, results) => {
          if (error) {
            console.error('Error deleting from leavecard: ', error);
          } else {
            console.log(`Deleted period and inclusivedates columns for ${results.affectedRows} rows from leavecard`);
          }
        });
      }

    if (updateRequestQueries.length > 0) {
        let query = `UPDATE leaverequests SET ${updateRequestQueries.join(', ')} WHERE requestid = ?`;
       
        const logData = `Update request initiated for requestid: ${requestid}`;
        logUserActivity(logData);
       
        db.query(query, requestQueryParams, handleUpdateResponse(res));
    }
});

function handleUpdateResponse(res) {
    return (error, results) => {
        if (error) {
            console.error('Error updating request: ', error);
            res.status(500).json({ error: 'Internal server error' });
        } else if (results.affectedRows === 0) {
            res.status(404).json({ error: 'Data not found' });
        } else {
            res.json({ success: true });
        }
    };
}

router.post('/reqfilter', authenticateToken, (req, res) => {
    
    const {year, month, reqStatus} = req.body
    const adminID = req.admin.id;
 
    // First, check the user's access level and department
    db.query('SELECT access_level, department FROM admins WHERE adminid = ?', [adminID], (error, results) => {
        if (error) {
            console.error('Error retrieving user access level: ', error);
            res.status(500).json({ error: 'Internal server error' });
        } else {
            let sqlQuery = `SELECT requestid, firstname, lastname, department, leaveid, reasonid, DATE_FORMAT(datefiled, '%m-%d-%Y') AS datefiled, middlename, salary, position, description, duration, inclusivedates, commutation, vacation, sickleave, deducted_vacation, deducted_sick, process_no, request_status, vacationCreds, sickCreds, datereceived, DATE_FORMAT(lb.updated_at, '%m-%d-%Y') AS updated_at FROM leaverequests lr join users u on lr.userid = u.userid join leavebalances lb on lr.userid = lb.userid WHERE request_status = ?`;
            let params = [reqStatus];
 
            if (year && month) {
                sqlQuery += ' AND DATE_FORMAT(datefiled, "%Y-%m") LIKE ?';
                params.push(`${year}-${month}%`);
            } else if (year) {
                sqlQuery += ' AND DATE_FORMAT(datefiled, "%Y") LIKE ?';
                params.push(`${year}%`);
            } else if (month) {
                sqlQuery += ' AND DATE_FORMAT(datefiled, "%m") LIKE ?';
                params.push(`${month}%`);
            }
 
            if (results[0].access_level === 2) {
                sqlQuery += ' ORDER BY datefiled DESC';
                db.query(sqlQuery, params, (error, results) => {
                    if (error) {
                        console.error('Error retrieving filtered requests: ', error);
                        res.status(500).json({ error: 'Internal server error' });
                    } else {
                         // Decrypt each field of each user
                         results.forEach(user => {
                            user.lastname = decryptData(user.lastname, key);
                            user.firstname = decryptData(user.firstname, key);
                            user.middlename = decryptData(user.middlename, key);
                        });
                        res.json(results); // Add this line
                    }
                });
            } else if (results[0].access_level === 1) {
                sqlQuery += ' AND department = ? ORDER BY datefiled DESC';
                params.push(results[0].department);
                db.query(sqlQuery, params, (error, results) => {
                    if (error) {
                        console.error('Error retrieving filtered requests: ', error);
                        res.status(500).json({ error: 'Internal server error' });
                    } else {
                         // Decrypt each field of each user
                         results.forEach(user => {
                            user.lastname = decryptData(user.lastname, key);
                            user.firstname = decryptData(user.firstname, key);
                            user.middlename = decryptData(user.middlename, key);
                        });
                        res.json(results); // Add this line
                    }
                });
            }
        }
    });
 });
 
 router.get('/getAdmins', authenticateToken, (req, res) => {
    const adminID = req.admin.id;

    // First, check the user's access level and department
    db.query('SELECT access_level, department FROM admins WHERE adminid = ?', [adminID], (error, results) => {
        if (error) {
            console.error('Error retrieving user access level: ', error);
            res.status(500).json({ error: 'Internal server error' });
        } else {
            // If the user's access level is 5, perform the first query
            if (results[0].access_level === 2) {
                db.query('SELECT adminid, password, lastname, firstname, middlename, contactnumber, department, access_level FROM admins LIMIT 0, 300', (error, results) => {
                    if (error) {
                        console.error('Error retrieving users: ', error);
                        res.status(500).json({ error: 'Internal server error' });
                    } else {
                                // Decrypt each field of each user
                    results.forEach(user => {
                        user.lastname = decryptData(user.lastname, key);
                        user.firstname = decryptData(user.firstname, key);
                        user.middlename = decryptData(user.middlename, key);
                        user.contactnumber = decryptData(user.contactnumber, key);
                    });
                    res.json(results);
                    }
                });
            }
        }
    });
});

router.get('/getUsers', authenticateToken, (req, res) => {
    const adminID = req.admin.id;

    // First, check the user's access level and department
    db.query('SELECT access_level, department FROM admins WHERE adminid = ?', [adminID], (error, results) => {
        if (error) {
            console.error('Error retrieving user access level: ', error);
            res.status(500).json({ error: 'Internal server error' });
        } else {
            // If the user's access level is 5, perform the first query
            if (results[0].access_level === 1) {
                // If the user's access level is not 5, perform the second query
                db.query('SELECT u.userid, u.password, u.lastname, u.firstname, u.middlename, u.department, u.position, u.salary, u.contactnumber, lb.vacation, lb.sickleave, lb.special_privilege_leave, lb.forcedleave, lb.solo_parent_leave FROM users u JOIN leavebalances lb ON u.userid = lb.userid WHERE u.department = ? LIMIT 0, 300', [results[0].department], (error, results) => {
                    if (error) {
                        console.error('Error retrieving users: ', error);
                        res.status(500).json({ error: 'Internal server error' });
                    } else {
                        // Decrypt each field of each user
                        results.forEach(user => {
                            user.lastname = decryptData(user.lastname, key);
                            user.firstname = decryptData(user.firstname, key);
                            user.middlename = decryptData(user.middlename, key);
                            user.contactnumber = decryptData(user.contactnumber, key);
                        });
                        res.json(results);
                    }
                });
            } else {
                db.query('SELECT u.userid, u.password, u.lastname, u.firstname, u.middlename, u.department, u.position, u.salary, u.contactnumber, lb.vacation, lb.sickleave, lb.special_privilege_leave, lb.forcedleave, lb.solo_parent_leave FROM users u JOIN leavebalances lb ON u.userid = lb.userid LIMIT 0, 300', (error, results) => {
                    if (error) {
                        console.error('Error retrieving users: ', error);
                        res.status(500).json({ error: 'Internal server error' });
                    } else {
                                // Decrypt each field of each user
                    results.forEach(user => {
                        user.lastname = decryptData(user.lastname, key);
                        user.firstname = decryptData(user.firstname, key);
                        user.middlename = decryptData(user.middlename, key);
                        user.contactnumber = decryptData(user.contactnumber, key);
                    });
                    res.json(results);
                    }
                });
            }
        }
    });
});
  //User Filters-Register-- Edit

router.post('/filteruser', authenticateToken, (req, res) => {
      const {department, reqStatus} = req.body
    const adminID = req.admin.id;
  
      // First, check the user's access level and department
      db.query('SELECT access_level, department FROM admins WHERE adminid = ?', [adminID], (error, results) => {
          if (error) {
              console.error('Error retrieving user access level: ', error);
              res.status(500).json({ error: 'Internal server error' });
          } else {
              // If the user's access level is 5, perform the first query
              if (results[0].access_level === 1) {
                db.query('SELECT u.userid, u.password, u.lastname, u.firstname, u.middlename, u.department, u.position, u.salary, u.contactnumber, lb.vacation, lb.sickleave, lb.special_privilege_leave, lb.forcedleave, lb.solo_parent_leave FROM users u join leavebalances lb on u.userid = lb.userid WHERE department = ?', [department], (error, results) => {
                    if (error) {
                        console.error('Error retrieving users: ', error);
                        res.status(500).json({ error: 'Internal server error' });
                    } else {
                         // Decrypt each field of each user
                         results.forEach(user => {
                            user.lastname = decryptData(user.lastname, key);
                            user.firstname = decryptData(user.firstname, key);
                            user.middlename = decryptData(user.middlename, key);
                        user.contactnumber = decryptData(user.contactnumber, key);

                        });
                        res.json(results);
                    }
                });
              } else if (results[0].access_level === 2) {
                  // If the user's access level is not 5, perform the second query
                  db.query('SELECT u.userid, u.password, u.lastname, u.firstname, u.middlename, u.department, u.position, u.salary, u.contactnumber, lb.vacation, lb.sickleave, lb.special_privilege_leave, lb.forcedleave, lb.solo_parent_leave FROM users u join leavebalances lb on u.userid = lb.userid where department = ?', [department], (error, results) => {
                    if (error) {
                        console.error('Error retrieving users: ', error);
                        res.status(500).json({ error: 'Internal server error' });
                    } else {
                         // Decrypt each field of each user
                         results.forEach(user => {
                            user.lastname = decryptData(user.lastname, key);
                            user.firstname = decryptData(user.firstname, key);
                            user.middlename = decryptData(user.middlename, key);
                        user.contactnumber = decryptData(user.contactnumber, key);

                        });
                        res.json(results);
                    }
                });
              }
          }
      });
  });


  router.post('/leave_history', authenticateToken, (req, res) => {
    const adminID = req.admin.id;
    const {userid} = req.body

    // First, check the user's access level and department
    db.query('SELECT access_level, department FROM admins WHERE adminid = ?', [adminID], (error, results) => {
        if (error) {
            console.error('Error retrieving user access level: ', error);
            res.status(500).json({ error: 'Internal server error' });
        } else {
            
                db.query(`SELECT lr.userid, requestid, firstname, lastname, department, leaveid, reasonid, DATE_FORMAT(datefiled, '%m-%d-%Y') AS datefiled, middlename, salary, position, description, duration, inclusivedates, commutation, vacation, sickleave, deducted_vacation, deducted_sick, process_no, request_status, vacationCreds, sickCreds, datereceived, DATE_FORMAT(lb.updated_at, '%m-%d-%Y') AS updated_at FROM leaverequests lr join users u on lr.userid = u.userid join leavebalances lb on lr.userid = lb.userid WHERE lr.userid = ? ORDER BY datefiled DESC LIMIT 300`, [userid], (error, results) => {
                    if (error) {
                        console.error('Error retrieving pending requests: ', error);
                        res.status(500).json({ error: 'Internal server error' });
                    } else {
                         // Decrypt each field of each user
                         results.forEach(user => {
                            user.lastname = decryptData(user.lastname, key);
                            user.firstname = decryptData(user.firstname, key);
                            user.middlename = decryptData(user.middlename, key);
                        });
                        res.json(results);
                    }
                });
            
        }
    });
});

router.put('/update_admin', authenticateToken, (req, res) => {
    const { adminid, password, lastname, firstname, middlename, contactnumber, department, access_level } = req.body;
    let updateAdminQueries = [];
    let adminQueryParams = [];

    if (lastname !== undefined) {
        updateAdminQueries.push('lastname = ?');
        const encryptedLastname = encryptData(lastname, key);
        adminQueryParams.push(encryptedLastname);
    }
    if (firstname !== undefined) {
        updateAdminQueries.push('firstname = ?');
         const encryptedFirstname = encryptData(firstname, key);
        adminQueryParams.push(encryptedFirstname);
    }
    if (middlename !== undefined) {
        updateAdminQueries.push('middlename = ?');
        const encryptedMiddlename = encryptData(middlename, key);
        adminQueryParams.push(encryptedMiddlename);
    }
    if (password !== undefined) {
        updateAdminQueries.push('password = ?');
        adminQueryParams.push(password);
    }
    if (department !== undefined) {
        updateAdminQueries.push('department = ?');
        adminQueryParams.push(department);
    }
    if (contactnumber !== undefined) {
        updateAdminQueries.push('contactnumber = ?');
        const encryptedContactnumber = encryptData(contactnumber, key);
        adminQueryParams.push(encryptedContactnumber);
    }
    if (access_level !== undefined) {
        updateAdminQueries.push('access_level = ?');
        adminQueryParams.push(access_level);
    }
    
    adminQueryParams.push(adminid);

    if (updateAdminQueries.length > 0) {
        let query = `UPDATE admins SET ${updateAdminQueries.join(', ')} WHERE adminid = ?`;
          // Log the update user request
          const logData = `User modification initiated for admin: ${adminid}`;
          logUserActivity(logData);


        db.query(query, adminQueryParams, handleUpdateResponse(res));
    }

});

  router.put('/update_user', authenticateToken, (req, res) => {
    const { userid, lastname, firstname, middlename, password, department, position, salary, contactnumber, vacation, sickleave, forcedleave, special_privilege_leave, solo_parent_leave } = req.body;
    let updateUserQueries = [];
    let updateLeaveQueries = [];
    let userQueryParams = [];
    let leaveQueryParams = [];

    if (lastname !== undefined) {
        updateUserQueries.push('lastname = ?');
        const encryptedLastname = encryptData(lastname, key);
        userQueryParams.push(encryptedLastname);
    }
    if (firstname !== undefined) {
        updateUserQueries.push('firstname = ?');
         const encryptedFirstname = encryptData(firstname, key);
        userQueryParams.push(encryptedFirstname);
    }
    if (middlename !== undefined) {
        updateUserQueries.push('middlename = ?');
        const encryptedMiddlename = encryptData(middlename, key);
        userQueryParams.push(encryptedMiddlename);
    }
    if (password !== undefined) {
        updateUserQueries.push('password = ?');
        userQueryParams.push(password);
    }
    if (department !== undefined) {
        updateUserQueries.push('department = ?');
        userQueryParams.push(department);
    }
    if (position !== undefined) {
        updateUserQueries.push('position = ?');
        userQueryParams.push(position);
    }
    if (salary !== undefined) {
        updateUserQueries.push('salary = ?');
        userQueryParams.push(salary);
    }
    if (contactnumber !== undefined) {
        updateUserQueries.push('contactnumber = ?');
        const encryptedContactnumber = encryptData(contactnumber, key);
        userQueryParams.push(encryptedContactnumber);
    }

    if (vacation !== undefined) {
        updateLeaveQueries.push('vacation = ?');
        leaveQueryParams.push(vacation);
    }
    if (sickleave !== undefined) {
        updateLeaveQueries.push('sickleave = ?');
        leaveQueryParams.push(sickleave);
    }
    if (forcedleave !== undefined) {
        updateLeaveQueries.push('forcedleave = ?');
        leaveQueryParams.push(forcedleave);
    }
    if (special_privilege_leave !== undefined) {
        updateLeaveQueries.push('special_privilege_leave = ?');
        leaveQueryParams.push(special_privilege_leave);
    }
    if (solo_parent_leave !== undefined) {
        updateLeaveQueries.push('solo_parent_leave = ?');
        leaveQueryParams.push(solo_parent_leave);
    }
    userQueryParams.push(userid);
    leaveQueryParams.push(userid);

    if (updateUserQueries.length > 0) {
        let query = `UPDATE users SET ${updateUserQueries.join(', ')} WHERE userid = ?`;
          // Log the update user request
          const logData = `User modification initiated for userid: ${userid}`;
          logUserActivity(logData);


        db.query(query, userQueryParams, handleUpdateResponse(res));
    }

    if (updateLeaveQueries.length > 0) {
        let query = `UPDATE leavebalances SET ${updateLeaveQueries.join(', ')} WHERE userid = ?`;

        // Log the update user request
        const logData = `User modification initiated for userid: ${userid}`;
        logUserActivity(logData);

        db.query(query, leaveQueryParams, handleUpdateResponse(res));
    }
});

function handleUpdateResponse(res) {
    return (error, results) => {
        if (error) {
            console.error('Error updating user: ', error);
            res.status(500).json({ error: 'Internal server error' });
        } else if (results.affectedRows === 0) {
            res.status(404).json({ error: 'Data not found' });
        } else {
            res.json({ success: true });
        }
    };
}

  //users ---------------end---------

  //Register-------------------------------
  router.post('/registeruser', (req, res) => {
    const { password, lastname, firstname, middlename, department, position, salary, contactnumber, vacation, sickleave, forcedleave, special_privilege_leave, solo_parent_leave } = req.body;
 
    // Please ensure proper data validation before inserting into database
    if (!lastname || !password) {
        return res.status(400).json({ error: 'Required fields' });
    }
 
    const encryptedPassword = password;
    const encryptedLastname = encryptData(lastname, key);
    const encryptedFirstname = encryptData(firstname, key);
    const encryptedMiddlename = encryptData(middlename, key);
    const encryptedDepartment = department;
    const encryptedPosition = position;
    const encryptedContactnumber = encryptData(contactnumber, key);
  console.log(encryptedPassword);

    const userInsertQuery = 'INSERT INTO users (password, lastname, firstname, middlename, department, position, salary, contactnumber) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
    const userInsertValues = [encryptedPassword, encryptedLastname, encryptedFirstname, encryptedMiddlename, encryptedDepartment, encryptedPosition, salary, encryptedContactnumber];


        // Log the user registration
        const logData = `User registration initiated for lastname: ${lastname}, firstname: ${firstname}`;
        logUserActivity(logData);


    db.query(userInsertQuery, userInsertValues, (error, results) => {
        if (error) {
            console.error('Error inserting user: ', error);
            res.status(500).json({ error: 'Internal server error' });
        } else {
            const userId = results.insertId;
            const leaveBalanceInsertQuery = 'INSERT INTO leavebalances (userid, vacation, sickleave, forcedleave, special_privilege_leave, solo_parent_leave, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW())';
            const leaveBalanceInsertValues = [userId, vacation, sickleave, forcedleave, special_privilege_leave, solo_parent_leave];
            
            db.query(leaveBalanceInsertQuery, leaveBalanceInsertValues, (error, results) => {
                if (error) {
                   console.error('Error inserting leave balance: ', error);
                   res.status(500).json({ error: 'Internal server error' });
                } else {
                   res.status(201).json({ message: 'User registered successfully', userId: userId });
                }
            });
        }
    });
 });
 
 //Admin--register

 router.post('/registeradmin', (req, res) => {
   
    const { password, lastname, firstname, middlename, contactnumber, department, access_level } = req.body;
 
    // Please ensure proper data validation before inserting into database
    if (!lastname || !password) {
        return res.status(400).json({ error: 'Required fields' });
    }
    const encryptedPassword = password;
    const encryptedLastname = encryptData(lastname, key);
    const encryptedFirstname = encryptData(firstname, key);
    const encryptedMiddlename = encryptData(middlename, key);
    const encryptedDepartment = department;
    const encryptedContactnumber = encryptData(contactnumber, key);
  console.log(encryptedPassword);

    const adminRegisterQuery = 'INSERT INTO admins (password, lastname, firstname, middlename, contactnumber, department, access_level) VALUES (?, ?, ?, ?, ?, ?, ?)';
    const adminRegisterValues = [encryptedPassword, encryptedLastname, encryptedFirstname, encryptedMiddlename, encryptedContactnumber, encryptedDepartment, access_level];
 
    // Log the admin registration
    const logData = `Admin registration initiated for lastname: ${lastname}, firstname: ${firstname}`;
    logUserActivity(logData);


    db.query(adminRegisterQuery, adminRegisterValues, (error, results) => {
        if (error) {
            console.error('Error inserting admin: ', error);
            res.status(500).json({ error: 'Internal server error' });
        } else {
            const adminId = results.insertId;
            res.status(201).json({ message: 'Admin registered successfully', adminId: adminId });
        }
    });
    
 });

//Leave Credits & Leave Card

router.get('/getCredits', (req, res) => {
    db.query('SELECT leavebalances.userid, firstname, lastname, vacation, sickleave, forcedleave, special_privilege_leave, solo_parent_leave FROM users JOIN leavebalances ON users.userid = leavebalances.userid', (error, results) => {
        if (error) {
            console.error('Error retrieving Data: ', error);
            res.status(500).json({ error: 'Internal server error' });
        } else {
             // Decrypt each field of each user
             results.forEach(user => {
                user.lastname = decryptData(user.lastname, key);
                user.firstname = decryptData(user.firstname, key);
            });
            res.json(results);
        }
    });
  });

  
  router.get('/getusercredits/:userid', (req, res) => {
    const param = req.params.userid;

    db.query('SELECT leavebalances.userid, firstname, lastname, vacation, sickleave, forcedleave, special_privilege_leave, solo_parent_leave FROM users JOIN leavebalances ON users.userid = leavebalances.userid where users.userid = ?', [param], (error, results) => {
        if (error) {
            console.error('Error retrieving Data: ', error);
            res.status(500).json({ error: 'Internal server error' });
        } else {
             // Decrypt each field of each user
             results.forEach(user => {
                user.lastname = decryptData(user.lastname, key);
                user.firstname = decryptData(user.firstname, key);
            });
            res.json(results);
        }
    });
  });
  
  router.get('/leavecard_data/:userid', (req, res) => {

    const param = req.params.userid;
    db.query(`SELECT u.userid, u.lastname, u.firstname, u.department, recordid, rownum, period, particulars, actiontaken, vacleave_earned, sickleave_earned, vactardy, sicktardy, VL, FL, vacWOP, sickWOP, Vacbal, Sickbal, SPL, SOL, MAL, PAL, MCW, RPL, SEL, note, DATE_FORMAT(created_at, '%m-%d-%Y') AS created_at FROM users u join leavecard lc on u.userid = lc.userid where u.userid = ?`, [param], (error, results) => {
        if (error) {
            console.error('Error retrieving users: ', error);
            res.status(500).json({ error: 'Internal server error' });
        } else {
            if (results.length === 0) {
                // If empty, query only for userid, lastname, firstname, and department
                db.query('SELECT u.userid, u.lastname, u.firstname, u.department FROM users u WHERE u.userid = ?', [param], (error, results) => {
                    if (error) {
                        console.error('Error retrieving user details: ', error);
                        res.status(500).json({ error: 'Internal server error' });
                    } else {
                        // Decrypt each field of each user
                        results.forEach(user => {
                            user.lastname = decryptData(user.lastname, key);
                            user.firstname = decryptData(user.firstname, key);
                        });
                        res.json(results);
                    }
                });
            } else {

             // Decrypt each field of each user
             results.forEach(user => {
                user.lastname = decryptData(user.lastname, key);
                user.firstname = decryptData(user.firstname, key);
            });
            res.json(results);

        }

        }
    });
  });
  
  
  router.post('/leavecard_req', (req, res) => {
    const rows = req.body; // This should be an array of objects
    let errors = [];
    
    rows.forEach((row) => {
      const { userid, rownum, period, particulars, actiontaken, vacleave_earned, sickleave_earned, vactardy, sicktardy, VL, FL, vacWOP, sickWOP, Vacbal, Sickbal, SPL, SOL, MAL, PAL, MCW, RPL, SEL, note  } = row;
   
      // Build the SET part of the query
      let setClause = '';
      let values = [];
      if (period !== undefined) {
        setClause += 'period = ?, ';
        values.push(period);
      }
      if (particulars !== undefined) {
        setClause += 'particulars = ?, ';
        values.push(particulars);
      }
       if (actiontaken !== undefined) {
        setClause += 'actiontaken = ?, ';
        values.push(actiontaken);
      }
   
       if (vacleave_earned !== undefined) {
        setClause += 'vacleave_earned = ?, ';
        values.push(vacleave_earned);
      }
      
        if (sickleave_earned !== undefined) {
        setClause += 'sickleave_earned = ?, ';
        values.push(sickleave_earned);
      }
   
       if (vactardy !== undefined) {
        setClause += 'vactardy = ?, ';
        values.push(vactardy);
      }
      
        if (sicktardy !== undefined) {
        setClause += 'sicktardy = ?, ';
        values.push(sicktardy);
      }
   
       if (VL !== undefined) {
        setClause += 'VL = ?, ';
        values.push(VL);
      }
      
       if (FL !== undefined) {
        setClause += 'FL = ?, ';
        values.push(FL);
      }
   
       if (vacWOP !== undefined) {
        setClause += 'vacWOP = ?, ';
        values.push(vacWOP);
      }
   
   
       if (sickWOP !== undefined) {
        setClause += 'sickWOP = ?, ';
        values.push(sickWOP);
      }
   
   
       if (Vacbal !== undefined) {
        setClause += 'Vacbal = ?, ';
        values.push(Vacbal);
      }
      
   
       if (Sickbal !== undefined) {
        setClause += 'Sickbal = ?, ';
        values.push(Sickbal);
      }
      
      if (SPL !== undefined) {
       setClause += 'SPL = ?, ';
       values.push(SPL);
     }

     if (SOL !== undefined) {
        setClause += 'SOL = ?, ';
        values.push(SOL);
      }
      
     if (MAL !== undefined) {
        setClause += 'MAL = ?, ';
        values.push(MAL);
      }

      if (PAL !== undefined) {
        setClause += 'PAL = ?, ';
        values.push(PAL);
      }

      if (MCW !== undefined) {
        setClause += 'MCW = ?, ';
        values.push(MCW);
      }

      if (RPL !== undefined) {
        setClause += 'RPL = ?, ';
        values.push(RPL);
      }
     
      if (SEL !== undefined) {
        setClause += 'SEL = ?, ';
        values.push(SEL);
      }
      
     if (note !== undefined) {
        setClause += 'note = ?, ';
        values.push(note);
      }
      // Remove trailing comma and space
      setClause = setClause.slice(0, -2);
   
       // Try to find the record
   db.query('SELECT * FROM leavecard WHERE userid = ? AND rownum = ?', [userid, rownum], (error, results) => {
    if (error) {
      console.error('Error retrieving user: ', error);
      errors.push('Error retrieving user');
    } else {
      // If the record exists, update it
      if (results.length > 0) {

        // Log the insert action
        const logData = `Attempting to update leavecard for userid: ${userid}, @row: ${rownum}.`;
        logUserActivity(logData);

        db.query(`UPDATE leavecard SET ${setClause} WHERE userid = ? AND rownum = ?`, [...values, userid, rownum], (error, results) => {
          if (error) {
            console.error('Error updating user: ', error);
            errors.push('Error updating user');
          }
        });
      } else {
        // If the record doesn't exist, insert it
        const logData = `Inserting new leavecard record for userid: ${userid}, @row: ${rownum}.`;
        logUserActivity(logData);

        db.query('INSERT IGNORE INTO leavecard (userid, rownum, period, particulars, actiontaken, vacleave_earned, sickleave_earned, vactardy, sicktardy, VL, FL, vacWOP, sickWOP, Vacbal, Sickbal, SPL, SOL, MAL, PAL, MCW, RPL, SEL, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [userid, rownum, period, particulars, actiontaken, vacleave_earned, sickleave_earned, vactardy, sicktardy, VL, FL, vacWOP, sickWOP, Vacbal, Sickbal, SPL, SOL, MAL, PAL, MCW, RPL, SEL, note], (error, results) => {
          if (error) {
            console.error('Error inserting user: ', error);
            errors.push('Error inserting user');
          }
        });
      }
    }
  });
});

// Send a single response after all operations have completed
res.json({ message: errors.length > 0 ? 'Errors occurred: ' + errors.join(', ') : 'Rows processed successfully' });
});
  
  
//----------
router.post('/Lcinsertreq', (req, res) => {
    const { userid, requestid, leaveid, inclusivedates, duration, Vacbal, Sickbal, year } = req.body;
    const period = inclusivedates;
    let leavetype = ''; // Initialize leavetype variable
    let actiontaken = ''; // Initialize actiontaken variable
    const vacleave_earned = 0, sickleave_earned = 0, vactardy = 0, sicktardy = 0, VL = 0, FL = 0, vacWOP = 0, sickWOP = 0, SPL = 0, SOL = 0, MAL = 0, PAL = 0, MCW = 0, RPL = 0, SEL = 0, note = '';

    let errors = [];

    // Execute the SELECT query to get the latest rownum AND year = ?
    db.query('SELECT rownum FROM leavecard WHERE userid = ? ORDER BY rownum DESC LIMIT 1', [userid], (err, result) => {
        if (err) {
            console.error(err);
            errors.push(err.message);
            res.json({ message: 'Errors occurred: ' + errors.join(', ') });
            return;
        }
        let rownum; // Default value or handle accordingly

        // Check if the result set is empty
        if (result.length === 0) {
            // Handle the case where no rows were returned
            // For example, set a default value for rownum or send an error response
            rownum = 1; // Default value or handle accordingly
        } else {
            rownum = result[0].rownum + 1;
        }


        // Define the base query
        const baseQuery = `INSERT INTO leavecard (userid, rownum, period, particulars, actiontaken, vacleave_earned, sickleave_earned, vactardy, sicktardy, VL, FL, vacWOP, sickWOP, Vacbal, Sickbal, SPL, SOL, MAL, PAL, MCW, RPL, SEL, note, requestid) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

        // Create an object to hold the values for the base query
        const baseValues = {
            userid, rownum, period, particulars: '', actiontaken, vacleave_earned, sickleave_earned, vactardy, sicktardy, VL, FL, vacWOP, sickWOP, Vacbal, Sickbal, SPL, SOL, MAL, PAL, MCW, RPL, SEL, note, requestid
        };

        // Format the duration value
        const durationParts = duration.toString().split('.');
        const days = parseInt(durationParts[0]);
        const hours = durationParts[1] ? Math.floor((parseFloat('0.' + durationParts[1]) * 8)) : 0;
        const minutes = Math.round((parseFloat('0.' + durationParts[1]) * 8 - hours) * 60);
        const formattedDuration = `(${days}.${String(hours).padStart(2, '0')}.${String(minutes).padStart(2, '0')})`;

        // Set the leavetype and other values based on leaveid
        switch (leaveid) {
            case '1':
                leavetype = 'Vacation Leave';
                baseValues.VL = duration;
                break;
            case '2':
                leavetype = 'Mandatory/Forced Leave';
                baseValues.FL = duration;
                break;
            case '3':
                leavetype = 'Sick Leave';
                baseValues.sicktardy = duration;
                break;
            case '4':
                leavetype = 'Maternity Leave';
                baseValues.MAL = duration;
                break;
            case '5':
                leavetype = 'Paternity Leave';
                baseValues.PAL = duration;
                break;
            case '6':
                leavetype = 'Special Privilege Leave';
                baseValues.SPL = duration;
                break;
            case '7':
                leavetype = 'Solo Parent Leave';
                baseValues.SOL = duration;
                break;
            case '8':
                leavetype = 'Study Leave';
                baseValues.note = "SL-" + duration;
                break;
            case '9':
                leavetype = '10-Day VAWC';
                baseValues.note = "VAWC-" + duration;
                break;
            case '10':
                leavetype = 'Rehabilitation Privilege';
                baseValues.RPL = duration;
                break;
            case '11':
                leavetype = 'Magna Carta for Women';
                baseValues.MCW = duration;
                break;
            case '12':
                leavetype = 'Special Emergency Leave';
                baseValues.SEL = duration;
                break;
            case '13':
                leavetype = 'Emergency Leave';
                baseValues.note = "SEL-" + duration;
                break;
            case '14':
                leavetype = 'Monetization';
                baseValues.VL = duration;
                break;
            case '15':
                leavetype = 'Terminal Leave';
                baseValues.note = "TL-" + duration;
                break;
            default:
                leavetype = 'Others';
                baseValues.note = duration;
        }

        // Set the particulars and actiontaken values
        baseValues.particulars = `${formattedDuration} - ${leavetype}`;
        actiontaken = `A- ${leavetype} (${duration}) #${requestid}`;
        baseValues.actiontaken = actiontaken;

        // Log the leave card request insertion
        const logData = `Inserting leave card request for userid: ${userid}, period: ${period}, leavetype: ${leavetype}, duration: ${duration}`;
        logUserActivity(logData);


        // Execute the INSERT query
        db.query(baseQuery, Object.values(baseValues), (err, result) => {
            if (err) {
                console.error(err);
                errors.push(err.message);
            }

             // Check if rownum is divisible by 4
             if (rownum % 4 === 0) {
                rownum++; // Increment rownum

                // Define the emptyPeriodQuery
                const emptyPeriodQuery = `INSERT INTO leavecard (userid, rownum, period) VALUES (?, ?, ?)`;

                // Execute the emptyPeriodQuery with only userid, rownum, and an empty period
                db.query(emptyPeriodQuery, [userid, rownum, ''], (err, result) => {
                    if (err) {
                        console.error(err);
                        errors.push(err.message);
                    }
                });
            }

            // Send a response
            res.json({ message: errors.length > 0 ? 'Errors occurred: ' + errors.join(', ') : 'Rows processed successfully' });
        });
    });
});

router.post('/Lcinsertdtr', (req, res) => {
    const { userid, period, particulars, vacleave_earned, sickleave_earned, vactardy, sicktardy, Vacbal, Sickbal, vacWOP, sickWOP, year } = req.body;

    let errors = [];

    // Execute the SELECT query to get the latest rownum AND year = ?
    db.query('SELECT rownum FROM leavecard WHERE userid = ? ORDER BY rownum DESC LIMIT 1', [userid], (err, result) => {
        if (err) {
            console.error(err);
            errors.push(err.message);
            res.json({ message: 'Errors occurred: ' + errors.join(', ') });
            return;
        }
        let rownum; // Default value or handle accordingly

        // Check if the result set is empty
        if (result.length === 0) {
            // Handle the case where no rows were returned
            // For example, set a default value for rownum or send an error response
            rownum = 1; // Default value or handle accordingly
        } else {
            rownum = result[0].rownum + 1;
        }

        const baseQuery = `INSERT INTO leavecard (userid, rownum, period, particulars, vacleave_earned, sickleave_earned, vactardy, sicktardy, Vacbal, Sickbal, vacWOP, sickWOP) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

        // Create an object to hold the values for the base query
        const baseValues = {
            userid, rownum, period, particulars, vacleave_earned, sickleave_earned, vactardy, sicktardy, Vacbal, Sickbal, vacWOP, sickWOP
        };

        // Log the detailed transaction insertion
        const logData = `Inserting data from DTR for userid: ${userid}, period: ${period}, particulars: ${particulars}`;
        logUserActivity(logData);

        // Execute the INSERT query
        db.query(baseQuery, Object.values(baseValues), (err, result) => {
            if (err) {
                console.error(err);
                errors.push(err.message);
            }

            // Check if rownum is divisible by 4
            if (rownum % 4 === 0) {
                rownum++; // Increment rownum

                // Define the emptyPeriodQuery
                const emptyPeriodQuery = `INSERT INTO leavecard (userid, rownum, period) VALUES (?, ?, ?)`;

                // Execute the emptyPeriodQuery with only userid, rownum, and an empty period
                db.query(emptyPeriodQuery, [userid, rownum, ''], (err, result) => {
                    if (err) {
                        console.error(err);
                        errors.push(err.message);
                    }
                });
            }
            // Send a response
            res.json({ message: errors.length > 0 ? 'Errors occurred: ' + errors.join(', ') : 'Rows processed successfully' });
        });
    });
});

//-----------
//Leave Credits --Filters

router.post('/creditsdeptfilter', authenticateToken, (req, res) => {
   
    const {department} = req.body
    const adminID = req.admin.id;
 
    // First, check the user's access level and department
    db.query('SELECT access_level, department FROM admins WHERE adminid = ?', [adminID], (error, results) => {
        if (error) {
            console.error('Error retrieving user access level: ', error);
            res.status(500).json({ error: 'Internal server error' });
        } else {
            let sqlQuery = 'SELECT lb.userid, firstname, lastname, department, middlename, salary, position, contactnumber, vacation, sickleave FROM leavebalances lb join users u on lb.userid = u.userid';            
            let params = [department];
 
 
            if (results[0].access_level === 2) {
                sqlQuery += '';
                db.query(sqlQuery, params, (error, results) => {
                    if (error) {
                        console.error('Error retrieving filtered requests: ', error);
                        res.status(500).json({ error: 'Internal server error' });
                    } else {
                         // Decrypt each field of each user
                         results.forEach(user => {
                            user.lastname = decryptData(user.lastname, key);
                            user.firstname = decryptData(user.firstname, key);
                            user.middlename = decryptData(user.middlename, key);
                              user.contactnumber = decryptData(user.contactnumber, key);

                        });
                        res.json(results); 
                    }
                });
            } else if (results[0].access_level === 1) {
                // sqlQuery += ' AND department = ? ORDER BY datefiled DESC';
                sqlQuery += 'WHERE department = ?';
                params.push(results[0].department);
                db.query(sqlQuery, params, (error, results) => {
                    if (error) {
                        console.error('Error retrieving filtered requests: ', error);
                        res.status(500).json({ error: 'Internal server error' });
                    } else {
                         // Decrypt each field of each user
                         results.forEach(user => {
                            user.lastname = decryptData(user.lastname, key);
                            user.firstname = decryptData(user.firstname, key);
                            user.middlename = decryptData(user.middlename, key);
                            user.contactnumber = decryptData(user.contactnumber, key);

                                });
                        res.json(results); // Add this line
                    }
                });
            }
        }
    });
 });

 //Reports-- Filters

router.get('/reportreq', authenticateToken, (req, res) => {
    const adminID = req.admin.id;

    // First, check the user's access level and department
    db.query('SELECT access_level, department FROM admins WHERE adminid = ?', [adminID], (error, results) => {
        if (error) {
            console.error('Error retrieving user access level: ', error);
            res.status(500).json({ error: 'Internal server error' });
        } else {
            // If the user's access level is 5, perform the first query
            if (results[0].access_level === 2) {
                db.query(`SELECT requestid, firstname, lastname, department, leaveid, reasonid, DATE_FORMAT(datefiled, '%m-%d-%Y') AS datefiled, middlename, salary, position, contactnumber, description, duration, inclusivedates, commutation, vacation, sickleave, deducted_vacation, deducted_sick, process_no, request_status, vacationCreds, sickCreds, datereceived, DATE_FORMAT(lb.updated_at, '%m-%d-%Y') AS updated_at FROM leaverequests lr join users u on lr.userid = u.userid join leavebalances lb on lr.userid = lb.userid ORDER BY datefiled DESC LIMIT 300`, (error, results) => {
                    if (error) {
                        console.error('Error retrieving pending requests: ', error);
                        res.status(500).json({ error: 'Internal server error' });
                    } else {
                         // Decrypt each field of each user
                         results.forEach(user => {
                            user.lastname = decryptData(user.lastname, key);
                            user.firstname = decryptData(user.firstname, key);
                            user.middlename = decryptData(user.middlename, key);
                            user.contactnumber = decryptData(user.contactnumber, key);
                        });
                        res.json(results);
                    }
                });
            } else if (results[0].access_level === 1) {
                // If the user's access level is not 5, perform the second query
                db.query(`SELECT requestid, firstname, lastname, department, leaveid, reasonid, DATE_FORMAT(datefiled, '%m-%d-%Y') AS datefiled, middlename, salary, position, contactnumber, description, duration, inclusivedates, commutation, vacation, sickleave, deducted_vacation, deducted_sick, process_no, request_status, vacationCreds, sickCreds, datereceived, DATE_FORMAT(lb.updated_at, '%m-%d-%Y') AS updated_at FROM leaverequests lr join users u on lr.userid = u.userid join leavebalances lb on lr.userid = lb.userid WHERE department = ? ORDER BY datefiled DESC LIMIT 300`, [results[0].department], (error, results) => {
                    if (error) {
                        console.error('Error retrieving pending requests: ', error);
                        res.status(500).json({ error: 'Internal server error' });
                    } else {
                         // Decrypt each field of each user
                         results.forEach(user => {
                            user.lastname = decryptData(user.lastname, key);
                            user.firstname = decryptData(user.firstname, key);
                            user.middlename = decryptData(user.middlename, key);
                            user.contactnumber = decryptData(user.contactnumber, key);
                        });
                        res.json(results);
                    }
                });
            }
        }
    });
});

router.post('/reportreqfilter', authenticateToken, (req, res) => {
    
    const {year, month} = req.body
    const adminID = req.admin.id;
 
    // First, check the user's access level and department
    db.query('SELECT access_level, department FROM admins WHERE adminid = ?', [adminID], (error, results) => {
        if (error) {
            console.error('Error retrieving user access level: ', error);
            res.status(500).json({ error: 'Internal server error' });
        } else {
            let sqlQuery = `SELECT requestid, firstname, lastname, department, leaveid, reasonid, DATE_FORMAT(datefiled, '%m-%d-%Y') AS datefiled, middlename, salary, position, contactnumber, description, duration, inclusivedates, commutation, vacation, sickleave, deducted_vacation, deducted_sick, process_no, request_status, vacationCreds, sickCreds, datereceived, DATE_FORMAT(lb.updated_at, '%m-%d-%Y') AS updated_at FROM leaverequests lr join users u on lr.userid = u.userid join leavebalances lb on lr.userid = lb.userid`;
            let params = [];
 
            if (year && month) {
                sqlQuery += ' WHERE DATE_FORMAT(datefiled, "%Y-%m") LIKE ?';
                params.push(`${year}-${month}%`);
            } else if (year) {
                sqlQuery += ' WHERE DATE_FORMAT(datefiled, "%Y") LIKE ?';
                params.push(`${year}%`);
            } else if (month) {
                sqlQuery += ' WHERE DATE_FORMAT(datefiled, "%m") LIKE ?';
                params.push(`${month}%`);
            }
 


            if (results[0].access_level === 2) {
                sqlQuery += ` ORDER BY datefiled DESC`;
                //params.push("Approved");
                db.query(sqlQuery, params, (error, results) => {
                    if (error) {
                        console.error('Error retrieving filtered requests: ', error);
                        res.status(500).json({ error: 'Internal server error' });
                    } else {
                         // Decrypt each field of each user
                         results.forEach(user => {
                            user.lastname = decryptData(user.lastname, key);
                            user.firstname = decryptData(user.firstname, key);
                            user.middlename = decryptData(user.middlename, key);
                            user.contactnumber = decryptData(user.contactnumber, key);
                        });
                        res.json(results); // Add this line
                    }
                });
            } else if (results[0].access_level === 1) {
                sqlQuery += ` AND department = ? ORDER BY datefiled DESC`;
                params.push(results[0].department);
                db.query(sqlQuery, params, (error, results) => {
                    if (error) {
                        console.error('Error retrieving filtered requests: ', error);
                        res.status(500).json({ error: 'Internal server error' });
                    } else {
                         // Decrypt each field of each user
                         results.forEach(user => {
                            user.lastname = decryptData(user.lastname, key);
                            user.firstname = decryptData(user.firstname, key);
                            user.middlename = decryptData(user.middlename, key);
                        user.contactnumber = decryptData(user.contactnumber, key);
                        });
                        res.json(results); // Add this line
                    }
                });
            }
        }
    });
 });
 

router.post('/reportdeptfilter', authenticateToken, (req, res) => {
   
    const {department} = req.body
    const adminID = req.admin.id;
 
    // First, check the user's access level and department
    db.query('SELECT access_level, department FROM admins WHERE adminid = ?', [adminID], (error, results) => {
        if (error) {
            console.error('Error retrieving user access level: ', error);
            res.status(500).json({ error: 'Internal server error' });
        } else {
            let sqlQuery = `SELECT requestid, firstname, lastname, department, leaveid, reasonid, DATE_FORMAT(datefiled, '%m-%d-%Y') AS datefiled, middlename, salary, position, contactnumber, description, duration, inclusivedates, commutation, vacation, sickleave, deducted_vacation, deducted_sick, process_no, request_status, vacationCreds, sickCreds, datereceived, DATE_FORMAT(lb.updated_at, '%m-%d-%Y') AS updated_at FROM leaverequests lr join users u on lr.userid = u.userid join leavebalances lb on lr.userid = lb.userid WHERE department = ?`;            
            let params = [department];
 
 
            if (results[0].access_level === 2) {
                sqlQuery += ` ORDER BY datefiled DESC LIMIT 300`;
                params.push(results[0].department);
                db.query(sqlQuery, params, (error, results) => {
                    if (error) {
                        console.error('Error retrieving filtered requests: ', error);
                        res.status(500).json({ error: 'Internal server error' });
                    } else {
                         // Decrypt each field of each user
                         results.forEach(user => {
                            user.lastname = decryptData(user.lastname, key);
                            user.firstname = decryptData(user.firstname, key);
                            user.middlename = decryptData(user.middlename, key);
                              user.contactnumber = decryptData(user.contactnumber, key);

                        });
                        res.json(results); // Add this line
                    }
                });
            } else if (results[0].access_level === 1) {
                // sqlQuery += ' AND department = ? ORDER BY datefiled DESC';
                sqlQuery += ' ORDER BY datefiled DESC LIMIT 300';
                params.push(results[0].department);
                db.query(sqlQuery, params, (error, results) => {
                    if (error) {
                        console.error('Error retrieving filtered requests: ', error);
                        res.status(500).json({ error: 'Internal server error' });
                    } else {
                         // Decrypt each field of each user
                         results.forEach(user => {
                            user.lastname = decryptData(user.lastname, key);
                            user.firstname = decryptData(user.firstname, key);
                            user.middlename = decryptData(user.middlename, key);
                            user.contactnumber = decryptData(user.contactnumber, key);

                                });
                        res.json(results); // Add this line
                    }
                });
            }
        }
    });
 });

//View--Update-- Deny--Approve
router.get('/btnview/:requestid', (req, res) => {
    const requestid = req.params.requestid;
  
    db.query(`SELECT requestid, lastname, firstname, middlename, department, contactnumber, DATE_FORMAT(datefiled, '%m-%d-%Y') AS datefiled, position, salary, deducted_vacation, deducted_sick, vacation, sickleave, vacationCreds, sickCreds, leaveid, reasonid, description, request_status, duration, inclusivedates, commutation, process_no FROM leaverequests lr join users u on lr.userid = u.userid join leavebalances lb on lr.userid = lb.userid WHERE lr.requestid = ${requestid}`, (error, results) => {
      if (error) {
        console.error('Error retrieving request with request id ' + requestid + ': ', error);
        res.status(500).json({ error: 'Internal server error' });
      } else {
        if (results.length > 0) {
            // Decrypt each field of the user
        results[0].lastname = decryptData(results[0].lastname, key);
        results[0].firstname = decryptData(results[0].firstname, key);
        results[0].middlename = decryptData(results[0].middlename, key);
        results[0].contactnumber = decryptData(results[0].contactnumber, key);
          res.json(results[0]);
        } else {
          res.status(404).json({ error: 'User not found' });
        }
      }
    });
  });



router.put('/update_deduction', (req, res) => {
    const { requestid, lessVac, lessSick } = req.body;

    // Log the deduction update action
    const logData = `Updating deductions for request id: ${requestid}`;
    logUserActivity(logData);


    db.query(
      `UPDATE leaverequests SET deducted_vacation = ${lessVac}, deducted_sick = ${lessSick} WHERE requestid = ${requestid}`,
      (error, results) => {
        if (error) {
          console.error('Error updating user deduction with request id ' + requestid + ': ', error);
          res.status(500).json({ error: 'Internal server error' });
        } else if (results.affectedRows === 0) {
          res.status(404).json({ error: 'Data not found' });
        } else {
          res.json({ success: true });
        }
      }
    );
  });
  
  
router.put('/deny', (req, res) => {
    const { requestid } = req.body;
    
    // Log the denial action
    const logData = `Denying leave request with id: ${requestid}`;
    logUserActivity(logData);

    db.query('UPDATE leaverequests SET request_status = ?, datereceived = DATE_FORMAT(CURDATE(), "%m-%d-%Y") WHERE requestid = ?', ['Denied', requestid], (error, results) => {
        if (error) {
            console.error('Error updating leave request status:', error);
            res.status(500).json({ error: 'Internal server error' });
        } else {
            

           // Insert into notifications table
         db.query('INSERT INTO notifications (userid, requestid, message, status) SELECT userid, ?, "Leave request Denied", 1 FROM leaverequests WHERE requestid = ?', [requestid, requestid], (error, results) => {
            if (error) {
              console.error('Error inserting into notifications:', error);
              res.status(500).json({ error: 'Internal server error' });
            } else {
              res.json(results[0]);
            }
          });
            
        }
    });
  });

router.put('/approve', (req, res) => {
    const { requestid, process_no, vacationCreds, sickCreds } = req.body;
  
    // Log the approval action
    const logData = `Approving leave request with id: ${requestid}, process_no: ${process_no}`;
    logUserActivity(logData);


    if (process_no === 1) {
      const new_process_no = process_no + 1;
      db.query('UPDATE leaverequests SET process_no = ?, vacationCreds = ?, sickCreds = ?, datereceived = DATE_FORMAT(CURDATE(), "%m-%d-%Y") WHERE requestid = ?', [new_process_no, vacationCreds, sickCreds, requestid], (error, results) => {
        if (error) {
          console.error('Error updating process_no:', error);
          res.status(500).json({ error: 'Internal server error' });
        } else {
          res.json(results[0]);
        }
      });
    } else if (process_no === 2) {
      db.query('UPDATE leaverequests SET request_status = ?, vacationCreds = ?, sickCreds = ? WHERE requestid = ?', ['Approved', vacationCreds, sickCreds, requestid], (error, results) => {
        if (error) {
          console.error('Error updating leave request status:', error);
          res.status(500).json({ error: 'Internal server error' });
        } else {
          

            db.query('SELECT leaveid FROM leaverequests WHERE requestid = ?', [requestid], (error, results) => {
                if (error) {
                    console.error('Error retrieving user leave balances: ', error);
                    res.status(500).json({ error: 'Internal server error' });
                } else {

                    db.query('INSERT INTO notifications (userid, requestid, message, status) SELECT userid, ?, "Leave request approved", 1 FROM leaverequests WHERE requestid = ?', [requestid, requestid], (error, results) => {
                        if (error) {
                          console.error('Error inserting into notifications:', error);
                          res.status(500).json({ error: 'Internal server error' });
                        } else {
                          //res.json(results[0]);
                        }
                      });
        
                    if (results[0].leaveid ===  1 || results[0].leaveid ===  2 || results[0].leaveid ===  3 || results[0].leaveid ===  6 || results[0].leaveid ===  7) {
                  
                        handleRequestDeduction(requestid, res);
                    } else {
                        res.json({ success: true });
                      }
                }
            });

         
        }
      });
    }
 });
 
 function handleRequestDeduction(requestid, res) {
    const query = 'SELECT lr.userid, lb.sickleave, lb.vacation, lb.forcedleave, lb.special_privilege_leave, lb.solo_parent_leave, leaveid, duration, deducted_vacation, deducted_sick FROM leaverequests lr JOIN leavebalances lb on lr.userid = lb.userid WHERE requestid = ?';
    db.query(query, [requestid], (error, results) => {
      if (error) throw error;
  
      if (results.length >  0) {
        const duration = results[0].duration;
        const lessVac = results[0].deducted_vacation;
        const lessSick = results[0].deducted_sick;
        const leaveType = results[0].leaveid;
        let netLeave;
  
        switch (leaveType) {
          case  1:
            netLeave = results[0].vacation - lessVac;
            updateBalance('lb.vacation', netLeave, requestid, res);
            break;
          case  2:
            netLeave = results[0].forcedleave - duration;
            updateBalance('lb.forcedleave', netLeave, requestid, res);
            break;
          case  3:
            netLeave = results[0].sickleave - lessSick;
            updateBalance('lb.sickleave', netLeave, requestid, res);
            break;
          case  6:
            netLeave = results[0].special_privilege_leave - duration;
            updateBalance('lb.special_privilege_leave', netLeave, requestid, res);
            break;
          case  7:
            netLeave = results[0].solo_parent_leave - duration;
            updateBalance('lb.solo_parent_leave', netLeave, requestid, res);
            break;
          default:
            console.log('Unsupported leave type');
            res.status(400).json({ error: 'Unsupported leave type' });
            break;
        }
      } else {
        console.log('No matching request found');
      }
    });
  }
  
  function updateBalance(column, newValue, requestid, res) {
    const query = `UPDATE leavebalances lb JOIN leaverequests lr ON lr.userid = lb.userid JOIN users u ON lr.userid = u.userid SET ${column} = ? WHERE lr.requestid = ?`;
    db.query(query, [newValue, requestid], (error, results) => {
      if (error) {
        console.error('Error updating user BALANCE with request id ' + requestid + ': ', error);
        res.status(500).json({ error: 'Internal server error' });
      } else if (results.affectedRows ===  0) {
        res.status(404).json({ error: 'Data not found' });
      } else {
        res.json({ success: true });
      }
    });
  }
  
  
//Feedback

router.post('/feedback', authenticateToken, (req, res) => {
    const { feedback } = req.body;
    const adminID = req.admin.id;

    db.query('INSERT INTO feedbacks SET ?', { adminid: adminID, feedback: feedback}, (error, results) => {
        if (error) {
            console.error('Error inserting feedback: ', error);
            res.status(500).json({ error: 'Internal server error' });
        } else {
            res.json({ message: 'Feedback submitted successfully!' });
        }
    });
});


module.exports = router;
