var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var jwt = require('jsonwebtoken');
var database = require('sqlite3');
var md5 = require('md5');
const config = require('./config/auth.config.js');

var HTTP_PORT = 5000;

let db = new database.Database('./db/logaggregator.db', (err) => {
    if (err) {
        console.error(err.message);
    }
    console.log('Connected to the logaggregator database.');
});

const isAuth = (req, res, next) => {
    const str = req.get('Authorization');
    if (!jwt) return res.json({
        "message": "failed, no jwt"
    });
    try {
        jwt.verify(str, config.secret, { algorithms: 'HS256' });
        res.locals.isAdmin = jwt.decode(str, { complete: true }).payload.isAdmin
        next();
    } catch {
        res.status(401);
        res.send('Bad Token');
    }
}

const isAdmin = (req, res, next) => {
    if (!res.locals.isAdmin) return res.status(401).send('Not Admin');
    next();
}

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.listen(HTTP_PORT, () => {
    console.log('Server running on port %PORT%'.replace('%PORT%', HTTP_PORT));
});

app.get('/', (req, res, next) => {
    res.render('firstEJSTemplate');
});

// GET: Get all users
app.get('/users', isAuth, isAdmin, (req, res, next) => {
    try {
        var sql = 'SELECT * FROM user';
        var params = [];
        db.all(sql, params, (err, users) => {
            if (err) {
                res.status(400).json({ "error": err.message });
                throw err;
            }
            res.json({
                "message": "succes",
                "data": users
            });
        });
    } catch {
        res.status(401);
        res.send('Bad Token');
    }
});

// GET: Get single user
app.get('/user/:username', isAuth, isAdmin, (req, res, next) => {
    var sql = 'SELECT * FROM user WHERE username = ?';
    var params = [req.params.username];
    db.get(sql, params, (err, user) => {
        if (err) {
            res.status(400).json({ "error": err.message });
            throw err;
        }
        res.json({
            "message": "success",
            "data": user
        });
    });
});

// POST: Add new user
app.post('/user/', isAuth, isAdmin, (req, res, next) => {
    var errors = [];
    if (!req.body.password) {
        errors.push('No password specified');
    }
    if (!req.body.username) {
        errors.push('No username specified');
    }
    if (errors.length) {
        res.status(400).json({ "error": errors.join(',') });
        throw err;
    }
    var userData = {
        username: req.body.username,
        password: md5(req.body.password)
    }
    var sql = 'INSERT INTO user (username, password) VALUES (?, ?)';
    var params = [userData.username, userData.password];
    db.run(sql, params, function (err, result) {
        if (err) {
            res.status(400).json({ "error": err.message })
            throw err;
        }
        res.json({
            "message": "success",
            "data": userData,
            "id": this.lastID
        })
    });
});

// PATCH: Update user
app.patch('/user/:username', isAuth, isAdmin, (req, res, next) => {
    var userData = {
        username: req.body.username,
        password: req.body.password ? md5(req.body.password) : null
    };
    var sql = 'UPDATE user set username = COALESCE(?,username), password = COALESCE(?,password) WHERE username = ?';
    var params = [userData.username, userData.password, req.params.username];
    db.run(sql, params, function (err, result) {
        if (err) {
            res.status(400).json({ "error": err.message })
            throw err;
        }
        res.json({
            "message": "success",
            "data": userData,
            "changes": this.changes
        });
    });
});

// DELETE: Remove user
app.delete('/user/:username', isAuth, isAdmin, (req, res, next) => {
    var sql = 'DELETE FROM user WHERE username = ?';
    db.run(sql, req.params.username, function (err, result) {
        if (err) {
            res.status(400).json({ "error": err.message })
            throw err;
        }
        res.json({
            "message": "deleted",
            "changes": this.changes
        });
    });
});

// POST: Login user
app.post('/login', (req, res, next) => {
    var password = md5(req.body.password);
    var sql = 'SELECT * FROM user WHERE (username, password) = (?, ?)';
    var params = [req.body.username, password]
    db.get(sql, params, function (err, user) {
        if (err) {
            res.status(400).json({ "error": err.message });
            throw err;
        }

        if (user != undefined) {
            var payload = {
                username: user.username,
                isAdmin: user.admin
            };

            var token = jwt.sign(payload, KEY, { algorithm: 'HS256', expiresIn: "15d" });
            res.send({
                username: user.username,
                admin: user.admin,
                jwt: token
            });
        } else {
            console.error('Failure');
            res.status(401)
            res.send('There\'s no user matching that');
        }
    });
});

// GET: Get all Projects and Logs
app.get('/data', isAuth, (req, res, next) => {
    var sql = 'SELECT rowid AS id, projectname FROM project';
    db.all(sql, (err, projects) => {
        if (err) {
            res.status(400).json({ "error": err.message });
            throw err;
        }

        var sql2 = 'SELECT projectid, timeofentry, severitylevel, content FROM log';
        db.all(sql2, (err, logs) => {
            if (err) {
                res.status(400).json({ "error": err.message });
                throw err;
            }

            projects.forEach(project => {
                logs.forEach(log => {
                    if (project['id'] == log.projectid) {
                        if (project.hasOwnProperty('logs')) {
                            project['logs'].push(log);
                        } else {
                            var logs = [];
                            logs.push(log);
                            project['logs'] = logs;
                        }
                    }
                });
            });

            res.json({
                'message': 'succes',
                'data': projects
            });
        });
    });
});

// GET: Get all projects
app.get('/project', isAuth, (req, res, next) => {
    var sql = 'SELECT * FROM project';
    db.all(sql, (err, projects) => {
        if (err) {
            res.status(400).json({ "error": err.message });
            throw err;
        }

        res.json({
            'message': 'succes',
            'data': projects
        });
    });
});

// GET: Get all logs where projectid is the same as project in request
app.get('/log/:projectid', isAuth, (req, res, next) => {
    var sql = 'SELECT * FROM log WHERE projectid = ?'
    db.all(sql, req.params.projectid, (err, logs) => {
        if (err) {
            res.status(400).json({ "error": err.message });
            throw err;
        }

        res.json({
            'message': 'succes',
            'data': logs
        });
    });
});

// GET: Get single log for projectid and logid
app.get('/log/:projectid/:logid', isAuth, (req, res, next) => {
    var sql = 'SELECT * FROM log WHERE id = ?'
    var params = [req.params.projectid, req.params.logid];
    db.get(sql, req.params.logid, (err, log) => {
        if (err) {
            res.status(400).json({ "error": err.message });
            throw err;
        }

        res.json({
            'message': 'succes',
            'data': log
        });
    });
});

// POST: Add new Project
app.post('/project/', isAuth, (req, res, next) => {
    var errors = [];
    if (!req.body.projectname) {
        errors.push('No projectname specified');
    }
    if (errors.length) {
        res.status(400).json({ "error": errors.join(',') });
        throw err;
    }
    var projectData = {
        projectname: req.body.projectname
    }
    var sql = 'INSERT INTO project (projectname) VALUES (?)';
    var params = [projectData.projectname];
    db.run(sql, params, function (err, result) {
        if (err) {
            res.status(400).json({ "error": err.message })
            throw err;
        }
        res.json({
            "message": "success",
            "data": projectData,
            "id": this.lastID
        })
    });
});

// DELETE: Remove Project
app.delete('/project/:projectid', isAuth, (req, res, next) => {
    var sql = 'DELETE FROM log WHERE projectid = ?';
    db.run(sql, req.params.projectid, function (err, result) {
        if (err) {
            res.status(400).json({ "error": err.message })
            throw err;
        }

        var logChanges = this.changes;

        var sql2 = 'DELETE FROM project WHERE id = ?';
        db.run(sql2, req.params.projectid, function (err, result) {
            if (err) {
                res.status(400).json({ "error": err.message })
                throw err;
            }

            res.json({
                "message": "deleted",
                "changes": 'Logs:' + logChanges + ', Projects:' + this.changes
            });
        });
    });
});

// POST: Add new Log
app.post('/log/', isAuth, (req, res, next) => {
    var errors = [];
    if (!req.body.projectid) {
        errors.push('No projectId specified');
    }
    if (!req.body.timeofentry) {
        errors.push('No timeofentry specified');
    }
    if (!req.body.severitylevel) {
        errors.push('No severitylevel specified');
    }
    if (!req.body.content) {
        errors.push('No content specified');
    }
    if (errors.length) {
        res.status(400).json({ "error": errors.join(',') });
        throw err;
    }
    var logData = {
        projectid: req.body.projectid,
        timeofentry: req.body.timeofentry,
        severitylevel: req.body.severitylevel,
        content: req.body.content
    }
    var sql = 'INSERT INTO log (projectid, timeofentry, severitylevel, content) VALUES (?, ?, ?, ?)';
    var params = [logData.projectid, logData.timeofentry, logData.severitylevel, logData.content];
    db.run(sql, params, function (err, result) {
        if (err) {
            res.status(400).json({ "error": err.message })
            throw err;
        }
        res.json({
            "message": "success",
            "data": logData,
            "id": this.lastID
        })
    });
});

// DELETE: Remove Log
app.delete('/log/:logid', isAuth, (req, res, next) => {
    var sql = 'DELETE FROM log WHERE logid = ?';
    db.run(sql, req.params.logid, function (err, result) {
        if (err) {
            res.status(400).json({ "error": err.message })
            throw err;
        }
        res.json({
            "message": "deleted",
            "changes": this.changes
        });
    });
});

// catch 404 and forward to error handler
app.use((req, res, next) => {
    next(createError(404));
});

// error handler
app.use((err, req, res, next) => {
    // set locals, only providing error in development
    res.locals.message = err.message;
    res.locals.error = req.app.get('env') === 'development' ? err : {};

    // render the error page
    res.status(err.status || 500);
    res.render('error');
});

module.exports = app;
