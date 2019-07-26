const mongoose = require('mongoose');
const User = mongoose.model('User');
const passport = require('passport');

exports.validateSignup = (req, res, next) => {
    req.sanitizeBody('name');
    req.sanitizeBody('email');
    req.sanitizeBody('password');
    req.checkBody('name', 'Please enter an user name').notEmpty();
    req.checkBody('name', 'Name must be between 4-10 characters and contain no special characters.').isLength({ min: 4, max: 10 });
    req.checkBody('email', 'Please enter a valid email').isEmail().normalizeEmail();
    req.checkBody('password', 'Please enter a password').notEmpty();
    req.checkBody('password', 'Password must be between 4-10 characters and contain no special characters.').isLength({ min: 4, max: 10 });
    const errors = req.validationErrors();
    if (errors) {
        const firstError = errors.map(error => error.msg)[0];
        return res.status(400).send(firstError);
    }
    next();
};

exports.signup = async (req, res) => { 
    const {name, email, password} = req.body;
    const user = await new User({name, email, password});
    await User.register(user, password, (err, user) => {
        if (err) {
            return res.status(500).send(err.message);
        }
        res.json(user.name);
    });
};

exports.signin = (req, res, next) => { 
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            return res.status(500).json(err.message);
        }
        if (!user) {
            return res.status(400).json(info.message);
        }

        req.logIn(user, err => {
            if (err) {
                return res.status(500).json(err.message);
            }
            res.json(user);
        });
    })(req, res, next);
};

exports.signout = (req, res) => { 
    res.clearCookie("next-cookie.sid");
    res.logout;
    res.json({message: "Signed out!"});
};

exports.checkAuth = (req, res, next) => { 
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/signin');
};
