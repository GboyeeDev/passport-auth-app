const express = require('express');

const router = express.Router();

const User = require('../models/users.model');
const bcrypt = require('bcryptjs');
const passport = require('passport');


router.get('/login', (req, res) => res.render('login'));

router.get('/register', (req, res) => res.render('register'));

router.post('/register', (req, res) => {
    const { name, email, password, password2 } = req.body;
    //console.log(req.body)
    let errors = [];

    //checks errors
    if (!name || !email || !password || !password2) {
        errors.push({ msg: 'Please fill in all fields' });
    }

    // check password match
    if (password !== password2) {
        errors.push({ msg: 'Passwords does not match' });
    }

    // checks for password length
    if (password.length < 6) {
        errors.push({ msg: 'Password must be greater than 6 characters' });
    }

    if (errors.length > 0) {
        res.render('register', {
            errors,
            name,
            email,
            password,
            password2
        });
    } else {
        // Validation being passed
        User.findOne({ email })
          .then(user => {
            if(user) {
                // user exists
                errors.push({ msg: 'email is already used' });
                res.render('register', {
                    errors,
                    name,
                    email,
                    password,
                    password2
                });
            }   else {
                const newUser = new User({
                    name,
                    email,
                    password
                });

                //hash password
                bcrypt.genSalt(10, (err, salt) => 
                  bcrypt.hash(newUser.password, salt, (err, hash) => {
                    if(err) throw err;
                    // set password to hashed
                    newUser.password = hash
                    // save user
                    newUser.save()
                      .then(user => {
                        req.flash('success_msg', 'You are now registered, Log in');
                        res.redirect('/users/login');
                      })
                      .catch(err => console.log(err))
                  }))
            }
          });
    }
});

//After user logs in (login handle)
router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/users/login',
        failureFlash: true
    })(req, res, next);
});


// Logout Handle
router.get('/logout', function(req, res, next) {
    req.logout(function(err) {
      if (err) { 
        return next(err); 
      }
      req.flash('success_msg', 'You are logged out');
      res.redirect('/');
    });
  });


module.exports = router;