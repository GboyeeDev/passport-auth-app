const Localstrategy = require('passport-local').Strategy;
const moogoose = require('mongoose');
const bcrypt = require('bcryptjs');


const User = require('../models/users.model');

module.exports = function(passport) {
    passport.use(
        new Localstrategy({ usernameField: 'email'}, (email, password, done) => {
            // Match the user email logging in 
            User.findOne({ email })
              .then(user => {
                if(!user) {
                    return done(null, false, { message: 'Please provide correct email' });
                }

                // match password
                bcrypt.compare(password, user.password, (err, isMatch) => {
                    if(err) throw err;

                    if(isMatch) {
                        return done(null, user);
                    } else {
                        return done(null, false, { message: 'Please provide correct password' });
                    }
                });
              })
              .catch(err => console.log(err));
        })
    );


    // to create cookie to support the authentication (login) system
    passport.serializeUser((user, done) => {
        done(null, user.id);
    });

    // passport.deserializeUser( function (id, done) {
    //     User.findById(id)
    //         .then(function(user) {
    //             done(null, user);
    //         })
    //         .catch(function(err) {
    //             done(err);
    //         });
    // });

    passport.deserializeUser(async function (id, done) {
        try {
          const user = await User.findById(id);
          done(null, user);
        } catch (err) {
          done(err);
        }
      });      
    
}