const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local').Strategy;

//change username field to email
const localOptions = { usernameField: 'email' };

const localLogin = new LocalStrategy(localOptions, function(email, password, done) {
	
	//verify email and password, call done if correct
	
	User.findOne({ email }, function(err, user) {

		if (err) {
			return done(err);
		}

		if (!user) {
			return done(null, false);
		}

		//compare passwords - is password == user.password
		user.comparePassword(password, function(err, isMatch) {
			if (err) { return done(err); }
			if (!isMatch) {
				return done(null, false);
			}

			return done(null, user);
		});

	});



	//otherwise call done with false

});

//setup options for jwt strategy
const jwtOptions = {
	//find jwt in header and extract
	jwtFromRequest: ExtractJwt.fromHeader('authorization'),
	secretOrKey: config.secret
};

//create jwt strategy - payload = decoded jwt token, done is method to continue
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {

	//see if userId in payload exists in database
	//if it does, call done with that user
	//otherwise call done without user object	

	User.findById(payload.sub, function(err, user) {
		if (err) {
			//1 - err object, 2 - false didnt find user
			return done(err, false);
		}

		//if have user, call done with no error and user
		if (user) {
			done(null, user);
		}
		//else call with no error, but false as user
		else {
			done(null, false);
		}

	});

});





//tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);