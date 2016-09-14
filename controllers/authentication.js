const jwt = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');

//function to encode - uses our secret and info to encode
function tokenForUser(user) {

	const timeStamp = new Date().getTime();
	//convention is sub - subject - who is token about?
	//iat = issued at time
	return jwt.encode({ sub: user.id, iat: timeStamp }, config.secret);
}

exports.signin = function(req, res, next) {
	//user has already had their email and password auth'd
	//need to give them a token

	res.send({ token: tokenForUser(req.user) });

}

exports.signup = function(req, res, next) {

	const email = req.body.email;
	const password = req.body.password;

	if (!email || !password) {
		return res.status(422).send({ error: "You must provide a username and a password"})
	}

	// See if user with given email exists
	User.findOne({ email }, (err, existingUser) => {

		// If user with email does exit, return error
		if (err) {
			return next(err);
		}

		// See if user with given email exists
		if (existingUser) {
			return res.status(422).send({ error: 'Email is in use'});
		}

		// If a user with email does NOT exist, create and save user record
		const user = new User({
			email,
			password
		});

		user.save((err) => {

			if (err) {
				return next(err);
			}

			//Respond to request indicating that user created
			res.json({ token: tokenForUser(user) });
		});

	});


}