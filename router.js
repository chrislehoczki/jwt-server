const Authentication = require('./controllers/authentication');
const passportService = require('./services/passport');
const passport = require('passport');

//create middleware between route and code to run
//disable cookies
const requireAuth = passport.authenticate('jwt', { session: false });
const requireSignin = passport.authenticate('local', { session: false });

module.exports = function(app) {

	app.get('/', requireAuth, function(req, res) {
		console.log(req.user);
		res.send({ hi: 'there' });
	});

	app.post('/signin', requireSignin, Authentication.signin);

	app.post('/signup', Authentication.signup);

}