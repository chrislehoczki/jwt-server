const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');


//define model

const userSchema = new Schema({
	email: { type: String, unique: true, lowercase: true }, //make sure it is unique
	password: String
});


//On save hook - encrypt password

//before saving model, run this function
userSchema.pre('save', function (next)  {

	const user = this; //context is user model

	//generate a salt then run callback
	bcrypt.genSalt(10, function (err, salt) {
		if (err) {
			return next(err);
		}

		//hash password using salt
		bcrypt.hash(user.password, salt, null, function (err, hash) {
			if (err) {
				return next(err);
			}

			//overwrite plain text pass with encrypted pass
			user.password = hash;

			//save the model and continue
			next();
		});
	});
});

userSchema.methods.comparePassword = function(candidatePassword, callback) {
	//this = user model - hashed password
	bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
		if (err) { return callback(err) }

		callback(null, isMatch);
	});
} 


// create model class
//class of users with - (collextion, user model)
const ModelClass = mongoose.model('user', userSchema);

//export model

module.exports = ModelClass;