var LocalStrategy = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;

//User Model
var User = require('../app/models/user');

//Authentication Variables
var configAuth = require('./auth');

module.exports = function(passport) {

	passport.serializeUser(function (user, done) {
		done(null, user.id);
	});

	passport.deserializeUser(function(id, done) {
		User.findById(id, function(err, user) {
			done(err, user);
		});
	});



	//====================================================================
	//LOCAL ==============================================================
	//====================================================================

	//Signup
	passport.use('local-signup', new LocalStrategy({
		usernameField: 'email',
		passwordField: 'password',
		passReqToCallback: true
	},
	function(req, email, password, done) {

		process.nextTick(function() {

			//Find user with same email
			User.findOne({ 'local.email': email }, function(err, user) {
				if (err) 
					return done(err);

				if (req.body.name == "")
					return done(null, false, req.flash('signupMessage', 'Name is required!'));

				if (user) {
					return done(null, false, req.flash('signupMessage', 'Email already taken!'));

				} else if (!isEmail(email)) {
					return done(null, false, req.flash('signupMessage', 'That is not a valid email address!'));

				} else {

					//Create new user
					var newUser = new User();

					newUser.local.name = req.body.name;
					newUser.local.email = email;
					newUser.local.password = newUser.generateHash(password);

					newUser.save(function(err) {
						if (err)
							throw err;
						
						return done(null, newUser);

					});
				}
			});
		});
	}));

	
	//Login
	passport.use('local-login', new LocalStrategy({
		usernameField: 'email',
		passwordField: 'password',
		passReqToCallback: true
	},
	function (req, email, password, done) {
		User.findOne({ 'local.email': email }, function(err, user) {

			if (err)
				return err;

			if (!user)
				return done(null, false, req.flash('loginMessage', 'No user found.'));

			if (!user.validPassword(password))
				return done(null, false, req.flash('loginMessage', 'Oops! Wrong password. Try Again :-)'));

			//At this point the username exists and the password matches

			return done(null, user);
		});
	}));

	//====================================================================
	//FACEBOOK ===========================================================
	//====================================================================

	passport.use(new FacebookStrategy({
		clientID     : configAuth.facebookAuth.clientID,
		clientSecret : configAuth.facebookAuth.clientSecret,
		callbackURL  : configAuth.facebookAuth.callbackURL,
		passReqToCallback: true
	},

	// facebook will send back the token and profile
	function (req, token, refreshToken, profile, done) {

		process.nextTick(function() {
			// find the user in the database based on their facebook id

			if (!req.user) {

				User.findOne({ 'facebook.id' : profile.id }, function(err, user) {

	            	//Error connecting to database
	            	if (err)
	                    return done(err);

	                //User with facebook id is found
	                if (user) {

	                	//Check for token. If null, user was unlinked and we should relink
	                	if (!user.facebook.token) {
	                		user.facebook.token = token;
	                		user.facebook.name = profile.name.givenName + ' ' + profile.name.familyName;
	                		user.facebook.email = profile.emails[0].value;

	                		user.save(function(err) {
	                			if (err)
	                				throw err;
	                			return done(null, user);
	                		});
	                	}

	                	return done(null, user);
	                } else {
	                	//Make a new user since no user with facebook id is found

	                	var newUser = new User();

	                	newUser.facebook.id = profile.id;
	                	newUser.facebook.token = token;
	                	newUser.facebook.name = profile.name.givenName + ' ' + profile.name.familyName;
	                	newUser.facebook.email = profile.emails[0].value;

	                	newUser.save(function(err) {
	                        if (err)
	                            throw err;

	                        // if successful, return the new user
	                        return done(null, newUser);
	                    });
	                }
	            });

			} else {
				var user = req.user;

				user.facebook.id    = profile.id;
                user.facebook.token = token;
                user.facebook.name  = profile.name.givenName + ' ' + profile.name.familyName;
                user.facebook.email = profile.emails[0].value;

                user.save(function(err) {
                    if (err)
                        throw err;

                    return done(null, user);
                });
			}
            
		});
	}));
};

function isEmail(email) { 
    var re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(email);
}