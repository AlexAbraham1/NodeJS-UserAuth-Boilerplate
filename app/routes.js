module.exports = function(app, passport) 
{
    
	//Home
	app.get('/', function(req, res) {

		if (req.user) {
			res.redirect('/profile');
		} else {
			res.render('index.ejs');
		}
	});

	//====================================================================
	//LOCAL ==============================================================
	//====================================================================

	//Login
	app.get('/login', function(req, res) {
		res.render('login.ejs', {message: req.flash('loginMessage')});
	});

	//Login POST
    app.post('/login', passport.authenticate('local-login', {
    	successRedirect: '/profile',
    	failureRedirect: '/login',
    	failureFlash: true
    }));

    //Signup
    app.get('/signup', function(req, res) {
    	res.render('signup.ejs', {message: req.flash('signupMessage')});
    });

    //Signup POST
    app.post('/signup', passport.authenticate('local-signup', {
    	successRedirect: '/profile',
    	failureRedirect: '/signup',
    	failureFlash: true
    }));

    //Profile
    app.get('/profile', isLoggedIn, function(req, res) {
    	res.render('profile.ejs', {
    		user: req.user, //Gets the user from session and passes it to template
    		goodMessage: req.flash('goodMessage'),
    		badMessage: req.flash('badMessage')
    	});
    });

    //Password Reset (Form inside profile page)
    app.post('/passwordReset', isLoggedIn, function(req, res) {

		var user = req.user;

		var oldPassword = req.body.oldPassword;
		var newPassword = req.body.newPassword;
		var retypePassword = req.body.retypePassword;

		//Old password is not a match
		if (!user.validPassword(oldPassword)) {
			req.flash('badMessage', 'Old password doesn\'t match! Try Again :-)');
			return res.redirect('/profile');
		}

		//New password is null
		if (newPassword == "") {
			req.flash('badMessage', 'New password can\'t be blank!');
			return res.redirect('/profile');
		}

		//New password fields don't match
		if (newPassword != req.body.retypePassword) {
			req.flash('badMessage', 'New passwords don\'t match! Try Again :-)'); 
			return res.redirect('/profile');
		}

		
		user.local.password = user.generateHash(newPassword);
		user.save(function(err) {
			req.flash('goodMessage', 'Password Reset Successful!');
			return res.redirect('/profile');
		});
		
	});

    //====================================================================
	//FACEBOOK ===========================================================
	//====================================================================


	app.get('/auth/facebook', passport.authenticate('facebook', { scope : 'email' }));

	//Callback for after user is authenticated
	app.get('/auth/facebook/callback', passport.authenticate('facebook', {
		successRedirect : '/profile',
		failureRedirect : '/'
	}));



    //Logout
    app.get('/logout', function(req, res) {
    	res.clearCookie('remember_me');
    	req.logout();
    	res.redirect('/');
    });


    // =============================================================================
	// AUTHORIZE (ALREADY LOGGED IN / CONNECTING OTHER SOCIAL ACCOUNT) =============
	// =============================================================================

	//Local
	app.get('/connect/local', function(req, res) {
        res.render('connect-local.ejs', { message: req.flash('loginMessage') });
    });

    app.post('/connect/local', passport.authenticate('local-signup', {
    	successRedirect: '/profile',
    	failureRedirect: '/connect/local',
    	failureFlash: true
    }));

    //Facebook
    app.get('/connect/facebook', passport.authorize('facebook', { 
    	scope : 'email' 
    }));

    app.get('/connect/facebook/callback', passport.authorize('facebook', {
        successRedirect : '/profile',
        failureRedirect : '/'
    }));

    // =============================================================================
	// UNLINK ACCOUNTS =============================================================
	// =============================================================================

	//Local
	app.get('/unlink/local', isLoggedIn, function(req, res) {
		var user = req.user;
		user.local.email = undefined;
		user.local.password = undefined;
		user.save(function(err) {
			res.redirect('/profile');
		});
	});

	//Facebook
	app.get('/unlink/facebook', isLoggedIn, function(req, res) {
		var user = req.user;
		user.facebook.token = undefined;
		user.save(function(err) {
			res.redirect('/profile');
		});
	});




   	//Check if user is logged in
    function isLoggedIn(req, res, next) {
    	if (req.isAuthenticated()) {
    		return next(); //Continue
    	}

    	//Otherwise, redirect to home since user is not logged in
    	res.redirect('/');
    }

};