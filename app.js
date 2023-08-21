// Import Project Packages
import "dotenv/config";
import express from "express";
import mongoose from "mongoose";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import passportFacebook from "passport-facebook";
import { check, validationResult } from "express-validator";
import { MongoMissingCredentialsError } from "mongodb";

// Import passport-local-mongoose and mongoose-findorcreate
import passportLocalMongoose from "passport-local-mongoose";
import findOrCreate from "mongoose-findorcreate";

//Use middleware 
const app = express();
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));

//Start the session using express-session
app.set('trust proxy', 1) // trust first proxy
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));

//Initialize passport
app.use(passport.initialize());
app.use(passport.session());

//Establish MongoDb Connection through Mongoose
const uri = process.env.DATABASE_URL;
mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        console.log('Connected to MongoDB');
    })
    .catch(error => {
        console.error('Error connecting to MongoDB:', error);
    });

const db = mongoose.connection;

db.on('connected', () => {
    console.log('Mongoose connected to ' + uri);
});

db.on('error', error => {
    console.error('Mongoose connection error:', error);
});

db.on('disconnected', () => {
    console.log('Mongoose disconnected');
});

//Create Schema
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleID: String,     
    facebookID: String,
    secret: String
  });

//Add plugins to the Schema (passportLocalMongoose, find one and create).
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//Create Model
const User = new mongoose.model("User", userSchema);

//Set up Passport and use local strategy.This is used in scenarios where you want to 
//handle authentication based on manual input of username (usually email) and password
passport.use(User.createStrategy());
const FacebookStrategy = passportFacebook.Strategy;


// When dealing with manual input of a username (usually email) and password for local authentication, you need to implement serialization 
// and deserialization of user objects. This is necessary to manage user sessions and authentication state.
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id)
    .then(user => {
      done(null, user);
    })
    .catch(err => {
      done(err, null);
    });
});

//After finishing config, use the passport strategy. In this case Google and Facebook.
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo", // Alternative profile URL since google+ is deprecated
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
//Add Facebook authentication
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));



/////////////Handle google authentication
//handle google authentication on both routes
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));


  app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });


/////////////Handle Facebook authentication
//handle Facebook authentication on both routes

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });




//Render home page
app.get('/', (req, res) => {
  res.render('home');
});

//Render register page
app.get('/register', (req, res) => {
  res.render('register');
});

//Render log in page
app.get('/login', (req, res) => {
  res.render('login');
}); 

app.get("/logout", function(req, res){
    req.logout(function(err) {
      if (err) {
        console.error("Logout error:", err);
      }
      res.redirect("/");
    });
  });
  


app.listen(process.env.PORT, function() {
    console.log("Server started on port 3000.");
  });
  