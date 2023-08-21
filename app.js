//Import Project Packages
import "dotenv/config";
import express from "express";
import mongoose from "mongoose";
import session from "express-session";
import passport from "passport";
import passportLocalMongoose from "passport-local-mongoose";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import passportFacebook from "passport-facebook";
import findOrCreate from "mongoose-findorcreate";
import { check, validationResult } from "express-validator";
import { MongoMissingCredentialsError } from "mongodb";

//Use middleware 
const app = express;
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
mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true,
  useCreateIndex: true,
  useUnifiedTopology: true 
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

// When dealing with manual input of a username (usually email) and password for local authentication, you need to implement serialization 
// and deserialization of user objects. This is necessary to manage user sessions and authentication state.
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function (err, user) {
      done(err, user);
    });
  });

//After finishing config, use the passport strategy. In this case Google and Facebook.
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
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
    callbackURL: "http://localhost:3000/auth/facebook/callback"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));