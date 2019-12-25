//file for /auth related routes (login, register, etc)

const express = require('express');
var jwt = require('jsonwebtoken');
var User = require('../model/user');
var bcrypt = require('bcryptjs');
var CryptoJS = require("crypto-js");
var env = require('../config/env');
var fs = require('fs');
var hskey = fs.readFileSync(env.HTTPS_KEY); //private key to encrypt api keys and secrets

const router = express.Router();

//logs to console if toggle is on
var logging = true;

function logger(message) {
  if (logging === true) {
    console.log(message);
  }
}

router.post('/login', function (req, res) {
  const email = req.body.email;
  const password = req.body.password;
  User.getUserByEmail(email, (err, user) => {
    if (err) {
      logger("login error1 ==> " + String(err));
      return res.json({ success: false, message: err });
    } else {
      if (!user) {
        logger("login failed: Email not in use " + email);
        return res.json({ success: false, message: 'Email not in use' });
      } else {
        User.validatePassword(password, user.password, (err, isMatch) => {
          if (err) {
            logger("login error2 ==> " + String(err));
            throw err;
          }
          if (isMatch) {
            // check nothing for the admin
            if (user.role === 'admin') {

            }
            // check if blocked
            else if (user.blocked === true) {
              logger("login failed ==> User " + email + " was blocked");
              return res.json({ success: false, buycoin: true });
            }
            // check if expired
            else if (user.lastPayAt.getTime() < new Date().getTime() - env.FREE_DAY * 24 * 60 * 60 * 1000 ) {
              logger("login failed ==> User " + email + " was expired");
              return res.json({ success: false, buycoin: true });
            }

            const token = jwt.sign({ user: req.user }, 'temp_pass');
            User.findOneAndUpdate({ email: email }, { token: token }, (err, user) => {
              if (err) {
                logger('login error3 ==> ' + err);
                res.json({ success: false, message: String(err) });
              } else {
                logger('login success: ' + user.email + ', token: ' + token);
                return res.json({ success: true, token: token, role: user.role });
              }
            });
          } else {
            logger("login failed: " + email + " Incorrect password");
            return res.json({ success: false, message: 'Incorrect password' });
          }
        });
      }
    }
  });
});

// update user settings
router.post('/settings', (req, res, next) => {
  ensureToken(req, res, (token)=> {
    // var token = req.body.token;
    var newPass = req.body.newPassword;
    var pass = req.body.password;
    var failure = { success: false };
    var success = { success: true, message: "password modified!" };
    var goodset = { success: true, message: "settings saved!" };

    logger("settings update requested with token " + token);
    console.log("settings post request body: " + JSON.stringify(req.body.apiKeys));
    // var encryptedKeys = CryptoJS.AES.encrypt(JSON.stringify(req.body.apiKeys), hskey);
    User.getUserByToken(token, (err, user) => {
      if (err) {
        res.json(failure);
      }
      if (user) {
        User.validatePassword(pass, user.password, (err, isMatch) => {
          if (err) {
            logger("error: " + String(err));
            failure.message = String(err);
            res.json(failure);
          }
          if (isMatch) {
            if (newPass) {
              User.editUser(user, newPass, err => {
                if (err) {
                  logger("failed to edit pass: " + String(err));
                  res.json(failure);
                }
                // console.log(success);
              });
            }
            User.findOneAndUpdate({ token: token }, {apiKeys: JSON.stringify(req.body.apiKeys)}, (err, user) => {
              if (err) {
                logger("error updating exchanges: " + String(err));
                failure.message = String(err);
                res.json(failure);
              } else {
                logger("keys updated");
                res.json(goodset);
              }
            });
          }
          else {
            var badpass = { success: false, message: "bad password" };
            console.log(badpass);
            res.json(badpass);
          }
        });
      }
    });
  });
});

//get 
// get settings for populating client form fields
router.get('/settings', (req, res, next) => {
  ensureToken(req, res, (token) =>{
    console.log("Settings requested with token: " + token);
    // const token = req.header("token");
    User.findOne({ token: token }, (err, user) => {
      if (err) {
        logger(String(err));
        res.json({ success: false, message: String(err) });
      } else {
        if (!user) {
          res.json({success:false, message: "Bad Token. Please try clearing your browsing history and logging in again."});
        } else {
          // check nothing for the admin
          if (user.role === 'admin') {

          }
          // check if user was blocked
          else if (user.blocked === true) {
            logger("login failed: User " + user.email + " was blocked");
            return res.json({ success: false, buycoin: true });
          } else if (user.lastPayAt.getTime() < new Date().getTime() - env.FREE_DAY * 24 * 60 * 60 * 1000 ) {
            logger("login failed: User " + user.email + " was expired");
            return res.json({ success: false, buycoin: true });
          }

          logger("successfully returned user settings: " + user);
          res.json({ success: true, message: user });
        }
      }
    });
  });
});

// get userlist
router.get('/userlist', (req, res, next) => {
  ensureToken(req, res, (token) => {
    logger("userlist requested with token: " + token);
    User.find({ role: 'user' }, (err, users) => {
      if (err) {
        logger('fetch userlist error ==> ' + String(err));
        res.json({ success: false, message: String(err) });
      } else {
        logger("successfully returned user list - count " + users.length);
        res.json({ success: true, users: users });
      }
    });
  });
});

// approve user
router.post('/approve', (req, res, next) => {
  ensureToken(req, res, (token) => {
    const { email, flag } = req.body;
    logger('user approve request: ' + email + ', ' + flag );
    User.findOneAndUpdate({ email }, { blocked: flag }, (err, user) => {
      if (err) {
        logger("user approve error: " + String(err));
        res.json({ success: false, message: String(err) });
      } else {
        if (!user) {
          logger("user approve error: User " + email + " does not exist");
          res.json({ success: false, message: "User " + email + " does not exist" });
        } else {
          logger("User " + email + " approve status changed ==> " + flag);
          res.json({ success: true, message: "User approve status has been changed" });
        }
      }
    });
  });
});

// remove user account
router.post('/remove', (req, res, next) => {
  ensureToken(req, res, (token) => {
    const { email } = req.body;
    logger('user account remove request ' + email);
    User.findOneAndRemove({ email }, (err, result) => {
      if (err) {
        logger(String(err));
        res.json({ success: false, message: String(err) });
      } else {
        logger("User " + email + " has been removed");
        res.json({ success: true, message: "User account has been removed" });
      }
    });
  });
});

// get settings for populating client form fields
router.post('/logout', (req, res, next) => {
  ensureToken(req, res, (token) => {
    console.log("logout request token " + token);
    User.findOneAndUpdate({ token: token }, { token: "" }, (err, user) => {
      if (err) {
        logger("logout error ==> " + String(err));
        res.json({ success: false, message: String(err) });
      } else {
        logger("logged out success token: " + token);
        return res.json({ success: true, message: "Successfully logged out" });
      }
    });
  });
});

router.post('/register', function (req, res) {
  const newUser = new User({
    email: req.body.email,
    password: req.body.password,
    token: '',
    role: 'user',
    blocked: false,
    createdAt: new Date(),
    lastPayAt: new Date()
  });

  logger("register request email: " + newUser.email + " password: " + newUser.password);

  User.getUserByEmail(newUser.email, (err, user) => {
    if (err) {
      logger("register error1 ==> " + String(err));
      return res.json({ success: false, message: err });
    } else {
      if (!user) {
        const token = jwt.sign({ user: newUser }, 'temp_pass');
        User.addUser(newUser, (err, user) => {
          if (err) {
            logger("register error2 ==> " + String(err));
            return res.json({ success: false, message: err });
          } else {
            logger("register success. email: " + newUser.email + " token: " + token + "");
            return res.json({ success: true, token: token });
          }
        });
      } else {
        logger("register error3 ==> Email " + newUser.email + " is already used");
        return res.json({
          success: false, message:
            "Email in use. Please log in or use another email instead"
        });
      }
    }
  });
});

//make sure a token was provided in a request, can be in req.body or a header
function ensureToken(req, res, next) {
  var headerToken = req.header("token");
  var bodyToken = req.body.token;
  if ((!headerToken || headerToken.length < 1) && (!bodyToken || bodyToken.length < 1)){
    res.json({success: false, message: 
      "Token is invalid. Please try clearing browsing history and logging in again"});
  }
  else{
    logger("ensured that token was provided. continuing with request...");
    if (headerToken && headerToken.length > 0){ next(headerToken) }
    else{
      next(bodyToken);
    }
  }
}

//make sure the user with the provided token has a registered account in the db
function ensureUser(req, res, next){
  ensureToken(req, res, (token)=>{
    User.findOne({ token: token }, (err, user) => {
      if (err) {
        res.json( { success: false, message: String(err) });
      } else {
        next(user);
      }
    });
  });
}

module.exports = {
  router: router,
  ensureToken: ensureToken,
  ensureUser: ensureUser
};
