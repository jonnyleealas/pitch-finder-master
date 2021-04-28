/*jslint node: true */
'use strict';
require('dotenv').config();
const express = require("express");
const router = express.Router();
const passport = require("passport");
const util = require("util");
const url = require("url");
const querystring = require("querystring");
const pg = require('pg');
const DB = process.env.DATABASE_URL;
const client = new pg.Client(DB);
client.on('error', err => console.error(err));
client.connect();
require("dotenv").config();
//login route
router.get(
  "/login",
  passport.authenticate("auth0", {
    scope: "openid email profile"
  }),
  (req, res) => {
    res.redirect("/");
  }
);
//callback from AUTH0
router.get("/callback", (req, res, next) => {
  console.log("IN CALLBACK ROUTE")
  passport.authenticate("auth0", (err, user, info) => {
    console.log("START OF AUTHENTICATE")
    if (err) {
      console.log("we hit an error")
      return next(err);
    }
    if (!user) {
      console.log("didnt find user")
      return res.redirect("/login");
    }
    req.logIn(user, (err) => {
      if (err) {
        console.log("we hit an error in log in")
        return next(err);
      }
      const returnTo = req.session.returnTo;
      delete req.session.returnTo;
      let sql = 'SELECT user_id FROM users WHERE user_id = $1;';
      let safe = [req.user.user_id];
      client.query(sql, safe)
        .then(dbData => {
          if (dbData.rowCount === 0) {
            console.log("trying to redirect /users")
            res.redirect('/users');
          } else {
            console.log("trying to redirect to either ", returnTo, " or /events")
            res.redirect(returnTo || "/events");
          }
        });
    });
    console.log("END OF AUTHENTICATE")
  })(req, res, next);
});
//handles logout
router.get("/logout", (req, res) => {
  req.logOut();

  let returnTo = req.protocol + 's' + "://" + req.hostname;
  const port = req.connection.localPort;

  if (port !== undefined && port !== 80 && port !== 443) {
    returnTo =
      process.env.NODE_ENV === "production" ?
      `${returnTo}/` :
      `${returnTo}:${port}/`;
  }
  const logoutURL = new URL(// jshint ignore:line
    util.format("https://%s/logout", process.env.AUTH0_DOMAIN) 
  );
  const searchString = querystring.stringify({
    client_id: process.env.AUTH0_CLIENT_ID,
    returnTo: returnTo
  });
  logoutURL.search = searchString;

  res.redirect(logoutURL);
});

module.exports = router;