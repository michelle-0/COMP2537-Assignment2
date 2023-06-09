require("./utils.js");

require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

app.use(express.static(__dirname + "/public"));

const expireTime = 60 * 60 * 1000; // expires after 1 hour (minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include("databaseConnection");

const userCollection = database.db(mongodb_database).collection("users");
// db.getCollection("users").find({});
// await db.getCollection("users").updateOne({username: 'you'}, {$set: {user_type: 'user'}});

app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store
    saveUninitialized: false,
    resave: true,
  })
);

function isValidSession(req) {
  if (req.session.authenticated) {
    return true;
  }
  return false;
}

function sessionValidation(req, res, next) {
  if (isValidSession(req)) {
    next();
  } else {
    res.redirect("/login");
  }
}

function isAdmin(req) {
  if (req.session.user_type == "admin") {
    return true;
  }
  return false;
}

function adminAuthorization(req, res, next) {
  if (!isAdmin(req)) {
    res.status(403);
    res.render("errorMessage");
    return;
  } else {
    next();
  }
}

app.get("/home", (req, res) => {
    res.render("home");
    return;
})

app.get("/", (req, res) => {
  if (!req.session.username) {
    res.render("home");
    return;
  }
  var username = req.session.username;
  res.render("main", {username: username});
});

app.get("/admin", sessionValidation, adminAuthorization, async (req, res) => {
    const result = await userCollection.find().project({username:1, user_type: 1}).toArray();
    res.render("admin", {users: result});
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/signup", (req, res) => {
  res.render("signup");
});

app.post("/submitUser", async (req, res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;

  if (!username) {
    res.status(404);
    res.render("404-name");
    return;
  }

  if (!email) {
    res.status(404);
    res.render("404-email");
    return;
  }

  if (!password) {
    res.status(404);
    res.render("404-password");
    return;
  }

  const schema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ username, email, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/signup");
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({ username, email, password: hashedPassword, user_type: "user"});
  console.log("Inserted user");
  req.session.authenticated = true;
  req.session.username = username;
  req.session.cookie.maxAge = expireTime;
  res.redirect("/members");
  return;
});

app.get("/members", (req, res) => {
  if (!req.session.username) {
    res.redirect("/");
    return;
  }
  var username = req.session.username;

  var random = Math.floor(Math.random() * 3) + 1;
  res.render("members", { username: username, random: random });
});
app.use("/admin", sessionValidation);

app.post("/loggingin", async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });
  const validationResult = schema.validate({ email, password });

  if (validationResult.error != null) {
    console.log(validationResult.error);
    return;
  }

  const result = await userCollection
    .find({ email: email })
    .project({ username: 1, email: 1, password: 1, user_type: 1, _id: 1 })
    .toArray();

  console.log(result);
  if (result.length != 1) {
    console.log("user not found");
    return;
  }

  if (await bcrypt.compare(password, result[0].password)) {
    console.log("correct password");
    req.session.authenticated = true;
    req.session.username = result[0].username;
    req.session.email = email;
    req.session.user_type = result[0].user_type;
    req.session.cookie.maxAge = expireTime;
    console.log("username: " + req.session.username);
    console.log("usertype:" + req.session.user_type);
    res.redirect("/members");
    return;
  } else {
    console.log("incorrect password");
    res.send(
      'Invalid email/password combination.<br><br><a href="/login">Try again</a>'
    );
    return;
  }
});

app.get("/promote", async (req, res) => {
  const {username} = req.query; // Retrieve the 'username' from the query parameters
  console.log(username);

  await userCollection.updateOne(
    { username: username },
    { $set: { user_type: "admin" } }
  );

  res.render("promote");
});

app.get("/demote", async (req, res) => {
  const { username } = req.query; // Retrieve the 'username' from the query parameters
  console.log(username);

  await userCollection.updateOne(
    { username: username },
    { $set: { user_type: "user" } }
  );

  res.render("demote");
});


app.get("/logout", (req, res) => {
  req.session.destroy();
  res.render("logout");
});

app.use(express.static(__dirname + "/public"));

// app.get("/admin", sessionValidation, adminAuthorization, async (req, res) => {
//   const result = await userCollection
//     .find()
//     .project({ username: 1, _id: 1 })
//     .toArray();

//   res.render("admin", { users: result });
// });

app.get("*", (req, res) => {
  res.status(404);
  res.render("notFound");
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});
