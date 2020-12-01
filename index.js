const express = require("express");
const mongodb = require("mongodb");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const randomstring = require("randomstring");
const jwt_decode = require("jwt-decode");

const {authorizeUser, authorizeUserRedirectOnFailure} = require("./customMiddleWares/authentication");
const { sendMail } = require("./appUtils/appUtils")

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());

const ObjectId = mongodb.ObjectID;
const port = process.env.PORT;
const dbUrl = process.env.DBURL;
const frontEnd = process.env.FRONTEND;
const gmailUserName = process.env.GMAILID;
const gmailPassword = process.env.GMAILPASSWORD;


app.listen(port, () => console.log("App is running in port: ", port));

app.post("/register", async (req, res) => {
    try {
        let client = await mongodb.connect(dbUrl);
        let db = client.db("UrlShortnerDB");
        let data = req.body;
        let salt = await bcrypt.genSalt(8);
        console.log(data);
        let result = await db.collection("users").findOne({email: data.email});

        if (result) {
            res.status(409).json({result: false, message: "User Already exists!"});
            return;
        }
        data.status = "inactive";
        data.activationToken = randomstring.generate();
        data.passwordModificationToken = "";
        data.password = await bcrypt.hash(data.password, salt);
        let link = frontEnd + "/verifyEmail.html?token=" + data.activationToken
        let message = "<p style='color:black;font-weight:bold'> Please click the below url to verify your account </p> <br>" + 
        "<a href='" + link + "'>" + link + "</a>";
        let subject = "Account Verification"

        console.log(gmailUserName, "++++++", gmailPassword)
        result = await sendMail(data.email, message, subject, gmailUserName, gmailPassword);
        console.log(result)
        console.log(message);

        console.log(data);

        // result = await db.collection("users").insertOne(data);
        res.status(200).json({message: "User added successfully", result: true});
    } catch (err) {
        console.log(err);
        res.status(500).json({message: "Internal server error", result: false});
    }
});

app.post("/users/active/:token", async (req, res) => {
    try {
        let client = await mongodb.connect(dbUrl);
        let db = client.db("UrlShortnerDB");
        let result = await db.collection("users").findOne({activationToken: req.params.token});
        if (! result) {
            res.status(400).json({result: false, message: "Please enter a valid activation URL!"});
            return;
        }

        result = await db.collection("users").findOneAndUpdate({
            activationToken: req.params.token
        }, {
            $set: {
                status: "active"
            }
        });
        res.status(200).json({message: "User Activated", result: true});
    } catch (err) {
        res.status(500).json({message: "Internal Server error", result: false});
    }
});

app.post("/users/:email", async (req, res) => {
    try {
        let client = await mongodb.connect(dbUrl);
        let db = client.db("UrlShortnerDB");
        let result = await db.collection("users").findOne({email: req.params.email});
        if (! result) {
            res.status(404).json({result: false, message: "Please enter a valid Email!"});
            return;
        }
        res.status(200).json({message: "Email Id is Valid", result: true});
    } catch (err) {
        res.status(500).json({message: "Internal Server error", result: false});
    }
});

app.post("/login", async (req, res) => {
    try {
        let client = await mongodb.connect(dbUrl);
        let db = client.db("UrlShortnerDB");
        let data = await db.collection("users").findOne({email: req.body.email});
        if (data) {
            if (data.status !== "active") {
                res.status(409).json({result: false, message: "Account not activated, Please activate Your account"});
                client.close();
                return;
            }
            let isValid = await bcrypt.compare(req.body.password, data.password);
            if (isValid) {
                let token = await jwt.sign({
                    userId: data._id,
                    email: data.email
                }, process.env.JWT_KEY, {expiresIn: "1h"});
                console.log("valid user", isValid);
                console.log("token", token);
                res.status(200).json({result: true, message: "login successful", token});
            } else {
                res.status(403).json({result: false, message: "invalid password"});
            }
        } else {
            res.status(401).json({result: false, message: "Email ID is not registered"});
        } client.close();
    } catch (error) {
        console.log(error);
        res.status(500).json({message: "Internal Server error", result: false});
    }
});

app.post("/users/forgotPassword/:email", async (req, res) => {
    try {
        let client = await mongodb.connect(dbUrl);
        let db = client.db("UrlShortnerDB");
        let email = req.params.email;

        passwordModificationToken = randomstring.generate();

        let link = frontEnd + "/changePassword.html?token=" + passwordModificationToken + "&&email=" + email;
        let message = "<p style='color:black;font-weight:bold'> Please click the below url to change Password</p> <br>" + 
        "<a href='" + link + "'>" + link + "</a>";
        let subject = "Password Reset Link"

        console.log(gmailUserName, "++++++", gmailPassword)
        result = await sendMail(email, message, subject, gmailUserName, gmailPassword);
        console.log(result)
        console.log(message);

        console.log(data);


        let result = await db.collection("users").findOne({email: req.params.email});
        result = await db.collection("users").findOneAndUpdate({
            email: email
        }, {
            $set: {
                passwordModificationToken: passwordModificationToken
            }
        });
        res.status(200).json({message: "Reset link sent!", result: true});
    } catch (err) {
        console.log(err);
        res.status(500).json({message: "Internal server error", result: false});
    }
});

app.post("/users/passwordReset/:email", async (req, res) => {
    try {
        let client = await mongodb.connect(dbUrl);
        let db = client.db("UrlShortnerDB");
        let email = req.params.email
        let token = req.body.token
        let result = await db.collection("users").findOne({passwordResetToken: token, email: email});
        if (! result) {
            res.status(400).json({result: false, message: "Please enter a valid activation URL!"});
            return;
        }

        res.status(200).json({message: "User authenticated successfully", result: true});
    } catch (err) {
        res.status(500).json({message: "Internal Server error", result: false});
    }
});

app.post("/users/changePassword/:email", async (req, res) => {
    try {
        let client = await mongodb.connect(dbUrl);
        let db = client.db("UrlShortnerDB");
        let newPassword = req.body.password;
        let result = await db.collection("users").findOne({email: req.params.email});
        if (! result) {
            res.status(404).json({result: false, message: "User Not found!"});
            return;
        }
        result = await db.collection("users").findOneAndUpdate({
            email: req.params.email
        }, {
            $set: {
                password: newPassword,
                passwordModificationToken: ""
            }
        });
        res.status(200).json({message: "Password Reset Successful!", result: true});
    } catch (err) {
        console.log(err);
        res.status(500).json({message: "Internal server error", result: false});
    }
});

app.get("/shortenUrls", [authorizeUser], async (req, res) => {
    try {
        let client = await mongodb.connect(dbUrl);
        let db = client.db("UrlShortnerDB");

        let authHeader = req.headers.authorization;
        let decodedHeader = jwt_decode(authHeader);
        let email = decodedHeader.email;
        let url = req.body.url;
        let token = randomstring.generate(6);
        result = await db.collection("urls").insertOne({email: email, url: url, token: token, createdTime: new Date()});
        res.status(200).json({message: "URL Shortening Successful!", result: true, shotenedUrlToken: token});
    } catch (err) {
        console.log(err);
        res.status(500).json({message: "Internal server error", result: false});
    }
});

app.get("/redirect/:urlToken", [authorizeUser], async (req, res) => {
    try {
        let client = await mongodb.connect(dbUrl);
        let db = client.db("UrlShortnerDB");

        let authHeader = req.headers.authorization;
        let decodedHeader = jwt_decode(authHeader);
        let email = decodedHeader.email;

        let result = await db.collection("urls").findOne({email: email, token: req.params.urlToken});

        if (! result) {
            res.status(404).json({message: "Invalid URL", result: false});
            return;
        }
        console.log(result);
        let url = result.url;
        console.log(url);
        // res.redirect(url);
        res.status(200).json({message: "URL found !", result: true, url: url});
    } catch (err) {
        console.log(err);
        res.status(500).json({message: "Internal server error", result: false});
    }
});


app.get("/urls", [authorizeUser], async (req, res) => {
    try {
        let client = await mongodb.connect(dbUrl);
        let db = client.db("UrlShortnerDB");

        let authHeader = req.headers.authorization;
        let decodedHeader = jwt_decode(authHeader);
        let email = decodedHeader.email;
        console.log(email)
        let result = await db.collection("urls").find({email: email});

        if (! result) {
            res.status(404).json({message: "Invalid URL", result: false});
            return;
        }
        // console.log(result)
        result = await result.toArray()
        console.log(result)
        // res.redirect(url);
        res.status(200).json({
            body: result,
            result: true
        });
    } catch (err) {
        console.log(err);
        res.status(500).json({message: "Internal server error", result: false});
    }
});