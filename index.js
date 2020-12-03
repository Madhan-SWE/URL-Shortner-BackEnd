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

            res.status(409).json({result: false, message: "User Already exists!", status: 409});
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

        result = await db.collection("users").insertOne(data);
        res.status(200).json({
            message: "Registration successful, Please check your email to activate your account.",
            result: true,
            status: 200
        });
    } catch (err) {
        console.log(err);
        res.status(500).json({message: "Internal server error", result: false, status: 500});
    }
});

app.post("/users/active/:token", async (req, res) => {
    try {
        let client = await mongodb.connect(dbUrl);
        let db = client.db("UrlShortnerDB");
        let result = await db.collection("users").findOne({activationToken: req.params.token});
        if (! result) {
            res.status(400).json({result: false, message: "Please enter a valid activation URL!", status: 400});
            return;
        }

        result = await db.collection("users").findOneAndUpdate({
            activationToken: req.params.token
        }, {
            $set: {
                status: "active"
            }
        });
        res.status(200).json({message: "User Activation successful, Please Login.", result: true, status: 200});
    } catch (err) {
        res.status(500).json({message: "Internal Server error", result: false, status: 500});
    }
});

app.post("/users/:email", async (req, res) => {
    try {
        let client = await mongodb.connect(dbUrl);
        let db = client.db("UrlShortnerDB");
        let result = await db.collection("users").findOne({email: req.params.email});
        if (! result) {
            res.status(404).json({result: false, message: "Please enter a valid Email!", status: 404});
            return;
        }
        res.status(200).json({message: "Email verified!", result: true, status: 200});
    } catch (err) {
        res.status(500).json({message: "Internal Server error", result: false, status: 500});
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
                res.status(200).json({result: true, message: "login successful", token: token, status: 200});
            } else {
                res.status(403).json({result: false, message: "invalid username or password!", status: 400});
            }
        } else {
            res.status(401).json({result: false, message: "Email ID is not registered", status: 401});
        } client.close();
    } catch (error) {
        console.log(error);
        res.status(500).json({message: "Internal Server error", result: false, status: 500});
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
        let wait = await sendMail(email, message, subject, gmailUserName, gmailPassword);
        // console.log(result)
        console.log(message);


        let result = await db.collection("users").findOne({email: req.params.email});
        result = await db.collection("users").findOneAndUpdate({
            email: email
        }, {
            $set: {
                passwordModificationToken: passwordModificationToken
            }
        });
        res.status(200).json({message: "Please check your email to reset password.", result: true, status: 200});
    } catch (err) {
        console.log(err);
        res.status(500).json({message: "Internal server error", result: false, status: 500});
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
            res.status(400).json({result: false, message: "Please enter a valid activation URL!", status: 400});
            return;
        }

        res.status(200).json({message: "User authenticated successfully", result: true, status: 200});
    } catch (err) {
        res.status(500).json({message: "Internal Server error", result: false, status: 500});
    }
});

app.post("/users/changePassword/:email", async (req, res) => {
    try {
        let client = await mongodb.connect(dbUrl);
        let db = client.db("UrlShortnerDB");
        let newPassword = req.body.password;
        let result = await db.collection("users").findOne({email: req.params.email});
        let salt = await bcrypt.genSalt(8);
        if (! result) {
            res.status(404).json({result: false, message: "User Not found!", status: 404});
            return;
        }
        result = await db.collection("users").findOneAndUpdate({
            email: req.params.email
        }, {
            $set: {
                password: await bcrypt.hash(newPassword, salt),
                passwordModificationToken: ""
            }
        });
        res.status(200).json({message: "Password Reset Successful!", result: true, status: 200});
    } catch (err) {
        console.log(err);
        res.status(500).json({message: "Internal server error", result: false, status: 500});
    }
});


app.post("/shortenUrls", [authorizeUser], async (req, res) => {
    try {
        let client = await mongodb.connect(dbUrl);
        let db = client.db("UrlShortnerDB");

        let authHeader = req.headers.authorization;
        let decodedHeader = jwt_decode(authHeader);
        let email = decodedHeader.email;
        let url = req.body.url; 
        console.log(req.body)

        let token = randomstring.generate(6);
        let data = {
            email: email,
            token: token,
            
            createdTime: new Date(),
            url
        }
        console.log(data);
        result = await db.collection("urls").insertOne(data);
        res.status(200).json({message: "URL Shortening Successful!", result: true, token, status: 200});
    } catch (err) {
        console.log(err);
        res.status(500).json({message: "Internal server error", result: false, status: 500});
    }
});

// [authorizeUser],

app.get("/redirect/:urlToken", [authorizeUser], async (req, res) => {
    try {
        let client = await mongodb.connect(dbUrl);
        let db = client.db("UrlShortnerDB");

        let authHeader = req.headers.authorization;
        let decodedHeader = jwt_decode(authHeader);
        let email = decodedHeader.email;
        // email = "rcmadhankumar@gmail.com"

        let result = await db.collection("urls").findOne({email: email, token: req.params.urlToken});

        if (! result) {
            res.status(404).json({message: "Invalid URL", result: false, status: 404});
            return;
        }
        console.log(result);
        let url = result.url;
        console.log(url);
        // res.redirect(url);
        res.status(200).json({message: "URL found !", result: true, url: url, status: 200});
    } catch (err) {
        console.log(err);
        res.status(500).json({message: "Internal server error", result: false, status: 500});
    }
});

// 

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
        result = await result.toArray()
        console.log(result)
        res.status(200).json({
            body: result,
            result: true,
            status: 200
        });
    } catch (err) {
        console.log(err);
        res.status(500).json({message: "Internal server error", result: false, status: 500});
    }
});


app.get("/urls/dashboardData", [authorizeUser], async (req, res) => {
    try {
        let client = await mongodb.connect(dbUrl);
        let db = client.db("UrlShortnerDB");

        let authHeader = req.headers.authorization;
        let decodedHeader = jwt_decode(authHeader);
        let email = decodedHeader.email;
        
        console.log(email)
        
        let d = new Date();
        d.setDate(d.getDate()-7)
        let urls_per_day_result = await db.collection("urls").aggregate([
            {
                $match: {
                    email: email,
                    createdTime: {
                        $gte: d
                    }
                }
            },
            {
                $sort: {
                    createdTime: -1
                }
            },
            {
                $project: {
                    dateString: {
                        $dateToString: { format: "%Y-%m-%d", date: "$createdTime"}
                    }
                }
            },
            {
                $group: {
                    _id: "$dateString",
                    count: {
                        $sum: 1
                    }
                }
            },
            {
                $project: {
                    date: {
                        $toDate: "$_id"
                    },
                    count: 1
                }
            },
            {
                $sort: {
                    _id: 1
                }
            }
        ])
        
        
        if (! urls_per_day_result) {
            res.status(404).json({message: "Invalid URL", result: false, status: 404});
            return;
        }
        urls_per_day_result = await urls_per_day_result.toArray()
        
        d = new Date();
        d.setDate(d.getDate()-180)
        let urls_per_month_result = await db.collection("urls").aggregate([
            {
                $match: {
                    email: email,
                    createdTime: {
                        $gte: d
                    }
                }
            },
            {
                $sort: {
                    createdTime: -1
                }
            },
            {
                $project: {
                    month: {
                        $month: "$createdTime"
                    }
                }
            },
            {
                $group: {
                    _id: "$month",
                    count: {
                        $sum: 1
                    }
                }
            },
            {
                $sort: {
                    _id: -1
                }
            },
            {
                $addFields: {
                    month: {
                        $let: {
                            vars: {
                                monthsInString: [, 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'July', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
                            },
                            in: {
                                $arrayElemAt: ['$$monthsInString', '$_id']
                            }
                        }
                    }
                }
            }
        ])

        if (! urls_per_month_result) {
            res.status(404).json({message: "Invalid URL", result: false, status: 404});
            return;
        }

        urls_per_month_result = await urls_per_month_result.toArray()

        res.status(200).json({
            body: {
                urls_per_day_result,
                urls_per_month_result
            },
            result: true,
            status: 200
        });
    } catch (err) {
        console.log(err);
        res.status(500).json({message: "Internal server error", result: false, status: 500});
    }
});

app.get("/login", [authorizeUser], async (req, res) => {
    try {
            res.status(200).json({
            result: true,
            status: 200
        });
    } catch (err) {
        console.log(err);
        res.status(500).json({message: "Internal server error", result: false, status: 500});
    }
});