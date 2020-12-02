const jwt = require("jsonwebtoken");

function authorizeUser(req, res, next) {
    if (req.headers.authorization != undefined) {
      jwt.verify(
        req.headers.authorization,
        process.env.JWT_KEY,
        (err, decode) => {
          
          if(err && (err.toString()).includes("TokenExpiredError"))
          {
            res.status(401).json({
                message: "Token Expired, Please login Again.",
                result: false
            })
            return 
          }
          if (err) throw err;
          if (decode) {
            console.log(decode);
            next();
          } else {
            res.status(40).json({result: false, message: "User not logged in"});
          }
        }
      );
    } else {
        res.status(404).json({result: false, message: "User not logged in"});
    }
  }



  module.exports = {authorizeUser};