const express = require("express"); 
const bodyParser = require("body-parser") //helps parse body of request
const cors = require("cors"); 
const bcrypt = require("bcryptjs")
const compression = require("compression"); //optimization? compresses response, so sends faster
const pool = require("./db"); //this connects the local (for now) database to the application
const app = express(); //creates express app
const path = require("path")

//our email handler
const nodemailer = require("nodemailer"); 

//unique string for the unique url sent to newly created user
const {v4: uuidv4} = require("uuid")

//env variables
require("dotenv").config(); 

//nodemailer thingies
let transporter = nodemailer.createTransport({
    host: "smtp-mail.outlook.com", // hostname
    secureConnection: false, // TLS requires secureConnection to be false
    port: 587, // port for secure SMTP
    tls: {
       ciphers:'SSLv3'
    },
    //nodemailer sends email from my email address
    auth: {
        user: process.env.AUTH_EMAIL, 
        pass: process.env.AUTH_PASS

    }
})

//testing transporter 
transporter.verify((error, success)=> {
    if(error){
        console.log(error); 
    }else{
        console.log("ready for messages!!! Lets Goooooo"); 
        console.log(success); 
    }
})

//sending the verification email
const sendVerificationEmail = (_id, email, res) => {
    //url to be used in the email 
    const currentUrl = "http://localhost:5000/"; 
    
    const uniqueString = uuidv4() + _id; 

    const mailOptions = {
        from: process.env.AUTH_EMAIL, 
        to: email, 
        subject: "Verify Your Email", 
        html:`<p>Verify your email address by clicking this link, This link expires in six hours </p>
        <p>Click <a href=${currentUrl + "user/verify/" + _id + "/" + uniqueString}>here</a> to proceed.</p>`
        
    }

    //hashing the unique string for some reason 
        const saltRounds = 10; 

    bcrypt.hash(uniqueString, saltRounds)
    .then((hashedUniqueString) => {
        //set values in userverification collection 
        try {
                const createdat = Date.now();
                const expiresat = Date.now() + 21600000; 
    
                pool.query(
                    `INSERT INTO usersverification (userid, uniquestring, createdat, expiresat) VALUES ($1, $2, to_timestamp(${createdat} / 1000.0), to_timestamp(${expiresat} / 1000.0)) RETURNING *`, 
                    [_id, hashedUniqueString]
                ).then(()=> {
                    transporter.sendMail(mailOptions)
                    .then(() => {
                        //email sent and verification record saved
                        res.json({
                            status: "PENDING", 
                            message: "Verification email sent"
                        })
                    })
                    .catch((error) => {
                        console.log(error); 
                        res.json({
                            status: "FAILED", 
                            message: "Verification email failed"
                        })
                    })
                })
            
        } catch (error) {
            console.log(error); 
            console.log(_id)
            res.json({
                status: "FAILED", 
                message: "Couldn't save verification email data!" 
            }) 
        }
}
    )
}

const {emailValidation, passwordValidation} = require("./validation"); 
const { useImperativeHandle } = require("react");
const { Router, response } = require("express");

//middleware
app.use(cors())
app.use(compression())
app.use(bodyParser.json())

app.listen(5000, () => { 
    //res.send("Hello World!")
    console.log("server started on port 5000, heyyy"); 
})

//This function runs when the link in your email is clicked.
app.get("/user/verify/:userId/:uniqueString", async (req, res) => {
    
    try {
    const {userId, uniqueString} = req.params; 
    const verifyUser = await pool.query("SELECT * FROM usersverification WHERE userid = $1", 
    [userId])

        if(verifyUser.rows.length>0){
            //user verification record exists so we proceed 
            const hashedUniqueString = verifyUser.rows[0].uniquestring; 
            const {expiresat} = verifyUser.rows[0].expiresat; 
            if(expiresat < Date.now()) {
                //record has expired so we delete it 
                pool.query("DELETE * FROM usersverification WHERE userid = $1", [userId])
                .catch((error) => {
                    console.log(error); 
                    let message ="an error occured while clearing expired user verification record"; 
                    
                })
            }
            else{
                //has not expired, so we validate the user string
                const newtrim = hashedUniqueString.trim(); 
                bcrypt.compare(uniqueString,newtrim) //here is your next issue, figure out this unique string stuff, and why it isnt working
                .then(result => {
                    
                    if(result) {
                        //string matches 
                        pool.query("UPDATE users SET verified = true WHERE id = $1", 
                        [userId])
                        console.log("verification is done");
                        try{
                            console.log("lets try to setup file");
                            var options = {
                                root: path.join(__dirname)
                            };
                             
                            var fileName = 'verified.html';
                            res.sendFile(fileName, options, function (err) {
                                console.log("were setting up file?")
                                if (err) {
                                    next(err);
                                    console.log("file failure")
                                } else {
                                    console.log('Sent:', fileName);
                                    
                                }
                            });  
                        }
                    
                    catch (error){
                        res.status(500).json({error: error.message})
                        console.log(error); 
                        console.log("fatal error")
                    }
                    }
                    else{
                        //existing record but incorrect verification details passed
                        console.log("invalid verification details passed")
                    }
                })
                .catch((error) => {
                    let message = "an error occured while comparing strings"
                })
            }
        }
        else{
            //it dont exist
            let message = "account record doesnt exist or has been verified already "
            res.json(message)

        }
    } catch (error) {
        console.log(error)
        let message = "An error occured while checking for existing user verification record"
        res.json(error)

    }
})









app.post ("/createUser", async (request, response) => {
    try{
    const {username, email, password, id} = request.body;
    const verified = false; 
    let errors = {}                     //maybe const?

    if (!emailValidation(email)){
        errors.email = "Email is not valid"; 
    }
    if (!passwordValidation(password)){
        errors.password = "Password is not valid"; 
    }

    const isEmailInUse = await pool.query(
        "SELECT * FROM users WHERE email = $1", 
        [email]
    );
    
    
    if (isEmailInUse.rows.length > 0){
        errors.email = "Email is already in use"
    }

    if (Object.keys(errors).length > 0){
        return response.status(400).json(errors);
        
    }
    
    const salt = await bcrypt.genSalt(10);//salt encryption
    const hashedPassword = await bcrypt.hash(password, salt); //hash encryption
    
    const newUser = await pool.query(
        "INSERT INTO users (email, username, password, verified) VALUES ($1, $2, $3, $4) RETURNING *", 
        [email, username, hashedPassword, verified]
    )

    
    //response.json({success: true, data: newUser.rows[0].id}); 
    const verificationEmailIsSending = await sendVerificationEmail(newUser.rows[0].id, email, response )//send verification email
    if (success = true){
        verificationEmailIsSending
    }
}
catch (error){
    response.status(500).json({error: error.message})
    console.log("an error occurred in the createUser route")
}
})



app.post ("/login", async(request, response) => {
    try {
        const {email, password} = request.body; 
        let errors = {}

        const user = await pool.query(
            "SELECT * FROM users WHERE email = $1", 
            [email]
        )
        
        if (user.rows.length === 0){
            response.status(400).json({ errors: "Email is not registered"});  
        }
        const hashPassTrim = user.rows[0].password.trim(); //we trim the password from the db

        const isMatch = await bcrypt.compare(password, hashPassTrim); //compare pw to hashed pw
        if(!isMatch){
            response.status(401).json({ errors: "Password is incorrect"}); 
        }
        if (user.rows[0].verified){
            //if they are verified 
            response.json({username: user.rows[0].username}); 
        }else{
            //they are not verified
            response.status(402).json({ errors: "Login unsuccessful, please verify your email"}); 
        }

        
        
    }catch(error) {
        console.error(error.message)
    }
})
 
