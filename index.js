require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;
const { MongoClient } = require("mongodb");

const port = process.env.PORT || 3000;
const app = express();
const Joi = require("joi");
const { get } = require("http");

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USERNAME;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

app.use(express.urlencoded({ extended: false }));
app.use(express.static("public"));
app.set("view engine", "ejs");
app.set("views", __dirname + "/public/views");

const client = new MongoClient(
    `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}?retryWrites=true&w=majority`
);

async function connectToDatabase() {
    try {
        await client.connect();
        console.log("Connected to MongoDB");
        return client.db(mongodb_database);
    } catch (error) {
        console.error("Error connecting to MongoDB:", error);
        process.exit(1);
    }
}

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret,
    },
});

app.use(
    session({
        store: mongoStore,
        secret: node_session_secret,
        resave: false,
        saveUninitialized: true,
        cookie: { maxAge: 60 * 60 * 1000 },
    })
);

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req, res, next) 
{
    if(isValidSession(req)) 
        {
        next();
        }
        else 
        {
            res.redirect("/login");
        }
}

function isAdmin(req)
{
    if(req.session.user.user_type == "admin")
    {
        return true;
    }
    return false;
}

async function adminAuthorization(req, res, next) {
    const userCollection = req.app.locals.userCollection;

    try {
        const user = await userCollection.findOne({ email: req.session.user.email });

        if (!user) {
            res.status(403);
            return res.render("errorMessage", { validationResult: "User not found" });
        }
        req.session.user.user_type = user.user_type;

        if (!isAdmin(req)) {
            res.status(403);
            return res.render("errorMessage", { validationResult: "You are not authorized to access this page" });
        }

        next();
    } catch (error) {
        console.error("Error in adminAuthorization middleware:", error);
        res.status(500).send("Internal Server Error");
    }
}

app.get("/", (req, res) => {
    if (req.session.user) {
        let data = {
            user: req.session.user,
        };
        res.render("members", data);
    } else {
        res.render("index");
    }
});

app.get("/signup", (req, res) => {
    res.render("signup");
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/about", (req, res) => {
    res.render("about");
});

app.get("/contact", (req, res) => {
    res.render("contact");
});

app.post("/login", async (req, res) => {
    const userCollection = req.app.locals.userCollection;
    const email = req.body.email;
    const password = req.body.password;

    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required(),
    });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error != null) {
        let data = {
            validationResult: validationResult.error.message,
        };
        return res.render("errorMessage", data);
    }

    const user = await userCollection.findOne({ email });
    if (!user) {
        let data = {
            validationResult: "User not found",
        };
        return res.render("errorMessage", data);
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
        let data = {
            validationResult: "Invalid password",
        };
        return res.render("errorMessage", data);
    }

    req.session.user = { name: user.name, email: user.email, user_type: user.user_type };
    req.session.authenticated = true;
    res.redirect("/members");
});

app.post("/members", async (req, res) => {
    const userCollection = req.app.locals.userCollection;
    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;

    const schema = Joi.object({
        name: Joi.string().alphanum().max(20).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required(),
    });

    const validationResult = schema.validate({ name, email, password });
    if (validationResult.error != null) {
        let data = {
            validationResult: validationResult.error.message,
        };
        return res.render("errorMessage", data);
    }

    const existingUser = await userCollection.findOne({ email });
    if (existingUser) {
        let data = {
            validationResult: "User already exists",
        };
        return res.render("errorMessage", data);
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
        name,
        email,
        password: hashedPassword,
        user_type: "user",
    });

    req.session.user = { name, email };
    req.session.authenticated = true;
    res.redirect("/members");
});

app.get("/members", (req, res) => {
    if (!req.session.user) {
        return res.redirect("/");
    }

    console.log("User session:", req.session.user); 

    const images = ["champ.jpg", "jayson-tatum-and-jaylen-brown.jpg", "Jayson.jpg.webp"];
    let data = {
        user: req.session.user,
    };
    res.render("members", data);
});

app.get("/logout", (req, res) => {
    res.render("logout");
});

app.post("/logout", async (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Error destroying session:", err);
            return res.status(500).send("Internal Server Error");
        }
        res.redirect("/");
    });
});

app.get("/admin", sessionValidation, adminAuthorization, async (req, res) => {
    const userCollection = req.app.locals.userCollection;
    const result = await userCollection.find().project({name: 1, user_type: 1, _id: 0}).toArray();

    console.log("Users fetched from database:", result);

    res.render("admin", { users: result });
});

app.post("/admin/updateUserType", sessionValidation, adminAuthorization, async (req, res) => {
    const userCollection = req.app.locals.userCollection;
    const { name, user_type } = req.body;

    try {
        const result = await userCollection.updateOne(
            { name: name }, 
            { $set: { user_type: user_type } } 
        );
        res.redirect("/admin");    
    } catch (error) {
        console.error("Error updating user type:", error);
        res.status(500).send("Internal Server Error");
    }
});


async function startServer() {
    const database = await connectToDatabase();
    const userCollection = database.collection("users");

    app.locals.userCollection = userCollection;

    app.listen(port, "0.0.0.0", () => {
        console.log(`Server is running on http://localhost:${port}`);
    });
}

startServer();

app.get("*dummy", (req, res) => {
    res.status(404);
    res.render("404");
});
