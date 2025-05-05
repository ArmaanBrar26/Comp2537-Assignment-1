require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const { MongoClient } = require('mongodb');

const port = process.env.PORT || 3000;
const app = express();
const Joi = require('joi');

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

app.use(express.urlencoded({ extended: false }));

const client = new MongoClient(`mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}?retryWrites=true&w=majority`);

async function connectToDatabase() {
    try {
        await client.connect();
        console.log('Connected to MongoDB');
        return client.db(mongodb_database);
    } catch (error) {
        console.error('Error connecting to MongoDB:', error);
        process.exit(1); // Exit the application if the database connection fails
    }
}

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret,
    }
});

app.use(session({
    store: mongoStore,
    secret: node_session_secret,
    resave: false,
    saveUninitialized: true,
}));


app.get('/', (req, res) => {
    res.send(`
        <html>
        <body>
        <form method="GET" action="/signup">
        <button type="submit">Sign Up</button>
        </form>
        <form method="POST" action="/login">
        <button type="submit">Login</button>
        </form>
        </body>
        </html>`)
});

app.get('/signup', (req, res) => {
    res.send(`
        <html>
        <body>
        <h1>Create User</h1>
        <form method="POST" action="/members">
        <input type="text" name="name" placeholder="Name"/>
        <input type="email" name="email" placeholder="Email"/>
        <input type="password" name="password" placeholder="Password"/>
        <button type="submit">Sign Up</button>
        </form>
        </body>
        </html>`)
});

app.post('/members', async (req, res) => {
    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;

    const schema = Joi.object({
        name: Joi.string().alphanum().max(20).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ name, email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        return res.send(`
            <html>
            <body>
            <p>${validationResult.error.message}</p>
            <a href="/signup">Try again</a>
            </body>
            </html>`);
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ name, email, password: hashedPassword });

    req.session.user = { name, email };

    res.redirect('/members'); 
});

app.get('/members', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/');
    }
    res.send(`
        <html>
        <body>
        <h1>Welcome ${req.session.user.name}</h1>
        <form method="POST" action="/logout">
        <button type="submit">Logout</button>
        </form>
        </body>
        </html>`);
});

// 404 Page Not Found Handler
app.get('*', (req, res) => {
    res.status(404);
    res.send(`
        <html>
        <body>
        <h1>Page Not Found - 404</h1>
        <p>The page you are looking for does not exist.</p>
        <a href="/">Go back to Home</a>
        </body>
        </html>`);
});

async function startServer() {
    const database = await connectToDatabase();
    const userCollection = database.collection('users');

    // Your existing server setup code goes here
    app.listen(port, () => {
        console.log(`Server is running on http://localhost:${port}`);
    });
}

startServer();