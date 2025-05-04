const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;


const port = process.env.PORT || 3000;
const app = express();
const Joi = require('joi');



app.use(session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: true,
}));

app.use(express.urlencoded({ extended: false }));

app.get('/', (req, res) => {
    res.send(`
        <html>
        <body>
        <form method="POST" action="/signup">
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
    if(validationResult.name != null)
    {
        console.log(validationResult.error);
        res.send(`
            <html>
            <body>
            <p>Invalid Name</p>
            <a href="/signup">Try again</a>
            </body>
            </html>`)
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    

})

app.listen(port, console.log(`Server is running on http://localhost:${port}`));