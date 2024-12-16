const bcrypt = require('bcrypt'); // Assume you have a User model
const jwt = require('jsonwebtoken');
require('dotenv').config();

app.post('/register', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).send("User already exists");
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create and save new user
        const newUser = new User({ email, password: hashedPassword });
        await newUser.save();

        res.status(201).send("User registered successfully");
    } catch (error) {
        res.status(500).send("Server error");
    }
});
