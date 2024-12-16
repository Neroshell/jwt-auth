const authenticate = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(403).send("Access denied. No token provided.");
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).send("Invalid token");
        }

        req.user = decoded;  // Attach user info to request
        next();
    });
};


//protected route

app.put('/profile', authenticate, async (req, res) => {
    try {
        const { email, name } = req.body;
        const user = await User.findById(req.user.id);

        if (!user) {
            return res.status(404).send("User not found");
        }

        user.email = email || user.email;
        user.name = name || user.name;

        await user.save();
        res.send("Profile updated successfully");
    } catch (error) {
        res.status(500).send("Server error");
    }
});
