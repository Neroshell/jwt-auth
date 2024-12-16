app.post('/logout', (req, res) => {
    res.clearCookie('token');  // Clear the JWT cookie
    res.send("User logged out successfully");
});
