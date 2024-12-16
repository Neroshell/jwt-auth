app.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;

    try {
        // Check if the token is valid
        const userId = resetTokens[token];
        if (!userId) {
            return res.status(400).send("Invalid or expired token");
        }

        // Find the user and update the password
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).send("User not found");
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        await user.save();

        // Remove the reset token
        delete resetTokens[token];

        res.send("Password reset successful");
    } catch (error) {
        res.status(500).send("Server error");
    }
});
