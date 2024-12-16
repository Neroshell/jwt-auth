const crypto = require('crypto');
const nodemailer = require('nodemailer'); // For sending emails
const resetTokens = {}; // Temporary in-memory store for reset tokens

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).send("User not found");
        }

        // Generate a reset token
        const resetToken = crypto.randomBytes(32).toString('hex');
        resetTokens[resetToken] = user._id;

        // Send reset link to user's email
        const resetLink = `http://yourapp.com/reset-password?token=${resetToken}`;
        const transporter = nodemailer.createTransport({ /* your SMTP config */ });
        await transporter.sendMail({
            to: email,
            subject: "Password Reset Request",
            text: `To reset your password, click the link: ${resetLink}`,
        });

        res.send("Password reset email sent");
    } catch (error) {
        res.status(500).send("Server error");
    }
});
