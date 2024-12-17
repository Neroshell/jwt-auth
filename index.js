import dotenv from 'dotenv'; // Loads environment variables from a .env file into process.env
import express from 'express'; // Web framework for building RESTful APIs and web applications
import morgan from 'morgan'; // HTTP request logger middleware for Node.js, useful for logging requests
import cors from 'cors'; // Middleware to enable Cross-Origin Resource Sharing (CORS) to allow or restrict access from different domains
import multer from 'multer'; // Middleware for handling multipart/form-data, used for file uploads
import { Sequelize, DataTypes } from 'sequelize'; // Sequelize ORM for Node.js for interacting with SQL databases (e.g., MySQL, PostgreSQL)
import path from 'path'; // Provides utilities for working with file and directory paths
import { fileURLToPath } from 'url'; // Converts a URL to a file path (useful for ES modules in Node.js)
import AWS from 'aws-sdk'; // AWS SDK for interacting with AWS services (e.g., S3, DynamoDB, etc.)
import bcrypt from 'bcrypt'; // Library to hash and compare passwords securely
import jwt from 'jsonwebtoken'; // Library to generate and verify JSON Web Tokens for user authentication
import helmet from 'helmet'; // Middleware to set various HTTP headers to protect against common vulnerabilities (XSS, clickjacking, etc.)
import slowDown from 'express-slow-down'; // Middleware for rate limiting requests and slowing down the response rate
import enforce from 'express-sslify'; // Ensures that all requests are encrypted by forcing HTTPS (only for production environments)
import csrf from 'csurf'; // Middleware to protect against Cross-Site Request Forgery (CSRF) attacks by generating and validating CSRF tokens
import rateLimit from 'express-rate-limit'; // Middleware to limit the number of requests from a particular IP address in a specified time window


const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
});


const csrfProtection = csrf({ cookie: true });

app.use(speedLimiter);



// Set up __dirname for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// AWS configuration
AWS.config.update({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION,
});
const s3 = new AWS.S3();

// Sequelize Connection to PostgreSQL
const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'postgres',
  logging: false,
});

// Define User model with Sequelize
const User = sequelize.define('User', {
  name: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  age: {
    type: DataTypes.INTEGER,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  profilePicture: {
    type: DataTypes.JSON, // To store S3 profile picture details
  },
});

// Sync database
(async () => {
  try {
    await sequelize.authenticate();
    console.log('Database connected successfully.');
    await sequelize.sync({ alter: true }); // Sync models with DB
    console.log('Database models synced.');
  } catch (error) {
    console.error('Unable to connect to the database:', error.message);
  }
})();

// Multer setup
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
});

const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000, // 15 minutes
  delayAfter: 100, // Start delaying after 100 requests
  delayMs: 500, // Delay each request by 500ms
});

// Initialize Express app
const app = express();

// Middleware
app.use(express.json());
app.use(morgan('dev'));
app.use(cors());
app.use(speedLimiter);
app.use(helmet());
app.use(speedLimiter);
app.use(enforce.HTTPS({ trustProtoHeader: true }));
app.use(csrfProtection);
app.use(limiter);;

// Routes
app.get('/', (req, res) => {
  res.send('Hello, World!');
});

// User registration with file upload
app.post('/user', upload.single('profilePicture'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).send({ message: 'No file uploaded' });
    }

    // Upload file to S3
    const fileContent = req.file.buffer;
    const params = {
      Bucket: process.env.BUCKET_NAME,
      Key: `profile-pictures/${Date.now()}_${req.file.originalname.replace(/\s+/g, '_')}`,
      Body: fileContent,
      ContentType: req.file.mimetype,
    };
    const uploadResult = await s3.upload(params).promise();

    // Save user details in PostgreSQL
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = await User.create({
      name: req.body.name,
      email: req.body.email,
      age: req.body.age,
      password: hashedPassword,
      profilePicture: {
        fieldname: req.file.fieldname,
        originalname: req.file.originalname,
        url: uploadResult.Location,
        size: req.file.size,
      },
    });

    console.log('Saved User:', user);
    res.status(201).send({ message: 'User created successfully', user });
  } catch (error) {
    console.error('Error uploading file or saving user:', error.message);
    res.status(500).send({ message: 'Server error', error: error.message });
  }
});

// User Registration
app.post('/register', async (req, res) => {
  try {
    // Check if email already exists
    const existingUser = await User.findOne({ where: { email: req.body.email } });
    if (existingUser) {
      return res.status(400).send({ message: 'Email already registered' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    // Create new user
    const user = await User.create({
      name: req.body.name,
      email: req.body.email,
      age: req.body.age,
      password: hashedPassword,
    });

    res.status(201).json({
      message: 'User registered successfully',
      user: { id: user.id, name: user.name, email: user.email, age: user.age },
    });
  } catch (err) {
    console.error('Error saving user:', err.message);
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
});

// User Login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(403).send('User does not exist');
    }

    // Compare passwords
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(403).send('Invalid credentials');
    }

    // Generate JWT
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '24h' });

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Strict',
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    });

    res.json({ message: 'User authenticated successfully' });
  } catch (e) {
    console.error(e);
    res.status(500).send('Internal Server Error');
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Listening on port ${PORT}`);
});
