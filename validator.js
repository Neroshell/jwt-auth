import slowDown from 'express-slow-down';
const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000, // 15 minutes
  delayAfter: 100, // Start delaying after 100 requests
  delayMs: 500, // Delay each request by 500ms
});
