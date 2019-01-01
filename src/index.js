const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv').config({ path: 'variables.env' });
const createServer = require('./createServer');
const db = require('./db');

const server = createServer();

// Use express middleware to handle cookies
server.express.use(cookieParser());

// decode the JWT to get the user ID on each request
server.express.use((req, res, next) => {
  const { token } = req.cookies;
  if (token) {
    // console.log('JWT: ', jwt.verify(token, dotenv.parsed.APP_SECRET));
    // This logs: JWT:  { userID: 'cjqe0kf58x3ib0a55hja4kb13', iat: 1546377289 }
    // Where is 'userID' being set???
    const { userID } = jwt.verify(token, dotenv.parsed.APP_SECRET);
    // put the userID onto the req for future requests to access
    req.userId = userID;
  }
  next();
});

server.start(
  {
    cors: {
      credentials: true,
      origin: process.env.FRONTEND_URL
    }
  },
  deets => {
    console.log(`Server now running on port http://localhost:${deets.port}`);
  }
);
