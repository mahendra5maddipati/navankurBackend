# Getting Started with Navankur Backend

## Prerequisites

- Node.js (v14 or higher)
- npm (v6 or higher)
- MongoDB
- Redis

## Setup

1. **Clone the repository:**

   ```sh
   git clone https://github.com/your-username/navankurAssignment.git
   cd navankurAssignment/navankuraBackend
   ```

2. **Install dependencies:**

   ```sh
   npm install
   ```

3. **Set up environment variables:**

   Create a `.env` file in the `navankuraBackend` directory and add the following:

   ```env
   PORT=5000
   MONGO_URI=your_mongodb_uri
   JWT_SECRET=your_jwt_secret
   REDIS_HOST=your_redis_host
   REDIS_PORT=your_redis_port
   REDIS_PASSWORD=your_redis_password
   EMAIL_USER=your_email_user
   EMAIL_PASS=your_email_password
   CLIENT_URL=http://localhost:3000
   ```

## Available Scripts

In the project directory, you can run:

### `npm start`

Starts the backend server in development mode.\
The server will restart automatically when you make changes.

### `npm test`

Runs the test suite.

## Learn More

To learn more about Express, check out the [Express documentation](https://expressjs.com/).

To learn more about MongoDB, check out the [MongoDB documentation](https://docs.mongodb.com/).

To learn more about Redis, check out the [Redis documentation](https://redis.io/documentation).
