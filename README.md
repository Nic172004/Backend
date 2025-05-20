# ClinQ Server - MongoDB Version

This is the backend server for the ClinQ appointment booking application, now using MongoDB instead of MySQL.

## Prerequisites

- Node.js (v14+)
- MongoDB (v4.4+)

## Setup

1. Install dependencies:
   ```
   npm install
   ```

2. Create a `.env` file in the root directory with the following variables:
   ```
   MONGODB_URI=mongodb://localhost:27017/clinq
   PORT=3000
   JWT_SECRET=your_jwt_secret_key_here
   ```

3. Make sure MongoDB is running on your system:
   - For Windows: MongoDB service should be running
   - For macOS/Linux: Run `mongod` in a terminal

## Starting the Server

For development (with auto-reload):
```
npm run dev
```

For production:
```
npm start
```

The server will run on http://localhost:3000 by default.

## API Endpoints

- `GET /api/test` - Test if the server is running
- `POST /api/register` - Register a new user
- `POST /api/login` - Login a user
- `GET /api/user/:id` - Get user profile
- `PUT /api/update-profile/:id` - Update user profile

## Database Schema

### Student Collection

- `_id`: MongoDB ObjectId
- `fname`: String, required
- `lname`: String, required
- `student_id`: String, required, unique
- `university_email`: String, required, unique
- `password`: String, required
- `pnumber`: String
- `birthdate`: String
- `agreed_to_terms`: String
- `created_at`: Date, default: current date

## Notes on MongoDB Migration

This server was migrated from MySQL to MongoDB. Key changes include:

1. Replaced MySQL connection with Mongoose/MongoDB
2. Restructured database queries to use MongoDB's document model
3. Implemented async/await pattern for database operations
4. Created proper MongoDB schema with Mongoose

For security in production, consider adding:
- Password hashing with bcrypt
- JWT-based authentication
- Input validation with a library like Joi
- Rate limiting for API endpoints 