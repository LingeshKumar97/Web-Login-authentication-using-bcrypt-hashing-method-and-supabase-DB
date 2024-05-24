const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
app.use(cors()); 
app.use(express.json());  

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

const SECRET_KEY = process.env.SECRET_KEY;

app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log('Registering user:', email);
    
    const hashedPassword = await bcrypt.hash(password, 8);
    console.log('Hashed password:', hashedPassword);

    const { data, error } = await supabase
      .from('users')
      .insert([{ email, password: hashedPassword }]);

    if (error) {
      console.error('Error inserting user:', error);
      return res.status(400).send(error.message);
    }

    console.log('User registered:', data);
    res.status(201).send({ message: 'User registered!' });
  } catch (err) {
    console.error('Unexpected error:', err);
    res.status(500).send('Server error');
  }
});

// Login Route
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log('Logging in user:', email);

    const { data, error } = await supabase
      .from('users')
      .select('id, password')
      .eq('email', email)
      .single();

    if (error) {
      console.error('User not found:', error);
      return res.status(400).send('User not found!');
    }

    const validPassword = await bcrypt.compare(password, data.password);
    if (!validPassword) {
      console.error('Invalid password');
      return res.status(400).send('Invalid password!');
    }

    const token = jwt.sign({ id: data.id, email: email }, SECRET_KEY, { expiresIn: '1h' });
    console.log('Token generated:', token);

    res.status(200).send({ token });
  } catch (err) {
    console.error('Unexpected error:', err);
    res.status(500).send('Server error');
  }
});

// Protected Route
app.get('/profile', verifyToken, (req, res) => {
  res.status(200).send('This is a protected route.');
});

function verifyToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).send('Token is required.');

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      console.error('Failed to authenticate token:', err);
      return res.status(500).send('Failed to authenticate token.');
    }
    req.userId = decoded.id;
    next();
  });
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
