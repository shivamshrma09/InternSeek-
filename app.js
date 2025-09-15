const express = require('express');
const fs = require('fs');
const bcrypt = require('bcrypt');
const readline = require('readline');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'))); 

// Route to serve login page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).send('Email and password required');

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const userRecord = JSON.stringify({ email, password: hashedPassword }) + '\n';
    fs.appendFile('data.txt', userRecord, (err) => {
      if (err) return res.status(500).send('Error saving user');
      res.status(200).send('Signup successful');
    });
  } catch (err) {
    res.status(500).send('Server error');
  }
});



app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).send('Email and password required');

  try {
    const fileStream = fs.createReadStream('data.txt');
    const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });

    let userFound = false;
    for await (const line of rl) {
      const user = JSON.parse(line);
      if (user.email === email) {
        userFound = true;
        const match = await bcrypt.compare(password, user.password);
        if (match) {
          return res.status(200).send('Login successful');
        } else {
          return res.status(401).send('Incorrect password');
        }
      }
    }

    if (!userFound) {
      res.status(404).send('User not found');
    }
  } catch (err) {
    res.status(500).send('Server error');
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
