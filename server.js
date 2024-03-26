const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser')
const { v4: uuid4 } = require('uuid');
const RDB = require('./DB/index.js')
const env = require('dotenv').config()

const app = express();
app.use(bodyParser.json())

const secretKey = process.env.SECRET_KET
const secretPassword = process.env.SERET_PASSWORD
const myDB = new RDB()

// Middleware to verify token
const verifyToken = (req, res, next) => {
    const token = req.headers.token;
    if (!token) return res.status(403).json({ 'message': 'Token is required' });
    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) return res.status(401).send({ 'message': 'Invalid token' });
        req.user = decoded;
        next();
    });
}

app.post('/connect', (req, res) => {
    try {
        const { password } = req.body
        if (!password)
            return res.status(401).json({ 'message': 'Password is required' });
        if (password !== secretPassword)
            return res.status(401).json({ 'message': 'Invalid password' });
        const token = jwt.sign(secretPassword, secretKey);
        return res.status(200).json({ token });
    } catch (err) {
        return res.status(500).json({ err });
    }
});

app.get('/users', verifyToken, async (req, res) => {
    const data = await myDB.readTable('user.json')
    if (!data) return res.status(500).send('Error reading data');
    return res.status(200).json(data);
});

app.post('/users', verifyToken, async (req, res) => {
    try {
        const oldData = await myDB.readTable('user.json')
        const id = `${uuid4()}N${oldData.length}`;
        const { name, password } = req.body
        if (!name || !password) return res.status(500).json({ 'message': 'Data is required' });
        await myDB.updateTable('user.json', { id, name, password })
        return res.status(200).json({ 'message': 'User data written successfully' })

    } catch (error) {
        return res.status(500).json({ 'message': 'Error writing data' });
    }
});


const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});



