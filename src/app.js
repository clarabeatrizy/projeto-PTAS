const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
dotenv.config();

const authRoutes = require('./routes/auth.routes');

const app = express();
app.use(cors());
app.use(express.json());

// Rotas de autenticação
app.use('/auth', authRoutes);

// Rota inicial
app.get('/', (req, res) => {
  res.json({ mensagem: 'API Restaurante (MVC) - funcionando' });
});

module.exports = app;
