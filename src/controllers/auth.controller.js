const prisma = require('../config/prismaClient');
const bcrypt = require('bcryptjs');
const generateToken = require('../utils/generateToken');

const SALT_ROUNDS = 10;

async function cadastro(req, res) {
  try {
    const { nome, email, password } = req.body;
    if (!nome || !email || !password) {
      return res.status(400).json({ mensagem: 'Campos incompletos', erro: true });
    }

    const existing = await prisma.usuario.findUnique({ where: { email } });
    if (existing) {
      return res.status(400).json({ mensagem: 'Email já cadastrado', erro: true });
    }

    const hashed = await bcrypt.hash(password, SALT_ROUNDS);

    const user = await prisma.usuario.create({
      data: { nome, email, password: hashed, role: 'CLIENTE' }
    });

    const token = generateToken({ id: user.id, email: user.email, role: user.role });

    return res.status(201).json({ mensagem: 'Cadastro realizado', erro: false, token });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ mensagem: 'Erro no servidor', erro: true });
  }
}

async function login(req, res) {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ mensagem: 'Login realizado', erro: true });
    }

    const user = await prisma.usuario.findUnique({ where: { email } });
    if (!user) {
      return res.status(401).json({ mensagem: 'Credenciais inválidas', erro: true });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ mensagem: 'Credenciais inválidas', erro: true });
    }

    const token = generateToken({ id: user.id, email: user.email, role: user.role });

    return res.json({ mensagem: 'Login realizado', erro: false, token });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ mensagem: 'Erro no servidor', erro: true });
  }
}

module.exports = { cadastro, login };
