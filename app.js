const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const dotenv = require("dotenv");
dotenv.config();

const {
  buscarUsuarios,
  buscarUsuarioPorUsername,
  criarUsuario,
} = require("./src/repository/usuarioRepository");
const {
  buscarLinks,
  buscarLinksPeloUsuario,
} = require("./src/repository/linkRepository");

const app = express();
const port = 3000;

const CHAVE_SECRETA = "macacobanana";

app.use(express.json());

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    res.send(401);
  }

  const usuario = await buscarUsuarioPorUsername(username);

  if (!usuario) {
    res.send(401);
  }

  const resultado = await bcrypt.compare(password, usuario.password);

  if (resultado) {
    const token = jwt.sign({ username }, CHAVE_SECRETA, {
      expiresIn: "1s",
    });

    res.send({ token });
  } else {
    res.send(401);
  }
});

app.use((req, res, next) => {
  console.log(req.headers.authorization);

  if (!req.headers.authorization) {
    return res.status(401).send("Token não informado");
  }

  const token = req.headers.authorization.split(" ")[1];

  try {
    jwt.verify(token, CHAVE_SECRETA);
    next();
  } catch (error) {
    return res.status(401).send("Token inválido");
  }
});

app.get("/usuarios", async (req, res) => {
  const usuarios = await buscarUsuarios();
  res.send(usuarios);
});

app.post("/usuarios", async (req, res) => {
  const usuario = req.body;

  if (!usuario.username || !usuario.password || !usuario.name) {
    return res
      .status(400)
      .json({ message: "Username e senha são obrigatórios." });
  }

  usuario.password = await bcrypt.hash(usuario.password, 12);

  const usuarioSalvo = await criarUsuario(usuario);
  res.send(usuarioSalvo);
});

app.get("/usuarios/:id/links", async (req, res) => {
  const id = Number(req.params.id);
  const links = await buscarLinksPeloUsuario(id);
  res.send(links);
});

app.get("/links", async (req, res) => {
  const links = await buscarLinks();
  res.send(links);
});

app.listen(port, () => {
  console.log(`App de exemplo esta rodando na porta ${port}`);
});
