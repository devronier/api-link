const { pool } = require("../config/db");
const { User } = require("../model/user");

async function buscarUsuarios() {
  const usuarios = await User.findAll({
    attributes: ["username", "name"],
  });

  return usuarios;
}

async function buscarUsuarioPorUsername(username) {
  const result = await User.findOne({ where: { username } });
  return result;
}

async function criarUsuario(usuario) {
  return await User.create(usuario);
}

module.exports = { buscarUsuarios, buscarUsuarioPorUsername, criarUsuario };
