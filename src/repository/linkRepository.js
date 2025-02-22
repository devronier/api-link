const { pool } = require("../config/db");

async function buscarLinks() {
  const result = await pool.query("SELECT * FROM links");

  return result.rows;
}

async function buscarLinksPeloUsuario(usuarioId) {
  const result = await pool.query("SELECT * FROM links WHERE user_id = $1", [
    usuarioId,
  ]);

  return result.rows;
}

module.exports = { buscarLinks, buscarLinksPeloUsuario };
