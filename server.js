require("dotenv").config();
const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const path = require("path");

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");
if (!process.env.JWT_SECRET) console.warn("Aviso: defina JWT_SECRET no .env (sem isso, os logins caem a cada reinício).");

/* ---------- Banco de dados (SQLite) ---------- */
const db = new Database(process.env.DB_FILE || path.join(__dirname, "farmacia.db"));
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS usuarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nome TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  senha_hash TEXT NOT NULL,
  perfil TEXT NOT NULL CHECK (perfil IN ('gerente','farmaceutico','balconista'))
);
CREATE TABLE IF NOT EXISTS produtos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nome TEXT NOT NULL,
  categoria TEXT NOT NULL,
  lote TEXT,
  validade TEXT NOT NULL,
  qtd INTEGER NOT NULL CHECK (qtd >= 0),
  minimo INTEGER NOT NULL CHECK (minimo >= 0),
  custo REAL NOT NULL CHECK (custo >= 0),
  preco REAL NOT NULL CHECK (preco >= 0),
  fornecedor TEXT
);
CREATE TABLE IF NOT EXISTS movimentacoes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  produto_id INTEGER,
  produto_nome TEXT NOT NULL,
  usuario_nome TEXT NOT NULL,
  tipo TEXT NOT NULL CHECK (tipo IN ('entrada','saida')),
  qtd INTEGER NOT NULL CHECK (qtd > 0),
  receita TEXT,
  data_hora TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS recuperacao_senha (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
  codigo_hash TEXT NOT NULL,
  expira_em INTEGER NOT NULL,
  usado INTEGER NOT NULL DEFAULT 0
);
`);

/* ---------- E-mail (SMTP) ---------- */
const transporter = process.env.SMTP_USER && process.env.SMTP_PASS
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST || "smtp.gmail.com",
      port: Number(process.env.SMTP_PORT || 465),
      secure: Number(process.env.SMTP_PORT || 465) === 465,
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    })
  : null;

async function enviarEmail(para, assunto, texto) {
  if (!transporter) {
    console.log(`\n[E-MAIL DE TESTE] Para: ${para}\nAssunto: ${assunto}\n${texto}\n`);
    return;
  }
  await transporter.sendMail({
    from: process.env.MAIL_FROM || `Farmácia Santana <${process.env.SMTP_USER}>`,
    to: para, subject: assunto, text: texto,
  });
}

/* ---------- Segurança: autenticação, perfis e limite de tentativas ---------- */
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

function auth(req, res, next) {
  const t = (req.headers.authorization || "").replace("Bearer ", "");
  try {
    const d = jwt.verify(t, SECRET);
    const u = db.prepare("SELECT id,nome,email,perfil FROM usuarios WHERE id=?").get(d.id);
    if (!u) throw new Error("x");
    req.user = u; next();
  } catch (e) { res.status(401).json({ erro: "Sessão expirada. Faça login novamente." }); }
}
const exigir = (...perfis) => (req, res, next) =>
  perfis.includes(req.user.perfil) ? next() : res.status(403).json({ erro: "Seu perfil não tem permissão para esta ação." });

const tentativas = new Map();
function limite(req, res, next) {
  const agora = Date.now();
  const t = (tentativas.get(req.ip) || []).filter(x => agora - x < 15 * 60 * 1000);
  if (t.length >= 10) return res.status(429).json({ erro: "Muitas tentativas. Aguarde alguns minutos." });
  t.push(agora); tentativas.set(req.ip, t); next();
}
const token = u => jwt.sign({ id: u.id }, SECRET, { expiresIn: "8h" });
const emailOk = e => /^\S+@\S+\.\S+$/.test(e);

/* ---------- Rotas públicas: cadastro, login e recuperação ---------- */
app.get("/api/status", (req, res) =>
  res.json({ semUsuarios: db.prepare("SELECT COUNT(*) c FROM usuarios").get().c === 0 }));

app.post("/api/cadastro", limite, (req, res) => {
  const nome = String(req.body.nome || "").trim().toLowerCase();
  const email = String(req.body.email || "").trim().toLowerCase();
  const senha = String(req.body.senha || "");
  if (nome.length < 3 || !emailOk(email) || senha.length < 6)
    return res.status(400).json({ erro: "Informe usuário (mín. 3 letras), e-mail válido e senha (mín. 6 caracteres)." });
  const primeiro = db.prepare("SELECT COUNT(*) c FROM usuarios").get().c === 0;
  try {
    db.prepare("INSERT INTO usuarios (nome,email,senha_hash,perfil) VALUES (?,?,?,?)")
      .run(nome, email, bcrypt.hashSync(senha, 10), primeiro ? "gerente" : "balconista");
    res.json({ ok: true });
  } catch (e) { res.status(409).json({ erro: "Usuário ou e-mail já cadastrado." }); }
});

app.post("/api/login", limite, (req, res) => {
  const nome = String(req.body.nome || "").trim().toLowerCase();
  const u = db.prepare("SELECT * FROM usuarios WHERE nome=?").get(nome);
  if (!u || !bcrypt.compareSync(String(req.body.senha || ""), u.senha_hash))
    return res.status(401).json({ erro: "Usuário ou senha incorretos." });
  res.json({ token: token(u), user: { id: u.id, nome: u.nome, email: u.email, perfil: u.perfil } });
});

app.post("/api/recuperar", limite, async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const u = db.prepare("SELECT * FROM usuarios WHERE email=?").get(email);
  if (u) {
    const codigo = String(crypto.randomInt(100000, 1000000));
    db.prepare("UPDATE recuperacao_senha SET usado=1 WHERE usuario_id=?").run(u.id);
    db.prepare("INSERT INTO recuperacao_senha (usuario_id,codigo_hash,expira_em) VALUES (?,?,?)")
      .run(u.id, crypto.createHash("sha256").update(codigo).digest("hex"), Date.now() + 10 * 60 * 1000);
    try {
      await enviarEmail(email, "Farmácia Santana · código de recuperação de senha",
        `Olá, ${u.nome}!\n\nSeu código de recuperação é: ${codigo}\nEle vale por 10 minutos.\n\nSe você não pediu isso, ignore esta mensagem.`);
    } catch (e) { console.error("Falha ao enviar e-mail:", e.message); }
  }
  // Resposta igual exista ou não o e-mail (não revela quem tem conta)
  res.json({ ok: true });
});

app.post("/api/redefinir", limite, (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const senha = String(req.body.senha || "");
  if (senha.length < 6) return res.status(400).json({ erro: "A nova senha precisa ter ao menos 6 caracteres." });
  const u = db.prepare("SELECT * FROM usuarios WHERE email=?").get(email);
  const hash = crypto.createHash("sha256").update(String(req.body.codigo || "").trim()).digest("hex");
  const r = u && db.prepare("SELECT * FROM recuperacao_senha WHERE usuario_id=? AND usado=0 AND expira_em>? AND codigo_hash=?")
    .get(u.id, Date.now(), hash);
  if (!r) return res.status(400).json({ erro: "Código inválido ou expirado." });
  db.transaction(() => {
    db.prepare("UPDATE usuarios SET senha_hash=? WHERE id=?").run(bcrypt.hashSync(senha, 10), u.id);
    db.prepare("UPDATE recuperacao_senha SET usado=1 WHERE id=?").run(r.id);
  })();
  res.json({ ok: true });
});

/* ---------- Rotas protegidas ---------- */
app.get("/api/eu", auth, (req, res) => res.json({ user: req.user }));

function lerProduto(b) {
  const p = {
    nome: String(b.nome || "").trim(), categoria: String(b.categoria || "Outros"),
    lote: String(b.lote || "").trim(), validade: String(b.validade || ""),
    qtd: parseInt(b.qtd), minimo: parseInt(b.minimo), custo: Number(b.custo), preco: Number(b.preco),
    fornecedor: String(b.fornecedor || "").trim(),
  };
  const nums = [p.qtd, p.minimo, p.custo, p.preco];
  if (!p.nome || !/^\d{4}-\d{2}-\d{2}$/.test(p.validade) || !nums.every(n => Number.isFinite(n) && n >= 0)) return null;
  return p;
}

app.get("/api/produtos", auth, (req, res) => res.json(db.prepare("SELECT * FROM produtos ORDER BY nome").all()));

app.post("/api/produtos", auth, exigir("gerente", "farmaceutico"), (req, res) => {
  const p = lerProduto(req.body);
  if (!p) return res.status(400).json({ erro: "Dados do produto inválidos." });
  db.prepare(`INSERT INTO produtos (nome,categoria,lote,validade,qtd,minimo,custo,preco,fornecedor)
    VALUES (@nome,@categoria,@lote,@validade,@qtd,@minimo,@custo,@preco,@fornecedor)`).run(p);
  res.json({ ok: true });
});

app.put("/api/produtos/:id", auth, exigir("gerente", "farmaceutico"), (req, res) => {
  const p = lerProduto(req.body);
  if (!p) return res.status(400).json({ erro: "Dados do produto inválidos." });
  db.prepare(`UPDATE produtos SET nome=@nome,categoria=@categoria,lote=@lote,validade=@validade,qtd=@qtd,
    minimo=@minimo,custo=@custo,preco=@preco,fornecedor=@fornecedor WHERE id=@id`).run({ ...p, id: req.params.id });
  res.json({ ok: true });
});

app.delete("/api/produtos/:id", auth, exigir("gerente"), (req, res) => {
  db.prepare("DELETE FROM produtos WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

app.get("/api/movimentos", auth, (req, res) => {
  const rows = db.prepare("SELECT * FROM movimentacoes ORDER BY id DESC LIMIT 100").all();
  res.json(rows.map(m => ({ id: m.id, nome: m.produto_nome, tipo: m.tipo, qtd: m.qtd,
    receita: m.receita, usuario: m.usuario_nome, data: m.data_hora })));
});

// Regras de negócio no servidor (mesmas do trigger do SQL)
app.post("/api/movimentos", auth, (req, res) => {
  const { produtoId, tipo } = req.body;
  const q = parseInt(req.body.qtd);
  const receita = String(req.body.receita || "").trim();
  if (!["entrada", "saida"].includes(tipo) || !(q > 0)) return res.status(400).json({ erro: "Dados inválidos." });
  const p = db.prepare("SELECT * FROM produtos WHERE id=?").get(produtoId);
  if (!p) return res.status(404).json({ erro: "Produto não encontrado." });
  if (tipo === "entrada" && req.user.perfil === "balconista")
    return res.status(403).json({ erro: "Balconista não pode registrar entrada de estoque." });
  if (tipo === "saida") {
    if (q > p.qtd) return res.status(400).json({ erro: `Estoque insuficiente (disponível: ${p.qtd}).` });
    if (p.validade < new Date().toISOString().slice(0, 10)) return res.status(400).json({ erro: "Produto vencido: venda bloqueada. Faça o descarte." });
    if (p.categoria === "Controlado" && !receita) return res.status(400).json({ erro: "Informe o número da receita para medicamento controlado." });
  }
  db.transaction(() => {
    db.prepare("UPDATE produtos SET qtd = qtd + ? WHERE id=?").run(tipo === "entrada" ? q : -q, p.id);
    db.prepare("INSERT INTO movimentacoes (produto_id,produto_nome,usuario_nome,tipo,qtd,receita) VALUES (?,?,?,?,?,?)")
      .run(p.id, p.nome, req.user.nome, tipo, q, receita || null);
  })();
  res.json({ ok: true });
});

/* ---------- Gestão de usuários (somente gerente) ---------- */
app.get("/api/usuarios", auth, exigir("gerente"), (req, res) =>
  res.json(db.prepare("SELECT id,nome,email,perfil FROM usuarios ORDER BY nome").all()));

app.post("/api/usuarios", auth, exigir("gerente"), (req, res) => {
  const nome = String(req.body.nome || "").trim().toLowerCase();
  const email = String(req.body.email || "").trim().toLowerCase();
  const senha = String(req.body.senha || "");
  const perfil = ["gerente", "farmaceutico", "balconista"].includes(req.body.perfil) ? req.body.perfil : "balconista";
  if (nome.length < 3 || !emailOk(email) || senha.length < 6)
    return res.status(400).json({ erro: "Informe usuário (mín. 3 letras), e-mail válido e senha (mín. 6 caracteres)." });
  try {
    db.prepare("INSERT INTO usuarios (nome,email,senha_hash,perfil) VALUES (?,?,?,?)").run(nome, email, bcrypt.hashSync(senha, 10), perfil);
    res.json({ ok: true });
  } catch (e) { res.status(409).json({ erro: "Usuário ou e-mail já cadastrado." }); }
});

app.delete("/api/usuarios/:id", auth, exigir("gerente"), (req, res) => {
  if (Number(req.params.id) === req.user.id) return res.status(400).json({ erro: "Você não pode remover a si mesmo." });
  db.prepare("DELETE FROM usuarios WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`Farmácia Santana rodando em http://localhost:${PORT}`));
