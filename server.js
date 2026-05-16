const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");
const app = express();
const prisma = new PrismaClient();
const SECRET = "estoquei_2025_xK9#mP2$vL8@nQ4&wR7!zT1^hJ6*yU3";

const allowedOrigins = [
  "https://projeto-estoquei-front-end.vercel.app",
  "http://localhost:3007"
];
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) callback(null, true);
    else callback(new Error("Bloqueado pelo CORS"));
  }
}));
app.use(express.json());

// Rate limiting simples
const loginAttempts = {};
function rateLimit(req, res, next) {
  const ip = req.ip;
  const now = Date.now();
  if (!loginAttempts[ip]) loginAttempts[ip] = [];
  loginAttempts[ip] = loginAttempts[ip].filter(t => now - t < 15 * 60 * 1000);
  if (loginAttempts[ip].length >= 10) return res.status(429).json({ error: "Muitas tentativas. Tente novamente em 15 minutos." });
  loginAttempts[ip].push(now);
  next();
}

function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Nao autorizado" });
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch { res.status(401).json({ error: "Token invalido" }); }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Acesso negado" });
  next();
}

function addDays(date, days) {
  const d = new Date(date);
  d.setDate(d.getDate() + days);
  return d;
}

async function checkAccess(req, res, next) {
  const company = await prisma.company.findUnique({ where: { id: req.user.companyId } });
  if (!company) return res.status(404).json({ error: "Empresa não encontrada" });
  const now = new Date();
  if (company.status === "trial" && now > new Date(company.trialEndsAt)) return res.status(403).json({ error: "trial_expired" });
  if (company.status === "active" && company.paidUntil && now > new Date(company.paidUntil)) {
    await prisma.company.update({ where: { id: company.id }, data: { status: "expired" } });
    return res.status(403).json({ error: "subscription_expired" });
  }
  if (company.status === "expired") return res.status(403).json({ error: "subscription_expired" });
  next();
}

app.post("/api/register", rateLimit, async (req, res) => {
  const { name, email, password, companyName } = req.body;
  if (!name || !email || !password || !companyName) return res.status(400).json({ error: "Preencha todos os campos" });
  if (password.length < 6) return res.status(400).json({ error: "Senha deve ter pelo menos 6 caracteres" });
  const exists = await prisma.user.findUnique({ where: { email } });
  if (exists) return res.status(400).json({ error: "Email ja cadastrado" });
  const trialEndsAt = addDays(new Date(), 5);
  const company = await prisma.company.create({ data: { name: companyName, status: "trial", trialEndsAt } });
  const hash = await bcrypt.hash(password, 10);
  const user = await prisma.user.create({ data: { name, email, password: hash, companyId: company.id, role: "admin" } });
  const token = jwt.sign({ userId: user.id, companyId: company.id, role: user.role }, SECRET, { expiresIn: "7d" });
  res.json({ token, accessStatus: "ok", user: { name: user.name, email: user.email, company: companyName } });
});

app.post("/api/login", rateLimit, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Preencha todos os campos" });
  const user = await prisma.user.findUnique({ where: { email }, include: { company: true } });
  if (!user) return res.status(400).json({ error: "Email ou senha incorretos" });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: "Email ou senha incorretos" });
  const company = user.company;
  const now = new Date();
  let accessStatus = "ok";
  if (company.status === "trial" && now > new Date(company.trialEndsAt)) accessStatus = "trial_expired";
  if (company.status === "expired") accessStatus = "subscription_expired";
  if (company.status === "active" && company.paidUntil && now > new Date(company.paidUntil)) accessStatus = "subscription_expired";
  const token = jwt.sign({ userId: user.id, companyId: user.companyId, role: user.role }, SECRET, { expiresIn: "7d" });
  res.json({ token, accessStatus, user: { name: user.name, email: user.email, company: company.name } });
});

app.get("/api/status", auth, async (req, res) => {
  const company = await prisma.company.findUnique({ where: { id: req.user.companyId } });
  const now = new Date();
  let accessStatus = "ok";
  let daysLeft = null;
  if (company.status === "trial") {
    const diff = new Date(company.trialEndsAt) - now;
    daysLeft = Math.ceil(diff / (1000 * 60 * 60 * 24));
    if (daysLeft <= 0) accessStatus = "trial_expired";
  }
  if (company.status === "active" && company.paidUntil) {
    const diff = new Date(company.paidUntil) - now;
    daysLeft = Math.ceil(diff / (1000 * 60 * 60 * 24));
    if (daysLeft <= 0) accessStatus = "subscription_expired";
  }
  if (company.status === "expired") accessStatus = "subscription_expired";
  res.json({ accessStatus, daysLeft, status: company.status, paidUntil: company.paidUntil });
});

// Rota admin protegida — só você pode ativar clientes
app.post("/api/admin/activate", auth, adminOnly, async (req, res) => {
  const { email, days } = req.body;
  if (!email) return res.status(400).json({ error: "Email obrigatório" });
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(404).json({ error: "Usuário não encontrado" });
  const paidUntil = addDays(new Date(), days || 30);
  await prisma.company.update({ where: { id: user.companyId }, data: { status: "active", paidUntil } });
  res.json({ success: true, paidUntil });
});

app.get("/api/products", auth, checkAccess, async (req, res) => {
  const products = await prisma.product.findMany({ where: { companyId: req.user.companyId }, orderBy: { name: "asc" } });
  res.json(products);
});

app.post("/api/products", auth, checkAccess, async (req, res) => {
  const { name, category, quantity, minQty, price } = req.body;
  if (!name) return res.status(400).json({ error: "Nome do produto obrigatório" });
  const product = await prisma.product.create({ data: { name, category: category||"", quantity: parseInt(quantity)||0, minQty: parseInt(minQty)||0, price: parseFloat(price)||0, companyId: req.user.companyId } });
  res.json(product);
});

app.put("/api/products/:id", auth, checkAccess, async (req, res) => {
  const { name, category, quantity, minQty, price } = req.body;
  const product = await prisma.product.findFirst({ where: { id: req.params.id, companyId: req.user.companyId } });
  if (!product) return res.status(404).json({ error: "Produto não encontrado" });
  const updated = await prisma.product.update({ where: { id: req.params.id }, data: { name, category, quantity: parseInt(quantity), minQty: parseInt(minQty), price: parseFloat(price) } });
  res.json(updated);
});

app.delete("/api/products/:id", auth, checkAccess, async (req, res) => {
  const product = await prisma.product.findFirst({ where: { id: req.params.id, companyId: req.user.companyId } });
  if (!product) return res.status(404).json({ error: "Produto não encontrado" });
  await prisma.movement.deleteMany({ where: { productId: req.params.id } });
  await prisma.product.delete({ where: { id: req.params.id } });
  res.json({ success: true });
});

app.get("/api/movements", auth, checkAccess, async (req, res) => {
  const movements = await prisma.movement.findMany({ where: { companyId: req.user.companyId }, include: { product: true, user: true }, orderBy: { createdAt: "desc" }, take: 50 });
  res.json(movements);
});

app.post("/api/movements", auth, checkAccess, async (req, res) => {
  const { productId, type, quantity } = req.body;
  const product = await prisma.product.findFirst({ where: { id: productId, companyId: req.user.companyId } });
  if (!product) return res.status(404).json({ error: "Produto não encontrado" });
  const qty = parseInt(quantity);
  if (!qty || qty <= 0) return res.status(400).json({ error: "Quantidade inválida" });
  const newQty = type === "entrada" ? product.quantity + qty : product.quantity - qty;
  if (newQty < 0) return res.status(400).json({ error: "Estoque insuficiente" });
  await prisma.product.update({ where: { id: productId }, data: { quantity: newQty } });
  const movement = await prisma.movement.create({ data: { type, quantity: qty, productId, userId: req.user.userId, companyId: req.user.companyId }, include: { product: true, user: true } });
  res.json(movement);
});

app.get("/api/alerts", auth, checkAccess, async (req, res) => {
  const products = await prisma.product.findMany({ where: { companyId: req.user.companyId } });
  res.json(products.filter(p => p.quantity <= p.minQty));
});

app.get("/api/summary", auth, checkAccess, async (req, res) => {
  const products = await prisma.product.findMany({ where: { companyId: req.user.companyId } });
  res.json({ total: products.length, outOfStock: products.filter(p=>p.quantity===0).length, lowStock: products.filter(p=>p.quantity>0&&p.quantity<=p.minQty).length, totalValue: products.reduce((s,p)=>s+p.price*p.quantity,0) });
});

app.listen(4000, () => console.log("✅ Servidor rodando em http://localhost:4000"));