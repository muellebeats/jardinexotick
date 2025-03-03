const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const cors = require('cors'); // Para permitir peticiones desde otros orígenes

const app = express();

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Simulación de base de datos en memoria
const users = {};

// (1) Endpoint para el webhook de pago
app.post('/webhook/payment', async (req, res) => {
  const { email, paymentStatus } = req.body;
  if (paymentStatus === 'success') {
    // Genera una contraseña aleatoria de 8 caracteres
    const rawPassword = Math.random().toString(36).slice(-8);
    const hashedPassword = await bcrypt.hash(rawPassword, 10);

    // Registra o actualiza el usuario en memoria
    users[email] = { email, password: hashedPassword };

    // Configura el transporte de correo (configuración de ejemplo)
    let transporter = nodemailer.createTransport({
      host: 'smtp.ejemplo.com',
      port: 587,
      secure: false,
      auth: {
        user: 'tu_usuario',
        pass: 'tu_contraseña'
      }
    });

    // Envía el correo con la contraseña
    await transporter.sendMail({
      from: '"Entrenamiento 2.0" <noreply@ejemplo.com>',
      to: email,
      subject: 'Tu Acceso al Entrenamiento 2.0',
      text: `Gracias por tu pago. Tu contraseña exclusiva es: ${rawPassword}\n\nUtiliza tu correo y esta contraseña para iniciar sesión.`
    });

    res.status(200).send("Usuario creado y correo enviado");
  } else {
    res.status(400).send("Pago no exitoso");
  }
});

// (2) Endpoint para registrar usuarios manualmente
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  // Validar que existan los campos
  if (!email || !password) {
    return res.status(400).json({ error: 'Email y contraseña son obligatorios' });
  }

  // Verificar si el usuario ya existe
  if (users[email]) {
    return res.status(409).json({ error: 'El usuario ya existe' });
  }

  // Hashear la contraseña
  const hashedPassword = await bcrypt.hash(password, 10);

  // Guardar en la "BD" (en memoria)
  users[email] = { email, password: hashedPassword };

  res.json({ message: 'Usuario registrado correctamente' });
});

// (3) Endpoint para login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users[email];

  if (!user) {
    return res.status(401).send("Usuario no encontrado");
  }

  // Verificar contraseña
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(401).send("Credenciales incorrectas");
  }

  // Generar token
  const token = jwt.sign({ email }, 'clave_secreta', { expiresIn: '1h' });
  res.json({ token });
});

// Middleware de autenticación (para proteger rutas)
function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).send("No token provided");
  }
  const token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).send("Token missing");
  }
  jwt.verify(token, 'clave_secreta', (err, decoded) => {
    if (err) {
      return res.status(403).send("Token invalid");
    }
    req.user = decoded; // { email: '...' }
    next();
  });
}

// (4) Endpoint para cambio de contraseña (requiere autenticación)
app.post('/change-password', authMiddleware, async (req, res) => {
  const { email } = req.user; 
  const { oldPassword, newPassword } = req.body;

  const user = users[email];
  if (!user) {
    return res.status(404).send("Usuario no encontrado");
  }

  // Verificar contraseña antigua
  const isMatch = await bcrypt.compare(oldPassword, user.password);
  if (!isMatch) {
    return res.status(401).send("Contraseña antigua incorrecta");
  }

  // Guardar la nueva contraseña en hash
  user.password = await bcrypt.hash(newPassword, 10);
  res.send("Contraseña actualizada");
});

// Ruta raíz de ejemplo
app.get('/', (req, res) => {
  res.send('¡Bienvenido a mi API!');
});

// Iniciar el servidor
const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Servidor corriendo en el puerto " + port));
