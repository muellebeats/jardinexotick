require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mongoose = require('mongoose');

const app = express();

// Conexión a MongoDB con Mongoose
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('Conectado a MongoDB Atlas'))
.catch(err => console.error('Error al conectar a MongoDB:', err));

// Definir el esquema y modelo de Usuario
const userSchema = new mongoose.Schema({
  email:    { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Endpoint para el webhook de pago
app.post('/webhook/payment', async (req, res) => {
  try {
    const { email, paymentStatus } = req.body;

    if (paymentStatus !== 'success') {
      return res.status(400).send("Pago no exitoso");
    }

    // Generar contraseña aleatoria y hashearla
    const rawPassword = Math.random().toString(36).slice(-8);
    const hashedPassword = await bcrypt.hash(rawPassword, 10);

    // Verificar si el usuario ya existe en la BD
    let user = await User.findOne({ email });
    if (!user) {
      // Crear nuevo usuario
      user = new User({ email, password: hashedPassword });
    } else {
      // Actualizar contraseña
      user.password = hashedPassword;
    }
    await user.save();

    // Enviar correo con la contraseña
    let transporter = nodemailer.createTransport({
      host: 'smtp.ejemplo.com',
      port: 587,
      secure: false,
      auth: {
        user: 'tu_usuario',
        pass: 'tu_contraseña'
      }
    });

    await transporter.sendMail({
      from: '"Entrenamiento 2.0" <noreply@ejemplo.com>',
      to: email,
      subject: 'Tu Acceso al Entrenamiento 2.0',
      text: `Gracias por tu pago. Tu contraseña exclusiva es: ${rawPassword}\n\nUtiliza tu correo y esta contraseña para iniciar sesión.`
    });

    return res.status(200).send("Usuario creado/actualizado y correo enviado");
  } catch (error) {
    console.error('Error en /webhook/payment:', error);
    return res.status(500).send("Error interno del servidor");
  }
});

// ---------------------
// Endpoint para registrar usuarios manualmente (/register)
// ---------------------
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validar que existan los campos
    if (!email || !password) {
      return res.status(400).json({ error: 'Email y contraseña son obligatorios' });
    }

    // Verificar si el usuario ya existe
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ error: 'El usuario ya existe' });
    }

    // Hashear la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Guardar en la BD
    const newUser = new User({ email, password: hashedPassword });
    await newUser.save();

    res.json({ message: 'Usuario registrado correctamente' });
  } catch (error) {
    console.error('Error en /register:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Endpoint para login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Buscar usuario en MongoDB
    const user = await User.findOne({ email });
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
  } catch (error) {
    console.error('Error en /login:', error);
    res.status(500).send("Error interno del servidor");
  }
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

// Endpoint para cambio de contraseña (requiere autenticación)
app.post('/change-password', authMiddleware, async (req, res) => {
  try {
    const { email } = req.user; 
    const { oldPassword, newPassword } = req.body;

    // Buscar usuario en la BD
    const user = await User.findOne({ email });
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
    await user.save();

    res.send("Contraseña actualizada");
  } catch (error) {
    console.error('Error en /change-password:', error);
    res.status(500).send("Error interno del servidor");
  }
});

// Ruta raíz de ejemplo
app.get('/', (req, res) => {
  res.send('¡Bienvenido a mi API!');
});

// Iniciar el servidor
const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Servidor corriendo en el puerto " + port));
