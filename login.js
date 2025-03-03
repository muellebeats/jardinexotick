const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');

const app = express();
app.use(bodyParser.json());

// Simulación de base de datos en memoria
const users = {};

// Endpoint para el webhook de pago
app.post('/webhook/payment', async (req, res) => {
    const { email, paymentStatus } = req.body;
    if (paymentStatus === 'success') {
        // Genera una contraseña aleatoria de 8 caracteres
        const rawPassword = Math.random().toString(36).slice(-8);
        const hashedPassword = await bcrypt.hash(rawPassword, 10);

        // Registra o actualiza el usuario
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

// Endpoint para login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = users[email];
    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ email }, 'clave_secreta', { expiresIn: '1h' });
        res.json({ token });
    } else {
        res.status(401).send("Credenciales incorrectas");
    }
});

// Endpoint para cambio de contraseña (requiere autenticación)
app.post('/change-password', async (req, res) => {
    // Supongamos que un middleware de autenticación añade req.user
    const { email } = req.user;
    const { oldPassword, newPassword } = req.body;
    const user = users[email];
    if (user && await bcrypt.compare(oldPassword, user.password)) {
        user.password = await bcrypt.hash(newPassword, 10);
        res.send("Contraseña actualizada");
    } else {
        res.status(401).send("Contraseña antigua incorrecta");
    }
});

app.listen(3000, () => console.log("Servidor corriendo en el puerto 3000"));
