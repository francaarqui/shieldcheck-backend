const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const Stripe = require('stripe');
const OpenAI = require('openai');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-shieldcheck-key-2026';
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const stripe = Stripe(STRIPE_SECRET_KEY);
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;

const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY,
});

const twilioClient = require('twilio')(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
const axios = require('axios');

// Configuração do Multer para uploads temporários
const upload = multer({
    dest: 'uploads/',
    limits: { fileSize: 25 * 1024 * 1024 }
});

if (!fs.existsSync('uploads/')) {
    fs.mkdirSync('uploads/');
}

const app = express();

const allowedOrigins = [
    'http://localhost:5173',
    'https://shieldcheck-ai.vercel.app', // Altere para seu domínio real da Vercel
    'https://shieldcheck.com.br'
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Interditado pelo CORS'));
        }
    },
    credentials: true
}));

// --- Middlewares ---

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Acesso negado.' });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido.' });
        req.user = user;
        next();
    });
};

const optionalAuthenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return next();
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (!err) req.user = user;
        next();
    });
};

const checkQuota = async (req, res, next) => {
    const userId = req.user ? req.user.id : null;
    const plan = req.user ? req.user.plan : 'FREE';
    if (plan === 'PREMIUM' || plan === 'BUSINESS' || plan === 'PRO') return next();

    if (plan === 'FREE') {
        const today = new Date().toISOString().split('T')[0];
        const { count } = await supabase.from('reports').select('*', { count: 'exact', head: true }).eq('user_id', userId).gte('timestamp', today);
        if (count >= 3) return res.status(429).json({ error: 'Cota diária atingida', limitReached: true });
        return next();
    }
    next();
};

const downloadWhatsAppMedia = async (url, filename) => {
    const filePath = path.join(__dirname, 'uploads', filename);
    const writer = fs.createWriteStream(filePath);

    const config = {
        url,
        method: 'GET',
        responseType: 'stream',
    };

    // Só usar autenticação se for URL do Twilio
    if (url.includes('twilio.com')) {
        config.auth = {
            username: process.env.TWILIO_ACCOUNT_SID,
            password: process.env.TWILIO_AUTH_TOKEN
        };
    }

    const response = await axios(config);
    response.data.pipe(writer);

    return new Promise((resolve, reject) => {
        writer.on('finish', () => resolve(filePath));
        writer.on('error', reject);
    });
};

const sendWhatsAppReply = async (to, message) => {
    try {
        await twilioClient.messages.create({
            from: process.env.TWILIO_PHONE,
            to: to,
            body: message
        });
        console.log(`📤 [WHATSAPP OUT] Para: ${to} | Mensagem enviada.`);
    } catch (error) {
        console.error("Twilio Error:", error);
    }
};

// --- Webhooks (must be before express.json) ---
const webhookRoutes = require('./routes/webhooks')(supabase, stripe, STRIPE_WEBHOOK_SECRET);
app.use('/api/webhook', webhookRoutes);

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// --- Modular Routes ---
const authRoutes = require('./routes/auth')(supabase, JWT_SECRET, authenticateToken);
const analyzeRoutes = require('./routes/analyze')(supabase, openai, optionalAuthenticateToken, checkQuota, upload);
const intelligenceRoutes = require('./routes/intelligence')(supabase, authenticateToken);
const b2bRoutes = require('./routes/b2b')(supabase, authenticateToken);
const familyRoutes = require('./routes/family')(supabase, authenticateToken);
const extensionRoutes = require('./routes/extension')(supabase, optionalAuthenticateToken);
const paymentRoutes = require('./routes/payments')(stripe, authenticateToken);
const adminRoutes = require('./routes/admin')(supabase, authenticateToken);
const whatsappRoutes = require('./routes/whatsapp')(supabase, openai, downloadWhatsAppMedia, sendWhatsAppReply);
const affiliateRoutes = require('./routes/affiliate')(supabase, authenticateToken);
const communityRoutes = require('./routes/community')(supabase, authenticateToken);
const brandProtectionRoutes = require('./routes/brand_protection')(supabase, authenticateToken);
const academyRoutes = require('./routes/academy')(supabase, authenticateToken);
const analyticsRoutes = require('./routes/analytics')(supabase, authenticateToken);

app.use('/api', authRoutes);
app.use('/api', analyzeRoutes);
app.use('/api', intelligenceRoutes);
app.use('/api', b2bRoutes);
app.use('/api/family', familyRoutes);
app.use('/api/extension', extensionRoutes);
app.use('/api', paymentRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/whatsapp', whatsappRoutes);
app.use('/api', affiliateRoutes);
app.use('/api/community', communityRoutes);
app.use('/api', brandProtectionRoutes);
app.use('/api', academyRoutes);
app.use('/api', analyticsRoutes);

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`🛡️  ShieldCheck AI Backend rodando na porta ${PORT}`);
    console.log(`🌐 Ambiente: ${process.env.NODE_ENV || 'development'}`);
});
