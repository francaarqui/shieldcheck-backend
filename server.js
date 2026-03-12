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

// Configuração do Multer para uploads temporários
const upload = multer({
    dest: 'uploads/',
    limits: { fileSize: 25 * 1024 * 1024 } // Limite de 25MB para o Whisper
});

// Criar pasta de uploads se não existir
if (!fs.existsSync('uploads/')) {
    fs.mkdirSync('uploads/');
}

const app = express();
app.use(cors());

// --- Stripe Webhook Endpoint ---
// Deve ficar ANTES do express.json() porque o Stripe precisa do raw body para validar a assinatura
app.post('/api/webhook/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
    const signature = req.headers['stripe-signature'];
    let event;

    try {
        // Se houver WEBHOOK_SECRET, valida a assinatura, senão aceita o evento (para facilitar o teste local sem CLI)
        if (STRIPE_WEBHOOK_SECRET) {
            event = stripe.webhooks.constructEvent(req.body, signature, STRIPE_WEBHOOK_SECRET);
        } else {
            event = JSON.parse(req.body.toString());
            console.warn("Aviso: STRIPE_WEBHOOK_SECRET não configurado. Aceitando evento sem validação de assinatura para testes.");
        }
    } catch (err) {
        console.error(`⚠️  Webhook signature verification failed.`, err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Lida com o evento de pagamento concluído
    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;

        // O Pricing Table envia o ID do usuário no `client_reference_id`
        const userId = session.client_reference_id;

        if (userId) {
            console.log(`💰 Pagamento recebido! Atualizando usuário ${userId} para PREMIUM...`);

            // Atualiza o plano do usuário no Supabase
            const { error } = await supabase
                .from('users')
                .update({ plan: 'PREMIUM' })
                .eq('id', userId);

            if (error) {
                console.error('Erro ao atualizar usuário para Premium no Supabase:', error);
            } else {
                console.log(`✅ Usuário ${userId} promovido a PREMIUM com sucesso!`);
            }
        } else {
            console.warn('⚠️ client_reference_id ausente na sessão de checkout. Não foi possível vincular o pagamento ao usuário.');
        }
    }

    res.json({ received: true });
});

// Middleware Global de JSON para as outras rotas
app.use(express.json());

// Middleware de Autenticação
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Acesso negado. Token não fornecido.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido ou expirado.' });
        req.user = user;
        next();
    });
};

// Middleware para verificar cotas de uso (FREEMIUM)
const checkQuota = async (req, res, next) => {
    const userId = req.user ? req.user.id : null;
    const isPremium = req.user ? req.user.plan === 'PREMIUM' : false;

    // Usuários Premium não têm limite (exceto áudio pesado se quiser)
    if (isPremium) return next();

    // Se for anônimo ou plano Free, verificamos a cota diária (Limite: 3 por dia)
    const today = new Date().toISOString().split('T')[0];

    try {
        // Busca contagem de hoje na tabela de reports
        const { count, error } = await supabase
            .from('reports')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', userId)
            .gte('timestamp', today);

        if (error) throw error;

        const limit = 3;
        if (count >= limit) {
            return res.status(429).json({
                error: 'Cota diária atingida',
                message: 'Você atingiu o limite de 3 análises gratuitas por dia. Faça o upgrade para o Premium para ter acesso ilimitado!',
                limitReached: true
            });
        }
        next();
    } catch (err) {
        console.error("Erro ao verificar cota:", err);
        next(); // Em caso de erro no banco, permitimos para não travar o usuário
    }
};

const optionalAuthenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return next();
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (!err) {
            console.log(`🔑 Token verificado para: ${user.email}`);
            req.user = user;
        } else {
            console.warn("⚠️ Falha na verificação do token opcional:", err.message);
        }
        next();
    });
};

/* ==================== AUTH ROUTES ==================== */

app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).json({ error: 'Preencha todos os campos.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const { data: user, error } = await supabase
            .from('users')
            .insert([{ name, email, password_hash: hashedPassword }])
            .select()
            .single();

        if (error) {
            if (error.code === '23505') { // Postgres unique violation
                return res.status(400).json({ error: 'E-mail já cadastrado.' });
            }
            return res.status(500).json({ error: 'Erro ao criar usuário.' });
        }

        const token = jwt.sign({ id: user.id, email, name, plan: 'FREE' }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, user: { id: user.id, name, email, plan: 'FREE', points: user.points || 0 } });
    } catch (err) {
        res.status(500).json({ error: 'Erro no servidor.' });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Preencha todos os campos.' });

    const { data: user, error } = await supabase
        .from('users')
        .select('*')
        .eq('email', email)
        .single();

    if (error || !user) return res.status(400).json({ error: 'Usuário não encontrado.' });

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) return res.status(400).json({ error: 'Senha incorreta.' });

    const token = jwt.sign({ id: user.id, email: user.email, name: user.name, plan: user.plan }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, plan: user.plan, points: user.points || 0 } });
});

app.get('/api/me', authenticateToken, async (req, res) => {
    const { data: user, error } = await supabase
        .from('users')
        .select('id, name, email, plan, points, created_at')
        .eq('id', req.user.id)
        .single();

    if (error || !user) return res.status(404).json({ error: 'Usuário não encontrado.' });
    res.json(user);
});

app.put('/api/users/settings', authenticateToken, async (req, res) => {
    const { name, email, newPassword } = req.body;
    const updates = {};

    if (name) updates.name = name;
    if (email) updates.email = email;
    if (req.body.whatsapp_number !== undefined) updates.whatsapp_number = req.body.whatsapp_number;
    if (newPassword) updates.password_hash = await bcrypt.hash(newPassword, 10);

    if (Object.keys(updates).length === 0) return res.status(400).json({ error: 'Nenhum dado para atualizar.' });

    const { error } = await supabase
        .from('users')
        .update(updates)
        .eq('id', req.user.id);

    if (error) return res.status(500).json({ error: 'Erro ao atualizar configurações.' });
    res.json({ message: 'Configurações atualizadas com sucesso.' });
});

/* ==================== CORE ROUTES ==================== */

const suspiciousPhrases = [
    'ganhe dinheiro rápido', 'última chance', 'oferta imperdível', 'clique aqui',
    'você foi sorteado', 'renda extra', 'lucro garantido', 'investimento seguro',
    'promoção exclusiva', 'urgente', 'bloqueado', 'atualize seus dados',
    'troquei de número', 'troquei meu número', 'preciso de ajuda urgente',
    'me faz um pix', 'me faz um pix agora', 'você foi selecionado',
    'emprestado até amanhã', 'minha conta bloqueou', 'paga essa conta pra mim',
    'não conta pra ninguém', 'é só por hoje', 'segredo nosso', 'não avisa o banco',
    'desbloqueio imediato', 'transferência de segurança', 'falso sequestro',
    'sem risco', 'método secreto', 'renda automática', 'fique rico trabalhando de casa',
    'liberdade financeira em dias', 'arrasta pra cima', 'compre meu curso'
];
const maliciousDomains = [
    "bit.ly", "tinyurl.com", "banco-seguro-br.com", "promocao-oficial.net"
];

const analyzeContent = async (text, type = 'text') => {
    try {
        const prompt = `
        Aja como um especialista em segurança cibernética e detecção de fraudes digitais (golpes de WhatsApp, SMS, E-mail e links maliciosos).
        Analise o seguinte conteúdo e forneça um resultado em formato JSON estrito com os seguintes campos:
        - score: um número de 0 a 100 representando o nível de risco (0-30 baixo, 31-60 suspeito, 61-100 alto).
        - status: Texto curto em MAIÚSCULAS ('BAIXO RISCO', 'CONTEÚDO SUSPEITO' ou 'ALTO RISCO').
        - signals: um array de strings com detalhes específicos sobre o motivo de ser golpe (ex: "Urgência detectada", "Promessa de dinheiro fácil", "Link suspeito"). Se for seguro, diga o que parece normal.
        - recommendation: uma sugestão clara do que o usuário deve fazer.

        CONTEÚDO PARA ANÁLISE:
        "${text}"
        `;

        const response = await openai.chat.completions.create({
            model: "gpt-4o-mini",
            messages: [
                { role: "system", content: "Você é um especialista em análise de fraudes digitais. Responda apenas em JSON." },
                { role: "user", content: prompt }
            ],
            response_format: { type: "json_object" }
        });

        const result = JSON.parse(response.choices[0].message.content);
        return result;
    } catch (error) {
        console.error("OpenAI Error:", error);
        // Fallback para lógica básica se a API falhar
        return {
            score: 50,
            status: 'ERRO NA ANÁLISE',
            signals: ['Não foi possível conectar à inteligência central.'],
            recommendation: 'Tente novamente em instantes ou verifique manualmente.'
        };
    }
};

const analyzeStore = async (url) => {
    try {
        const domainMatch = url.match(/^(?:https?:\/\/)?(?:[^@\n]+@)?(?:www\.)?([^:\/\n?]+)/im);
        const domain = domainMatch ? domainMatch[1] : url;

        const prompt = `
        Analise a URL de e-commerce abaixo e forneça um relatório de segurança em formato JSON.
        Verifique:
        - Typosquatting: Se domínios tentam se passar por marcas famosas (ex: ammericanas, magalu-ofertas, etc).
        - Extensões suspeitas: .top, .xyz, .site, .cloud são comuns em golpes.
        - Coerência do nome: Se o nome do domínio faz sentido para uma loja.

        URL: "${url}"
        DOMÍNIO: "${domain}"

        Retorne o JSON com os campos:
        - trustScore: número de 0 a 100.
        - registrationAge: Uma estimativa fictícia baseada no domínio (ex: "Poucos dias", "Antigo", "Bloqueado").
        - riskFactors: array de strings com detalhes sobre o que foi encontrado.
        - recommendation: Texto sugerindo se deve comprar ou não.
        `;

        const response = await openai.chat.completions.create({
            model: "gpt-4o-mini",
            messages: [
                { role: "system", content: "Você é um especialista em segurança de e-commerce. Responda apenas em JSON." },
                { role: "user", content: prompt }
            ],
            response_format: { type: "json_object" }
        });

        const result = JSON.parse(response.choices[0].message.content);
        return { domain, ...result };
    } catch (error) {
        console.error("Store Analysis Error:", error);
        return {
            domain: url,
            trustScore: 30,
            registrationAge: "Indeterminado",
            riskFactors: ["Falha na conexão com a inteligência de proteção."],
            recommendation: "Atenção redobrada. Não foi possível validar a segurança automaticamente."
        };
    }
};

app.post('/api/analyze', optionalAuthenticateToken, checkQuota, async (req, res) => {
    const { content, type } = req.body;
    const userId = req.user ? req.user.id : null;

    if (!content) {
        return res.status(400).json({ error: 'Nenhum conteúdo enviado para análise.' });
    }

    console.log(`🔍 Iniciando análise para usuário: ${userId || 'Anônimo'}`);
    const baseResult = await analyzeContent(content, type);

    // Dynamic patterns
    const { data: rows, error } = await supabase
        .from('scam_patterns')
        .select('pattern_text, pattern_type')
        .gte('report_count', 3);

    let dynamicScore = 0;
    let dynamicSignals = [];

    if (!error && rows && rows.length > 0) {
        const lowerContent = content.toLowerCase();
        rows.forEach(row => {
            if (lowerContent.includes(row.pattern_text.toLowerCase())) {
                dynamicScore += 25;
                dynamicSignals.push(`Padrão emergente relatado por usuários: "${row.pattern_text}"`);
            }
        });
    }

    baseResult.score = Math.min(100, Math.max(0, baseResult.score + dynamicScore));
    baseResult.signals.push(...dynamicSignals);

    if (baseResult.score > 60) {
        baseResult.status = 'ALTO RISCO';
        baseResult.recommendation = 'Evite clicar em links ou fornecer informações pessoais. Há alta probabilidade de fraude baseada também em alertas de outros usuários.';
    } else if (baseResult.score > 30) {
        baseResult.status = 'Conteúdo Suspeito';
        baseResult.recommendation = 'O conteúdo apresenta características dúbias e assemelha-se a alertas comunitários.';
    }

    if (baseResult.signals.length > 1 && baseResult.signals[0] === "Nenhum padrão malicioso conhecido foi detectado.") {
        baseResult.signals.shift();
    }

    console.log(`💾 Salvando relatório no banco para user: ${userId}`);
    const { error: insertError } = await supabase.from('reports').insert([{ user_id: userId, content, type: type || 'text', risk_score: baseResult.score }]);
    if (insertError) console.error("❌ Erro ao salvar relatório:", insertError);
    else console.log("✅ Relatório salvo com sucesso.");

    setTimeout(() => {
        res.json(baseResult);
    }, 1500);
});

const transcribeMedia = async (filePath) => {
    try {
        const transcription = await openai.audio.transcriptions.create({
            file: fs.createReadStream(filePath),
            model: "whisper-1",
        });
        return transcription.text;
    } catch (error) {
        console.error("Whisper Error:", error);
        throw new Error("Erro na transcrição do áudio.");
    }
};

const ACADEMY_QUIZZES = [
    {
        id: 1,
        title: "O Gerente do Banco no WhatsApp",
        context: "Você recebe uma mensagem no WhatsApp com a foto com o brasão do seu banco. A mensagem diz: 'Prezado cliente, identificamos um Pix suspeito de R$ 980,00 na sua conta. Para cancelar, confirme sua senha abaixo ou retorne C para falar com um atendente.'",
        options: [
            { text: "Respondo com 'C' para resolver o problema rapidamente com o atendente.", isCorrect: false, feedback: "Atenção: Golpistas usam urgência para o seu cérebro parar de pensar. Ao responder, eles te ligarão e guiarão você para fazer uma transferência falsa." },
            { text: "Digito a senha como pediram, pois a foto do perfil é realmente o símbolo do meu banco.", isCorrect: false, feedback: "Muito Perigoso: Qualquer um pode baixar a foto de um banco no Google. Bancos reais NUNCA pedem senhas pelo WhatsApp." },
            { text: "Ignoro a mensagem e abro o aplicativo oficial do meu banco pelo celular para checar o extrato.", isCorrect: true, feedback: "Exato! Você não cedeu à urgência. Ao checar o app oficial, você descobrirá que não há nenhum Pix suspeito." }
        ],
        points: 50
    },
    {
        id: 2,
        title: "A Compra Muito Barata",
        context: "Você vê um anúncio de uma Smart TV de 50 polegadas por R$ 350,00 alegando ser 'Liquidação de Estoque'. O site tem um design incrivelmente profissional.",
        options: [
            { text: "Aproveito a chance pois o site tem um cadeado verde na barra de navegação.", isCorrect: false, feedback: "Mito: O cadeado só significa que a conexão é privada. Hoje 95% dos sites golpistas têm cadeado." },
            { text: "Compro rapidamente porque vi diversos comentários positivos no anúncio.", isCorrect: false, feedback: "Erro Comum: Golpistas usam robôs para elogiar o próprio anúncio, criando prova social falsa." },
            { text: "Copio o link da loja e pesquiso no Verificador ShieldCheck antes de qualquer coisa.", isCorrect: true, feedback: "Perfeito! Consultar a idade do domínio revelará rapidamente que a 'loja' foi criada há apenas três dias." }
        ],
        points: 80
    },
    {
        id: 3,
        title: "O Empréstimo Facilitado",
        context: "Uma financeira 'on-line' entra em contato oferecendo crédito imediato com juros baixos, mesmo para negativados. No final, pedem um 'depósito de garantia' de R$ 200 para liberar o valor.",
        options: [
            { text: "Faço o Pix de R$ 200, pois o valor do empréstimo compensa muito esse custo inicial.", isCorrect: false, feedback: "Golpe Clássico: Nenhuma financeira séria pede dinheiro adiantado para liberar empréstimo." },
            { text: "Bloqueio o número imediatamente. Pedir dinheiro antecipado para liberar crédito é contra a lei e sinal claro de fraude.", isCorrect: true, feedback: "Correto! Esse é um dos golpes mais praticados. O dinheiro da 'garantia' simplesmente some." },
            { text: "Peço o contrato por e-mail para ler todas as cláusulas antes de pagar.", isCorrect: false, feedback: "Risco: Golpistas enviam contratos falsos e profissionais para te convencer a pagar. O ideal é ignorar." }
        ],
        points: 100
    }
];

app.post('/api/analyze-media', optionalAuthenticateToken, checkQuota, upload.single('file'), async (req, res) => {
    const { type } = req.body;
    const userId = req.user ? req.user.id : null;
    const file = req.file;

    if (!file) {
        return res.status(400).json({ error: 'Nenhum arquivo enviado.' });
    }

    try {
        // 1. Transcrever usando Whisper
        const transcribedText = await transcribeMedia(file.path);

        // 2. Analisar o texto transcrito usando nossa lógica de IA
        const baseResult = await analyzeContent(transcribedText, type || 'audio');

        // 3. Deletar arquivo temporário
        fs.unlinkSync(file.path);

        // 4. Registrar no Supabase
        await supabase.from('reports').insert([{
            user_id: userId,
            content: transcribedText,
            type: type || 'audio',
            risk_score: baseResult.score
        }]);

        res.json({
            ...baseResult,
            transcribedText
        });
    } catch (error) {
        if (file && fs.existsSync(file.path)) fs.unlinkSync(file.path);
        console.error("Analyze Media Error:", error);
        res.status(500).json({ error: error.message || 'Erro ao processar mídia.' });
    }
});

app.get('/api/history', async (req, res) => {
    const { data: rows, error } = await supabase
        .from('reports')
        .select('id, type, risk_score, timestamp')
        .order('timestamp', { ascending: false })
        .limit(10);

    if (error) return res.status(500).json({ error: error.message });
    res.json(rows || []);
});

/* ==================== CROWDSOURCING / REPORTING ROUTES ==================== */

app.post('/api/report-scam', authenticateToken, async (req, res) => {
    const { content, type } = req.body;
    const userId = req.user.id;

    if (!content) return res.status(400).json({ error: 'Conteúdo obrigatório.' });

    const { data: newReport, error: insertError } = await supabase
        .from('scam_reports')
        .insert([{ user_id: userId, content, content_type: type }])
        .select()
        .single();

    if (insertError) return res.status(500).json({ error: 'Erro ao registrar denúncia.' });

    const urlRegex = /(https?:\/\/[^\s]+)/g;
    const phoneRegex = /\+?55\s?\(?\d{2}\)?\s?\d{4,5}-?\d{4}/g;

    const urls = content.match(urlRegex) || [];
    const phones = content.match(phoneRegex) || [];

    let patternsToUpsert = [];
    urls.forEach(u => patternsToUpsert.push({ text: u, type: 'url' }));
    phones.forEach(p => patternsToUpsert.push({ text: p, type: 'phone' }));

    if (patternsToUpsert.length === 0) {
        const snippet = content.substring(0, 50).trim();
        if (snippet.length > 10) {
            patternsToUpsert.push({ text: snippet, type: 'text_snippet' });
        }
    }

    for (const p of patternsToUpsert) {
        const { data: existing } = await supabase
            .from('scam_patterns')
            .select('id, report_count')
            .eq('pattern_text', p.text)
            .single();

        if (existing) {
            await supabase
                .from('scam_patterns')
                .update({ report_count: existing.report_count + 1 })
                .eq('id', existing.id);
        } else {
            await supabase
                .from('scam_patterns')
                .insert([{ pattern_text: p.text, pattern_type: p.type, report_count: 1 }]);
        }
    }

    res.json({ message: 'Denúncia registrada e repassada à inteligência da rede.', report_id: newReport.id });
});

app.get('/api/recent-scams', async (req, res) => {
    const { data: rows, error } = await supabase
        .from('scam_reports')
        .select(`
            id, content, content_type, created_at,
            users ( name )
        `)
        .order('created_at', { ascending: false })
        .limit(5);

    if (error) return res.status(500).json({ error: error.message });

    // Flatten result for frontend
    const formattedRows = (rows || []).map(r => ({
        id: r.id,
        content: r.content,
        content_type: r.content_type,
        created_at: r.created_at,
        reporter: r.users ? r.users.name : 'Anônimo'
    }));

    res.json(formattedRows);
});

app.get('/api/admin/trends', async (req, res) => {
    const { data: rows, error } = await supabase
        .from('scam_patterns')
        .select('pattern_text, pattern_type, report_count')
        .order('report_count', { ascending: false })
        .limit(10);

    if (error) return res.status(500).json({ error: error.message });
    res.json(rows || []);
});

/* ==================== USER DATA ROUTES ==================== */

app.get('/api/user/history', authenticateToken, async (req, res) => {
    const { data: rows, error } = await supabase
        .from('reports')
        .select('id, content, type, risk_score, timestamp')
        .eq('user_id', req.user.id)
        .order('timestamp', { ascending: false });

    if (error) return res.status(500).json({ error: error.message });

    const historyDetails = (rows || []).map(row => {
        let status = 'BAIXO RISCO';
        if (row.risk_score > 60) status = 'ALTO RISCO';
        else if (row.risk_score > 30) status = 'SUSPEITO';
        return { ...row, status };
    });

    console.log(`📋 Buscando histórico para usuário: ${req.user.id}. Encontrados: ${rows?.length || 0} registros.`);
    res.json(historyDetails);
});

app.get('/api/user/stats', authenticateToken, async (req, res) => {
    const { data: rows, error } = await supabase
        .from('reports')
        .select('risk_score')
        .eq('user_id', req.user.id);

    if (error) return res.status(500).json({ error: error.message });

    const total = (rows || []).length;
    const golpes = (rows || []).filter(r => r.risk_score > 60).length;
    const seguros = (rows || []).filter(r => r.risk_score <= 30).length;
    const suspeitos = total - golpes - seguros;

    res.json({ total, golpes, seguros, suspeitos });
});

/* ==================== B2B DEVELOPER (API KEYS) ==================== */
const crypto = require('crypto');

app.get('/api/developer/key', authenticateToken, async (req, res) => {
    const userId = req.user.id;

    const { data: row, error } = await supabase
        .from('api_keys')
        .select('api_key, usage_count')
        .eq('user_id', userId)
        .single();

    if (row && row.api_key) {
        return res.json({ apiKey: row.api_key, usage: row.usage_count });
    } else {
        const newKey = 'sc_' + crypto.randomBytes(24).toString('hex');
        const { error: insertError } = await supabase
            .from('api_keys')
            .insert([{ user_id: userId, api_key: newKey }]);

        if (insertError) return res.status(500).json({ error: 'Não foi possível gerar a chave de API.' });
        res.json({ apiKey: newKey, usage: 0 });
    }
});

app.post('/api/v1/analyze', async (req, res) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) return res.status(401).json({ error: 'x-api-key header missing.' });

    const { data: row, error } = await supabase
        .from('api_keys')
        .select('user_id, usage_count')
        .eq('api_key', apiKey)
        .single();

    if (error || !row) return res.status(401).json({ error: 'Chave de API inválida.' });

    const { content, type } = req.body;
    if (!content) return res.status(400).json({ error: 'Campo content obrigatório.' });

    await supabase
        .from('api_keys')
        .update({ usage_count: row.usage_count + 1 })
        .eq('api_key', apiKey);

    const result = await analyzeContent(content, type);
    res.json({ success: true, provider: "ShieldCheck AI B2B", data: result });
});

/* ==================== WHATSAPP BOT INTEGRATION ==================== */

/**
 * Auxiliar para baixar mídia do WhatsApp (Twilio/Meta)
 */
const downloadWhatsAppMedia = async (url, filename) => {
    try {
        const response = await fetch(url);
        if (!response.ok) throw new Error(`Falha ao baixar mídia: ${response.statusText}`);
        const buffer = await response.arrayBuffer();
        const filePath = path.join('uploads', filename);
        fs.writeFileSync(filePath, Buffer.from(buffer));
        return filePath;
    } catch (error) {
        console.error("❌ Erro ao baixar mídia do WhatsApp:", error);
        return null;
    }
};

/**
 * Envia mensagem via WhatsApp (Twilio ou Meta)
 * Por enquanto faz log, mas está pronto para integração real
 */
const sendWhatsAppReply = async (to, message) => {
    console.log(`📤 [WHATSAPP OUT] Para: ${to} | Mensagem: ${message.substring(0, 50)}...`);

    // Configuração para Twilio (se as credenciais existirem)
    if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_PHONE) {
        try {
            const twilio = require('twilio');
            const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
            await client.messages.create({
                body: message,
                from: process.env.TWILIO_PHONE,
                to: `whatsapp:+${to}`
            });
            console.log("✅ Mensagem enviada via Twilio com sucesso!");
        } catch (err) {
            console.error("❌ Erro ao enviar via Twilio:", err.message);
        }
    } else {
        console.log("⚠️ Credenciais Twilio não configuradas - rodando em modo simulação.");
    }
};

/**
 * Endpoint para receber mensagens do WhatsApp (via Webhook)
 * Suporta provedores como Twilio, Meta Business ou instâncias privadas.
 */
app.post('/api/whatsapp/webhook', async (req, res) => {
    try {
        const incomingData = req.body;
        console.log("📱 Mensagem recebida via WhatsApp:", JSON.stringify(incomingData, null, 2));

        // Estrutura genérica de mensagem (compatível com Twilio e Webhooks padrão)
        const content = incomingData.text || incomingData.Body || "";
        const sender = incomingData.from || incomingData.From || "Desconhecido";
        const mediaUrl = incomingData.MediaUrl0 || incomingData.media || null;
        const mediaType = incomingData.MediaContentType0 || "";

        let userId = null;
        let riskEmoji = "🛡️";
        let finalContent = content;
        let isAudio = false;

        // Tentar vincular ao usuário via número de telefone
        const formattedSender = sender.replace(/\D/g, ''); // Limpa caracteres não numéricos. Ex: whatsapp:+5511 -> 5511

        // Se começar com whatsapp:, remove
        const cleanNumber = formattedSender.startsWith('55') ? formattedSender : formattedSender.replace(/^.*(?=55)/, '');

        const { data: userData } = await supabase
            .from('users')
            .select('id, name, plan')
            .ilike('whatsapp_number', `%${cleanNumber}%`)
            .maybeSingle();

        if (userData) {
            userId = userData.id;
            console.log(`🔗 Mensagem vinculada ao usuário: ${userData.name} (${userId})`);
        }

        if (mediaUrl && (mediaType.includes('audio') || mediaUrl.includes('ogg') || mediaUrl.includes('mp3'))) {
            console.log("🎙️ Áudio detectado no WhatsApp. Processando...");
            const tempFile = `wa_${Date.now()}_${cleanNumber}.ogg`;
            const filePath = await downloadWhatsAppMedia(mediaUrl, tempFile);

            if (filePath) {
                try {
                    finalContent = await transcribeMedia(filePath);
                    isAudio = true;
                    console.log(`📝 Transcrição concluída: "${finalContent.substring(0, 50)}..."`);
                    fs.unlinkSync(filePath); // Limpa o arquivo
                } catch (transcribeError) {
                    console.error("❌ Erro na transcrição:", transcribeError);
                    finalContent = "[Erro ao processar áudio]";
                }
            }
        }

        let replyMessage = "";

        if (finalContent && finalContent !== "[Erro ao processar áudio]") {
            // Análise de texto usando nossa lógica central
            const verdict = await analyzeContent(finalContent, isAudio ? 'audio' : 'whatsapp');

            riskEmoji = verdict.score > 60 ? "🚨" : verdict.score > 30 ? "⚠️" : "✅";

            replyMessage = `*RESULTADO SHIELDCHECK AI* ${riskEmoji}\n\n`;
            if (isAudio) replyMessage += `*O que ouvimos:* "${finalContent.substring(0, 100)}${finalContent.length > 100 ? '...' : ''}"\n\n`;

            replyMessage += `*Status:* ${verdict.status}\n`;
            replyMessage += `*Risco:* ${verdict.score}/100\n\n`;
            replyMessage += `*Sinais:* \n${verdict.signals.map(s => `• ${s}`).join('\n')}\n\n`;
            replyMessage += `*Recomendação:* ${verdict.recommendation}\n\n`;
            replyMessage += `--- \n`;
            replyMessage += `🚀 *Proteja seus amigos:* Encaminhe esta análise para quem te enviou a mensagem original!\n\n`;
            replyMessage += `📱 *Salve este contato:* ShieldCheck AI - Seu Escudo Digital.\n`;
            replyMessage += `🔗 *Painel de Controle:* https://shieldcheck-ai.vercel.app`; // Ajustar para URL real

            // Salvar no histórico se o usuário estiver vinculado
            if (userId) {
                await supabase.from('reports').insert([{
                    user_id: userId,
                    content: finalContent,
                    type: isAudio ? 'audio' : 'whatsapp',
                    risk_score: verdict.score,
                    timestamp: new Date().toISOString()
                }]);
            }
        } else if (finalContent === "[Erro ao processar áudio]") {
            replyMessage = "❌ *ShieldCheck AI:* Desculpe, não consegui processar seu áudio no momento. Tente me enviar o texto da mensagem ou um link.";
        } else {
            replyMessage = "🛡️ Olá! Eu sou o assistente do *ShieldCheck AI*. \n\nEnvie qualquer mensagem suspeita, link ou áudio para eu analisar o risco de golpe para você em segundos.";
        }

        // Enviar a resposta real
        await sendWhatsAppReply(cleanNumber, replyMessage);

        res.json({
            success: true,
            destination: cleanNumber,
            reply: replyMessage
        });

    } catch (error) {
        console.error("❌ Erro no Webhook do WhatsApp:", error);
        res.status(500).json({ error: "Erro ao processar mensagem do WhatsApp." });
    }
});

/* ==================== STORE CHECKER (E-COMMERCE) ==================== */

app.get('/api/check-store', optionalAuthenticateToken, async (req, res) => {
    const { url } = req.query;
    if (!url) return res.status(400).json({ error: 'URL da loja obrigatória.' });

    const result = await analyzeStore(url);
    res.json(result);
});

/* ==================== ACADEMY (GAMIFICATION) ==================== */

app.get('/api/academy/quizzes', optionalAuthenticateToken, (req, res) => {
    res.json(ACADEMY_QUIZZES);
});

app.post('/api/academy/submit', authenticateToken, async (req, res) => {
    const { isCorrect, pointsAwarded } = req.body;
    if (isCorrect) {
        const { data: user } = await supabase
            .from('users')
            .select('points')
            .eq('id', req.user.id)
            .single();

        const currentPoints = user ? (user.points || 0) : 0;

        const { error } = await supabase
            .from('users')
            .update({ points: currentPoints + pointsAwarded })
            .eq('id', req.user.id);

        if (error) return res.status(500).json({ error: 'Erro ao atribuir pontos.' });
        res.json({ success: true, pointsAwarded, message: 'Pontos adicionados com sucesso!' });
    } else {
        res.json({ success: false, message: 'Resposta Incorreta. Tente novamente mais tarde.' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`ShieldCheck AI Backend rodando na porta ${PORT} com Supabase`);
});

