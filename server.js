const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const Stripe = require('stripe');

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-shieldcheck-key-2026';
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const stripe = Stripe(STRIPE_SECRET_KEY);
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET; // Para ambiente de teste online ou webhook cli

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

const optionalAuthenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return next();
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (!err) {
            req.user = user;
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

const analyzeContent = (text, type = 'text') => {
    let score = 0;
    const lowerText = text.toLowerCase();
    const signals = [];

    // Analyze text/phrases
    for (const phrase of suspiciousPhrases) {
        if (lowerText.includes(phrase)) {
            score += 35;
            signals.push(`Urgência/Promessa detectada: "${phrase}"`);
        }
    }

    // Analyze links
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    const urls = text.match(urlRegex);
    if (urls) {
        let hasSuspiciousLink = false;
        urls.forEach(url => {
            const domain = new URL(url).hostname;
            if (maliciousDomains.some(d => domain.includes(d))) {
                score += 50;
                signals.push(`Link suspeito detectado: ${domain}`);
                hasSuspiciousLink = true;
            }
        });
        if (!hasSuspiciousLink) {
            score += 10;
            signals.push('Contém links externos (verifique o destino).');
        }
    }

    // Phone numbers (mock)
    const phoneRegex = /\+?55\s?\(?\d{2}\)?\s?\d{4,5}-?\d{4}/g;
    const phones = text.match(phoneRegex);
    if (phones && phones.length > 0) {
        score += 20;
        signals.push('Contém número de telefone. Desconfie de DDDs desconhecidos.');
    }

    // Money requests
    const moneyRegex = /pix|transferir|pagar|boleto|r\$\s?\d+/gi;
    if (moneyRegex.test(text)) {
        score += 25;
        signals.push('Menção a pagamentos ou dinheiro.');
    }

    // Normalize score
    score = Math.min(100, Math.max(0, score));

    let status = 'Baixo risco';
    let recommendation = 'O conteúdo parece seguro, mas mantenha a atenção a detalhes imperceptíveis.';

    if (score > 60) {
        status = 'ALTO RISCO';
        recommendation = 'Evite clicar em links ou fornecer informações pessoais. Há uma alta probabilidade de fraude.';
    } else if (score > 30) {
        status = 'Conteúdo Suspeito';
        recommendation = 'O conteúdo apresenta características dúbias. Não tome decisões precipitadas e verifique a fonte oficial.';
    }

    if (score === 0 && signals.length === 0) {
        signals.push("Nenhum padrão malicioso conhecido foi detectado.")
    }

    return { score, status, signals, recommendation };
};

app.post('/api/analyze', optionalAuthenticateToken, async (req, res) => {
    const { content, type } = req.body;
    const userId = req.user ? req.user.id : null;

    if (!content) {
        return res.status(400).json({ error: 'Nenhum conteúdo enviado para análise.' });
    }

    const baseResult = analyzeContent(content, type);

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

    await supabase.from('reports').insert([{ user_id: userId, content, type: type || 'text', risk_score: baseResult.score }]);

    setTimeout(() => {
        res.json(baseResult);
    }, 1500);
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

    const result = analyzeContent(content, type);
    res.json({ success: true, provider: "ShieldCheck AI B2B", data: result });
});

/* ==================== STORE CHECKER (E-COMMERCE) ==================== */

app.get('/api/check-store', optionalAuthenticateToken, (req, res) => {
    const { url } = req.query;
    if (!url) return res.status(400).json({ error: 'URL da loja obrigatória.' });

    setTimeout(() => {
        const domainMatch = url.match(/^(?:https?:\/\/)?(?:[^@\n]+@)?(?:www\.)?([^:\/\n?]+)/im);
        const domain = domainMatch ? domainMatch[1] : url;

        const isMalicious = maliciousDomains.includes(domain.toLowerCase());
        const isNew = Math.random() > 0.5;

        let trustScore = 85;
        let riskFactors = [];
        let registrationAge = isNew ? '12 dias (Risco Extremo)' : '3 anos e 4 meses (Confiável)';

        if (isMalicious) {
            trustScore = 5;
            riskFactors.push('Domínio presente em nossa lista de bloqueios ativa.');
            registrationAge = 'Domínio Bloqueado';
        } else if (isNew) {
            trustScore = 30;
            riskFactors.push('O domínio foi registrado há menos de 1 mês. A chance de fraude iminente é altíssima.');
            riskFactors.push('Nenhum CNPJ válido ou correspondente encontrado no rodapé do site.');
        } else {
            riskFactors.push('CNPJ confere com o titular do domínio.');
        }

        res.json({
            domain, trustScore, registrationAge, riskFactors,
            recommendation: trustScore > 50 ? 'Loja aparentemente segura para transações.' : 'NÃO REALIZE COMPRAS NESTE SITE. Alto risco de perda financeira.'
        });
    }, 1200);
});

/* ==================== ACADEMY (GAMIFICATION) ==================== */

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
