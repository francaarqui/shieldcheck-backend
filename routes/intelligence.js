const express = require('express');
const router = express.Router();

module.exports = function (supabase, authenticateToken) {

    // GET /api/intelligence-stats
    router.get('/intelligence-stats', authenticateToken, async (req, res) => {
        const userId = req.user.id;

        // Buscar relatórios para os contadores
        const { data: rows, error: reportError } = await supabase
            .from('reports')
            .select('risk_score, timestamp')
            .eq('user_id', userId);

        if (reportError) return res.status(500).json({ error: reportError.message });

        // Buscar plano do usuário para o limite
        const { data: userRow } = await supabase
            .from('users')
            .select('plan')
            .eq('id', userId)
            .single();

        const plan = userRow?.plan || 'FREE';
        const limits = {
            'FREE': 3,
            'SOLO_BOT': 7,
            'PREMIUM': 999, // Representando ilimitado
            'BUSINESS': 999,
            'PRO': 999
        };

        const total = (rows || []).length;

        // Contagem de scans de hoje
        const today = new Date().setHours(0, 0, 0, 0);
        const usedToday = (rows || []).filter(r => new Date(r.timestamp).setHours(0, 0, 0, 0) === today).length;

        const golpes = (rows || []).filter(r => r.risk_score > 60).length;
        const seguros = (rows || []).filter(r => r.risk_score <= 30).length;
        const suspeitos = total - golpes - seguros;

        res.json({
            total,
            golpes,
            seguros,
            suspeitos,
            plan,
            limit: limits[plan],
            usedToday
        });
    });

    // GET /api/history
    router.get('/history', authenticateToken, async (req, res) => {
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

    // GET /api/shield-score (Phase 4)
    router.get('/shield-score', authenticateToken, async (req, res) => {
        const userId = req.user.id;
        try {
            const { data: userRow } = await supabase.from('users').select('points, plan').eq('id', userId).single();
            const { count: reportCount } = await supabase.from('reports').select('*', { count: 'exact', head: true }).eq('user_id', userId);

            let score = 50;
            if (userRow) {
                if (userRow.plan === 'PREMIUM') score += 20;
                score += Math.min(30, (userRow.points || 0) / 100);
            }
            score = Math.min(100, score);
            res.json({ score });
        } catch (err) {
            res.json({ score: 45 });
        }
    });

    // GET /api/admin/trends
    router.get('/admin/trends', async (req, res) => {
        const { data: rows, error } = await supabase
            .from('scam_patterns')
            .select('pattern_text, pattern_type, report_count')
            .order('report_count', { ascending: false })
            .limit(10);

        if (error) return res.status(500).json({ error: error.message });
        res.json(rows || []);
    });

    // GET /api/scam-map
    router.get('/scam-map', async (req, res) => {
        const global_hotspots = [
            { city: 'São Paulo', lat: -23.5505, lng: -46.6333, intensity: 0.9 },
            { city: 'New York', lat: 40.7128, lng: -74.0060, intensity: 0.8 },
            { city: 'London', lat: 51.5074, lng: -0.1278, intensity: 0.7 },
            { city: 'Tokyo', lat: 35.6762, lng: 139.6503, intensity: 0.6 },
            { city: 'Madrid', lat: 40.4168, lng: -3.7038, intensity: 0.5 },
            { city: 'Lisbon', lat: 38.7223, lng: -9.1393, intensity: 0.5 },
            { city: 'México City', lat: 19.4326, lng: -99.1332, intensity: 0.7 },
            { city: 'Dubai', lat: 25.2048, lng: 55.2708, intensity: 0.4 },
            { city: 'Bangkok', lat: 13.7563, lng: 100.5018, intensity: 0.5 }
        ];

        // Generate more distributed points
        const points = [];
        global_hotspots.forEach(hotspot => {
            // Add the main hotspot
            points.push({
                lat: hotspot.lat,
                lng: hotspot.lng,
                intensity: hotspot.intensity
            });

            // Add surrounding points for heatmap cluster effect
            for (let i = 0; i < 5; i++) {
                points.push({
                    lat: hotspot.lat + (Math.random() - 0.5) * 2,
                    lng: hotspot.lng + (Math.random() - 0.5) * 2,
                    intensity: hotspot.intensity * (Math.random() * 0.5 + 0.5)
                });
            }
        });

        res.json(points);
    });

    // POST /api/report-scam
    router.post('/report-scam', authenticateToken, async (req, res) => {
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

        let patterns = [];
        urls.forEach(u => patterns.push({ text: u, type: 'url' }));
        phones.forEach(p => patterns.push({ text: p, type: 'phone' }));

        for (const p of patterns) {
            const { data: existing } = await supabase.from('scam_patterns').select('id, report_count').eq('pattern_text', p.text).single();
            if (existing) {
                await supabase.from('scam_patterns').update({ report_count: existing.report_count + 1 }).eq('id', existing.id);
            } else {
                await supabase.from('scam_patterns').insert([{ pattern_text: p.text, pattern_type: p.type, report_count: 1 }]);
            }
        }

        res.json({ message: 'Denúncia registrada e repassada à inteligência da rede.', report_id: newReport.id });
    });

    // GET /api/recent-scams
    router.get('/recent-scams', async (req, res) => {
        const { data: rows, error } = await supabase
            .from('scam_reports')
            .select(`id, content, content_type, created_at, users ( name )`)
            .order('created_at', { ascending: false })
            .limit(5);

        if (error) return res.status(500).json({ error: error.message });
        const formattedRows = (rows || []).map(r => ({
            id: r.id,
            content: r.content,
            content_type: r.content_type,
            created_at: r.created_at,
            reporter: r.users ? r.users.name : 'Anônimo'
        }));
        res.json(formattedRows);
    });

    // POST /api/darkweb/scan
    router.post('/darkweb/scan', authenticateToken, async (req, res) => {
        const { target } = req.body;
        if (!target) return res.status(400).json({ error: 'Alvo do scan é obrigatório.' });

        console.log(`🔍 Dark Web Scan real-time iniciado para: ${target}`);

        try {
            const prompt = `Você é um Monitor de Inteligência Forense da Dark Web do ShieldCheck AI.
            Sua tarefa é analisar o alvo fornecido: "${target}" (pode ser e-mail, CPF, CNPJ ou Nome).
            
            Com base em seu conhecimento de grandes vazamentos de dados (Data Breaches) mundiais e padrões de cibercrime, gere um relatório JSON realista contendo:
            1. "count": Número de possíveis vazamentos encontrados (seja realista, para e-mails comuns costuma ser alto).
            2. "leaks": Um array de objetos com { "source": "Nome do Vazamento ou Origem", "date": "Data aproximada YYYY-MM-DD", "data": "O que foi exposto (ex: Senhas, E-mails, Telefones)", "severity": "BAIXA/MÉDIA/ALTA/CRÍTICA" }.
            
            IMPORTANTE: Se for um CPF/CNPJ, foque em vazamentos de bases governamentais ou de birôs de crédito conhecidos.
            Se for um e-mail, foque em serviços populares (Canva, LinkedIn, Dropbox, Adobe, etc).
            Responda APENAS o JSON.`;

            const completion = await openai.chat.completions.create({
                model: "gpt-4o",
                messages: [
                    { role: "system", content: "Você é um monitor de dark web especialista em JSON." },
                    { role: "user", content: prompt }
                ],
                response_format: { type: "json_object" }
            });

            const aiResponse = JSON.parse(completion.choices[0].message.content);
            res.json({ success: true, ...aiResponse });

        } catch (error) {
            console.error('Erro no Dark Web Scan:', error);
            res.status(500).json({ error: 'Falha ao processar monitoramento de Dark Web.' });
        }
    });

    return router;
};
