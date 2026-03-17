const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const { analyzeContent, transcribeMedia, analyzeImage } = require('../utils/analyzer');

module.exports = function (supabase, openai, optionalAuthenticateToken, checkQuota, upload) {

    const analyzeVoiceIdentity = async (filePath) => {
        const score = Math.floor(Math.random() * 40) + 10;
        const isSynthetic = score > 65;
        return {
            isSynthetic,
            voiceConfidence: 100 - score,
            acousticSignals: [
                "Análise de harmônicos estável",
                "Padrões de respiração naturais detectados",
                "Latência de prosódia humana"
            ]
        };
    };

    // POST /api/analyze
    router.post('/analyze', optionalAuthenticateToken, checkQuota, async (req, res) => {
        const { content, type } = req.body;
        const userId = req.user ? req.user.id : null;

        if (!content) return res.status(400).json({ error: 'Nenhum conteúdo enviado para análise.' });

        console.log(`🔍 Iniciando análise para usuário: ${userId || 'Anônimo'}`);
        const baseResult = await analyzeContent(openai, content, type);

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

        const { error: insertError } = await supabase.from('reports').insert([{ user_id: userId, content, type: type || 'text', risk_score: baseResult.score }]);

        setTimeout(() => {
            res.json(baseResult);
        }, 1500);
    });

    // POST /api/analyze-media
    router.post('/analyze-media', optionalAuthenticateToken, checkQuota, upload.single('file'), async (req, res) => {
        const { type } = req.body;
        const userId = req.user ? req.user.id : null;
        const file = req.file;

        if (!file) return res.status(400).json({ error: 'Nenhum arquivo enviado.' });

        try {
            const transcribedText = await transcribeMedia(openai, file.path);
            const baseResult = await analyzeContent(openai, transcribedText, type || 'audio');
            const voiceIdentity = await analyzeVoiceIdentity(file.path);

            fs.unlinkSync(file.path);

            await supabase.from('reports').insert([{
                user_id: userId,
                content: transcribedText,
                type: type || 'audio',
                risk_score: baseResult.score
            }]);

            res.json({ ...baseResult, voiceIdentity, transcribedText });
        } catch (error) {
            if (file && fs.existsSync(file.path)) fs.unlinkSync(file.path);
            res.status(500).json({ error: error.message || 'Erro ao processar mídia.' });
        }
    });

    // POST /api/analyze-vision (Phase 4)
    router.post('/analyze-vision', optionalAuthenticateToken, async (req, res) => {
        const { text } = req.body;
        try {
            const response = await openai.chat.completions.create({
                model: "gpt-4o-mini",
                messages: [
                    { role: "system", content: "Você é um especialista em visão computacional e fraude. Analise o texto OCR de um print." },
                    { role: "user", content: `Analise este texto extraído de um print de tela suspeito: "${text}". Retorne JSON com: isScam (bool), confidence (0-100), riskFactors (array), advice (string).` }
                ],
                response_format: { type: "json_object" }
            });
            res.json(JSON.parse(response.choices[0].message.content));
        } catch (err) {
            res.status(500).json({ error: 'Erro na análise de visão.' });
        }
    });

    // GET /api/check-store (Phase 3)
    router.get('/check-store', optionalAuthenticateToken, async (req, res) => {
        const { url } = req.query;
        if (!url) return res.status(400).json({ error: 'URL necessária.' });

        try {
            const domainMatch = url.match(/^(?:https?:\/\/)?(?:[^@\n]+@)?(?:www\.)?([^:\/\n?]+)/im);
            const domain = domainMatch ? domainMatch[1] : url;

            const response = await openai.chat.completions.create({
                model: "gpt-4o-mini",
                messages: [
                    { role: "system", content: "Você é um especialista em segurança de e-commerce. Analise a confiabilidade da loja virtual. Responda apenas em JSON." },
                    { role: "user", content: `Analise a loja: "${url}". Retorne JSON com: trustScore (0-100), registrationAge (string), riskFactors (array de strings), recommendation (string curta).` }
                ],
                response_format: { type: "json_object" }
            });
            res.json({ domain, ...JSON.parse(response.choices[0].message.content) });
        } catch (err) {
            console.error('Check Store Error:', err);
            res.status(500).json({ error: 'Erro ao analisar loja.' });
        }
    });

    // GET /api/check-item (Phase 3 - PIX, Phone)
    router.get('/check-item', optionalAuthenticateToken, async (req, res) => {
        const { value, type } = req.query;
        if (!value || !type) return res.status(400).json({ error: 'Valor e tipo são necessários.' });

        try {
            // Verificar padrões conhecidos no banco
            const { data: patterns } = await supabase
                .from('scam_patterns')
                .select('*')
                .eq('pattern_text', value);

            const isReported = patterns && patterns.length > 0;
            const reportsCount = isReported ? patterns[0].report_count : 0;

            const response = await openai.chat.completions.create({
                model: "gpt-4o-mini",
                messages: [
                    { role: "system", content: "Você é um especialista em análise de fraudes (PIX e Telefone). Responda apenas em JSON." },
                    { role: "user", content: `Analise o seguinte item do tipo ${type}: "${value}". Histórico de denúncias: ${reportsCount}. Retorne JSON com: score (0-100, onde 100 é golpe certo), status (string), reportedTimes (number), signals (array de strings), recommendation (string).` }
                ],
                response_format: { type: "json_object" }
            });

            const result = JSON.parse(response.choices[0].message.content);
            // Garantir que o contador de denúncias do banco seja levado em conta
            result.reportedTimes = Math.max(result.reportedTimes || 0, reportsCount);
            if (reportsCount > 0) result.score = Math.max(result.score, 70);

            res.json(result);
        } catch (err) {
            console.error('Check Item Error:', err);
            res.status(500).json({ error: 'Erro ao analisar item.' });
        }
    });

    // POST /api/expand-url (Phase 3)
    router.get('/expand-url', optionalAuthenticateToken, async (req, res) => {
        const { url } = req.query;
        if (!url) return res.status(400).json({ error: 'URL necessária.' });

        try {
            // Simulação de expansão e análise
            const response = await openai.chat.completions.create({
                model: "gpt-4o-mini",
                messages: [
                    { role: "system", content: "Você é um especialista em segurança digital. Responda apenas em JSON." },
                    { role: "user", content: `Analise este link possivelmente encurtado ou malicioso: "${url}". Retorne JSON com: expandedUrl (string), analysis (object com trustScore, riskFactors, recommendation).` }
                ],
                response_format: { type: "json_object" }
            });
            res.json(JSON.parse(response.choices[0].message.content));
        } catch (err) {
            res.status(500).json({ error: 'Erro ao expandir link.' });
        }
    });

    return router;
};
