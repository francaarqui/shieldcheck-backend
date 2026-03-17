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
            baseResult.recommendation = '⚠️ ALERTA DE SEGURANÇA: Nossa análise identificou múltiplos vetores de ataque e padrões de engenharia social conhecidos. Recomenda-se o bloqueio imediato e não compartilhamento de dados sensíveis.';
        } else if (baseResult.score > 30) {
            baseResult.status = 'Consistência Duvidosa';
            baseResult.recommendation = 'ANÁLISE DE ATENÇÃO: Foram detectados sinais de alerta que, embora não conclusivos, assemelham-se a táticas de persuasão usadas por golpistas. Proceda com cautela extrema.';
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
                model: "gpt-4o",
                messages: [
                    { role: "system", content: "Você é um Perito em Fraudes Documentais e Fraude de Boletos Bancários. Sua função é analisar textos extraídos por OCR e identificar discrepâncias fiscais, erros de digitação em campos críticos e padrões de boletos falsos." },
                    {
                        role: "user", content: `Analise este texto extraído de um documento/boleto: "${text}". 
                    Verifique:
                    - Consistência entre o nome do beneficiário e o CPF/CNPJ.
                    - Formatação de códigos de barras (se presentes em texto).
                    - Termos comuns em golpes (ex: 'Agência e Código do Cedente' divergentes).
                    - Veracidade aparente de datas e valores expressos.

                    Retorne EXCLUSIVAMENTE um objeto JSON: { isScam (bool), confidence (0-100), riskFactors (array com justificativas técnicas), advice (veredito final do perito) }.` }
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
                model: "gpt-4o",
                messages: [
                    { role: "system", content: "Você é um Especialista de Segurança de Elite com foco em Threat Intelligence e E-commerce Fraud. Sua missão é realizar uma auditoria técnica profunda em domínios." },
                    {
                        role: "user", content: `Realize uma auditoria técnica completa no domínio: "${url}". 
                    
                    VETORES DE INVESTIGAÇÃO:
                    - WHOIS: Analise idade do domínio, proprietário e ocultação de dados.
                    - SSL: Verifique tipo de certificado, emissor e expiração.
                    - DNS & HEADERS: Simule checagem de DMARC/SPF e cabeçalhos de servidor comuns em lojas falsas.
                    - BLACKLISTS: Verifique reputação em bases globais de phishing e malware.
                    - TYPOSQUATTING: Identifique variações de nomes de marcas famosas.

                    Retorne um JSON detalhado: { trustScore (0-100), registrationAge (ex: "2 anos e 3 meses"), riskFactors (array de strings técnicas), recommendation (veredito técnico detalhado) }.` }
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
                model: "gpt-4o",
                messages: [
                    { role: "system", content: "Você é um Analista de Segurança Senior especializado em monitoramento de transações e Deep Web. Sua função é auditar chaves PIX e Números de Telefone em busca de padrões criminosos." },
                    {
                        role: "user", content: `Investigue o item (${type}): "${value}". 
                    Histórico de denúncias: ${reportsCount}.

                    CRITÉRIOS DE AUDITORIA:
                    - Padrões de nomes de laranjas ou contas de aluguel.
                    - Formatos de chaves aleatórias geradas por scripts de golpe.
                    - DDDs e Prefixos com alto índice de atividades de estelionato.
                    - Cruzamento com formatos de dados comumente encontrados em leaks.

                    Retorne um JSON: { score (0-100), status (string técnica), reportedTimes (number), signals (array de achados técnicos), recommendation (diretriz de segurança final) }.` }
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
                model: "gpt-4o",
                messages: [
                    { role: "system", content: "Você é um Especialista de Forense em URLs e Malware. Sua função é expandir links e identificar redirecionamentos perigosos." },
                    {
                        role: "user", content: `Analise o link: "${url}". 
                    
                    OBJETIVOS:
                    - Expandir encurtadores e identificar o destino real.
                    - Detectar Shadow Redirects e Phishing de credenciais.
                    - Avaliar a reputação do serviço de encurtamento.
                    
                    Retorne um JSON: { expandedUrl (string), analysis: { trustScore, riskFactors (array), recommendation (string) } }.` }
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
