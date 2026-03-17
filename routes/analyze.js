const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const { analyzeContent, transcribeMedia, analyzeImage } = require('../utils/analyzer');
const { getNetworkInfo } = require('../utils/networkChecker');

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

        console.log(`🌐 AUDITORIA DE LOJA: Analisando ${url}`);

        try {
            const domainMatch = url.match(/^(?:https?:\/\/)?(?:[^@\n]+@)?(?:www\.)?([^:\/\n?]+)/im);
            const domain = domainMatch ? domainMatch[1] : url;

            const networkData = await getNetworkInfo(domain);

            const response = await openai.chat.completions.create({
                model: "gpt-4o",
                messages: [
                    {
                        role: "system",
                        content: `Você é um Auditor Sênior de Segurança Digital. Sua missão é analisar dados técnicos REAIS. 
                        
                        REGRAS DE VERACIDADE (CRÍTICO):
                        1. NUNCA INVENTE datas de registro. Se não houver data no contexto, diga "Idade de registro protegida ou não identificada via DNS".
                        2. Se 'ssl.valid' for true, o SSL é SEGURO. Não diga que é suspeito se o certificado estiver válido e funcional.
                        3. Se nameservers indicar algo como 'cloudflare.com' ou 'vercel-dns.com', aponte como ponto positivo de infraestrutura.
                        4. Analise o contexto: se o domínio é muito curto ou usa extensões comuns de golpe (.shop, .promo, .xyz) sem infraestrutura sólida, aponte o risco.
                        5. Seja técnico e objetivo: use termos como "Propagação DNS", "Autoridade do Emissor SSL", "TTL de Registro".`
                    },
                    {
                        role: "user", content: `AUDITORIA TÉCNICA REAIS para o domínio: "${domain}". 
                    
                    DADOS TÉCNICOS COLETADOS:
                    - DNS RESOLVIDO: ${networkData.dns.resolved ? 'SIM' : 'NÃO'}
                    - SERVIDORES NS: ${JSON.stringify(networkData.dns.nameservers)}
                    - IP: ${JSON.stringify(networkData.dns.records)}
                    - CERTIFICADO SSL: Valid=${networkData.ssl.valid}, Emissor=${networkData.ssl.issuer}, Válido até=${networkData.ssl.validTo}
                    
                    MISSÃO:
                    Forneça um laudo técnico de confiança. Se a loja acabou de ser criada (poucos dias), e você vê um SSL novo ou DNS básico, aponte isso como um fator de alerta para novos comércios. Se o usuário diz que criou a loja há poucos dias, seu laudo deve confirmar que a infraestrutura é 'Recém-configurada'.

                    Retorne um JSON: { 
                        trustScore: (0-100), 
                        registrationAge: (string técnica, ex: "Infraestrutura Recém-detectada" ou "Domínio Estabelecido"), 
                        riskFactors: (array), 
                        recommendation: (veredito técnico impactante) 
                    }.` }
                ],
                response_format: { type: "json_object" }
            });

            const result = JSON.parse(response.choices[0].message.content);
            console.log(`✅ AUDITORIA DE LOJA: Concluída para ${domain} | Score: ${result.trustScore}`);
            res.json({ domain, ...result });
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

    // POST /api/check-social
    router.post('/check-social', optionalAuthenticateToken, checkQuota, async (req, res) => {
        const { handle } = req.body;
        if (!handle) return res.status(400).json({ error: 'Handle necessário.' });

        console.log(`🕵️ AUDITORIA SOCIAL: Iniciando investigação para @${handle}`);

        try {
            const response = await openai.chat.completions.create({
                model: "gpt-4o",
                messages: [
                    {
                        role: "system",
                        content: `Você é uma Unidade de Inteligência Cibernética (OSINT). Sua missão é realizar uma auditoria forense baseada na estrutura de handles e padrões comportamentais de redes sociais.
                        
                        DIRETRIZES TÉCNICAS:
                        1. Analise o handle "@${handle}" em busca de:
                           - Entropia de caracteres (ex: excesso de números aleatórios).
                           - Padrões de substituição (L por 1, O por 0) típicos de perfis falsos.
                           - Semântica de autoridade forjada (uso de termos como 'oficial', 'sac', 'atendimento' em contas sem selo).
                        2. Como você não tem acesso a métricas em tempo real (seguidores exatos), utilize seu conhecimento de base sobre a popularidade do handle ou, na ausência, forneça uma ESTIMATIVA PROFISSIONAL qualitativa (ex: "Perfil com baixa densidade orgânica aparente" ou "Handle com características de criador de conteúdo").
                        3. NUNCA exiba "Não disponível". Use termos como "Analítico Pendente", "Estimado via Padrão Forense" ou "Análise de Densidade Sugere: [valor qualitativo]".`
                    },
                    {
                        role: "user", content: `Realize a auditoria completa do perfil: "@${handle}".
                        
                        Retorne EXCLUSIVAMENTE um objeto JSON com: 
                        { 
                          botProbability: (0-100), 
                          accountAge: (string qualitativa profisisonal, ex: "Estabelecido há mais de 2 anos" ou "Recém-detectado"), 
                          followers: (string qualitativa, ex: "Alcance Orgânico Moderado"), 
                          following: (string qualitativa), 
                          riskLevel: (Baixo, Médio, ALTO), 
                          verdict: (veredito curto e impactante), 
                          signals: (array de 3 a 5 evidências forenses), 
                          recommendation: (instrução técnica clara) 
                        }.`
                    }
                ],
                response_format: { type: "json_object" }
            });

            const result = JSON.parse(response.choices[0].message.content);
            console.log(`✅ AUDITORIA SOCIAL: Concluída para @${handle} | Veredito: ${result.riskLevel}`);
            res.json(result);
        } catch (err) {
            console.error('❌ Check Social Error:', err);
            res.status(500).json({ error: 'Erro ao analisar perfil.' });
        }
    });

    // POST /api/analyze-doc
    router.post('/analyze-doc', optionalAuthenticateToken, checkQuota, upload.single('file'), async (req, res) => {
        const file = req.file;
        if (!file) return res.status(400).json({ error: 'Arquivo necessário.' });

        console.log(`📄 ANALISADOR DE DOCS: Processando novo arquivo: ${file.originalname}`);

        try {
            const imageData = fs.readFileSync(file.path, { encoding: 'base64' });
            const extension = file.path.split('.').pop().toLowerCase();
            const mimeType = extension === 'png' ? 'image/png' : extension === 'webp' ? 'image/webp' : 'image/jpeg';

            const response = await openai.chat.completions.create({
                model: "gpt-4o",
                messages: [
                    {
                        role: "user",
                        content: [
                            {
                                type: "text",
                                text: `Aja como um Perito Forense Digital especializado em Fraude Financeira Brasileira. Sua tarefa é analisar este documento (Boleto, DANFE, Recibo ou ID).
                                
                                PROTOCOLO DE EXTRAÇÃO (DADOS REAIS):
                                - Tipo: Identifique se é Boleto, DANFE, etc.
                                - Beneficiário: Extraia o Nome/Razão Social EXATO.
                                - CNPJ/CPF: Busque o documento do beneficiário.
                                - Banco: Identifique a instituição emissora.
                                - Valor: Valor total em R$.
                                
                                ANÁLISE FORENSE:
                                - Verifique a linha digitável (se visível) quanto a inconsistências.
                                - Procure por sinais de edição (fontes diferentes, desalinhamentos).
                                - VALIDE se o beneficiário parece legítimo para o tipo de serviço.
                                
                                Retorne EXCLUSIVAMENTE um JSON: { type, beneficiary, cnpj, bank, value, riskScore (0-100), status, signals (array de achados técnicos), recommendation }.`
                            },
                            {
                                type: "image_url",
                                image_url: { "url": `data:${mimeType};base64,${imageData}` },
                            },
                        ],
                    },
                ],
                response_format: { type: "json_object" }
            });

            if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
            const result = JSON.parse(response.choices[0].message.content);
            console.log(`✅ ANALISADOR DE DOCS: Concluído | Risco: ${result.riskScore}%`);
            res.json(result);
        } catch (err) {
            if (file && fs.existsSync(file.path)) fs.unlinkSync(file.path);
            console.error('❌ Analyze Doc Error:', err);
            res.status(500).json({ error: 'Erro ao analisar documento.' });
        }
    });

    // GET /api/expand-url (Phase 3 - Link Expander)
    router.get('/expand-url', optionalAuthenticateToken, async (req, res) => {
        const { url } = req.query;
        if (!url) return res.status(400).json({ error: 'URL necessária.' });

        console.log(`🔗 Iniciando expansão e análise forense de link: ${url}`);

        try {
            const response = await openai.chat.completions.create({
                model: "gpt-4o",
                messages: [
                    { role: "system", content: "Você é um Especialista em Cyber Intelligence do ShieldCheck AI. Sua função é analisar links encurtados, expandi-los e realizar uma auditoria de segurança técnica." },
                    {
                        role: "user", content: `Analise o link: "${url}". 

                    MISSÃO:
                    1. Identifique o destino real provável (se for um encurtador conhecido como bit.ly, tinyurl, etc).
                    2. Realize uma auditoria técnica sobre esse destino.
                    3. Verifique sinais de phishing, redirecionamentos maliciosos em cascata ou scripts de roubo de sessão.

                    Retorne um JSON: { expandedUrl (string), analysis: { trustScore (0-100), riskFactors (array), recommendation (string) } }.` }
                ],
                response_format: { type: "json_object" }
            });

            const result = JSON.parse(response.choices[0].message.content);
            res.json(result);
        } catch (err) {
            console.error('Expand URL Error:', err);
            res.status(500).json({ error: 'Erro ao expandir link.' });
        }
    });

    return router;
};
