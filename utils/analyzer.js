const fs = require('fs');

const analyzeContent = async (openai, text, type = 'text') => {
    try {
        const prompt = `
        Aja como um Perito Sênior em Forense Digital e Threat Intelligence. Sua missão é dissecar o conteúdo fornecido em busca de vetores de ataque, padrões de engenharia social e sinais técnicos de fraude.
        
        Analise o seguinte conteúdo:
        "${text}"

        VETORES DE ANÁLISE OBRIGATÓRIOS:
        1. PERSUASÃO: Detecte gatilhos de urgência, autoridade forjada, medo (fomo) ou promessas irreais.
        2. SINTAXE E ORIGEM: Analise erros gramaticais propositais (evasão de filtros), inconsistência de links e remetentes suspeitos.
        3. ENTROPIA TÉCNICA: Avalie se a estrutura da mensagem segue padrões conhecidos de bots de spam ou campanhas de phishing em massa.

        Retorne um resultado em formato JSON estrito:
        - score: (0-100) Representando a probabilidade estatística de fraude/perigo.
        - status: Texto curto ('BAIXO RISCO', 'CONTEÚDO SUSPEITO', 'ALTO RISCO').
        - signals: Array de strings com achados forenses técnicos (ex: "Uso de domínios homográficos", "Gatilho de urgência cognitiva", "Anomalia em registro de SPF").
        - recommendation: Recomendação autoritária e clara baseada em protocolos de segurança.
        `;

        const response = await openai.chat.completions.create({
            model: "gpt-4o",
            messages: [
                { role: "system", content: "Você é um analista de elite em segurança cibernética. Responda exclusivamente em JSON." },
                { role: "user", content: prompt }
            ],
            response_format: { type: "json_object" }
        });

        return JSON.parse(response.choices[0].message.content);
    } catch (error) {
        console.error("OpenAI Error:", error);
        return {
            score: 50,
            status: 'ERRO NA ANÁLISE',
            signals: ['Falha na comunicação com o motor de inferência central.'],
            recommendation: 'Proceda com cautela extrema e verifique manualmente as fontes.'
        };
    }
};

const transcribeMedia = async (openai, filePath) => {
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

const analyzeImage = async (openai, filePath) => {
    try {
        // Encode image to base64
        const imageData = fs.readFileSync(filePath, { encoding: 'base64' });
        // Detect mimeType based on extension for safety
        const extension = filePath.split('.').pop().toLowerCase();
        const mimeType = extension === 'png' ? 'image/png' :
            extension === 'webp' ? 'image/webp' : 'image/jpeg';

        const response = await openai.chat.completions.create({
            model: "gpt-4o",
            messages: [
                {
                    role: "user",
                    content: [
                        {
                            type: "text",
                            text: `Aja como um Perito em Visão Computacional de Segurança. Analise este print de tela em busca de fraudes visuais.
                            
                            FOCO DA ANÁLISE:
                            - Falsificação de interface (UI Spoofing) de bancos ou lojas.
                            - Elementos de manipulação psicológica (contadores de tempo falsos, alertas de 'conta bloqueada').
                            - Inconsistências em logotipos, fontes e alinhamentos que indicam amadorismo ou clonagem.
                            
                            RETORNE UM JSON COM:
                            - score: (0-100) Probabilidade de fraude.
                            - status: (BAIXO RISCO, CONTEÚDO SUSPEITO, ALTO RISCO).
                            - signals: Array de evidências visuais forenses encontradas.
                            - recommendation: Instrução técnica de proteção.`
                        },
                        {
                            type: "image_url",
                            image_url: {
                                "url": `data:${mimeType};base64,${imageData}`,
                            },
                        },
                    ],
                },
            ],
            response_format: { type: "json_object" }
        });

        return JSON.parse(response.choices[0].message.content);
    } catch (error) {
        console.error("Vision Error:", error);
        return {
            score: 50,
            status: 'ERRO NA VISÃO',
            signals: ['Falha técnica no motor de inteligência visual.'],
            recommendation: 'Analise o texto da imagem manualmente na nossa busca textual.'
        };
    }
};

module.exports = {
    analyzeContent,
    transcribeMedia,
    analyzeImage
};
