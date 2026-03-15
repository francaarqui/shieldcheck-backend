const fs = require('fs');

const analyzeContent = async (openai, text, type = 'text') => {
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
        return {
            score: 50,
            status: 'ERRO NA ANÁLISE',
            signals: ['Não foi possível conectar à inteligência central.'],
            recommendation: 'Tente novamente em instantes ou verifique manualmente.'
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
            model: "gpt-4o-mini",
            messages: [
                {
                    role: "user",
                    content: [
                        {
                            type: "text",
                            text: `Analise este print de tela (pode ser uma conversa de WhatsApp, um site, ou um SMS).
                            Identifique sinais de:
                            1. GOLPES DE PIX (pressão para pagamento rápido).
                            2. PHISHING (links falsos que imitam bancos ou lojas).
                            3. ENGENHARIA SOCIAL (alguém pedindo dinheiro ou fingindo ser parente).
                            4. ERROS DE PORTUGUÊS ou design amador em sites "oficiais".

                            RETORNE UM JSON COM:
                            - score: (0-100) nível de risco.
                            - status: (BAIXO RISCO, CONTEÚDO SUSPEITO, ALTO RISCO).
                            - signals: array de sinais detectados.
                            - recommendation: recomendação clara de segurança.`
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
            signals: ['Não foi possível analisar a imagem.'],
            recommendation: 'Tente descrever o que está na imagem para uma análise textual.'
        };
    }
};

module.exports = {
    analyzeContent,
    transcribeMedia,
    analyzeImage
};
