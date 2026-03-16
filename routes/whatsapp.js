const express = require('express');
const router = express.Router();
const fs = require('fs');
const { analyzeContent, transcribeMedia, analyzeImage } = require('../utils/analyzer');

module.exports = function (supabase, openai, downloadWhatsAppMedia, sendWhatsAppReply) {

    // Helper to find user and check quota
    const getWhatsAppUser = async (phoneNumber) => {
        // Twilio sends "whatsapp:+55..."
        const cleanNumber = phoneNumber.replace('whatsapp:', '');

        const { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('whatsapp_number', cleanNumber)
            .single();

        return user;
    };

    const checkWhatsAppQuota = async (user) => {
        if (!user) return true; // Anonymous is handled separately or blocked
        if (user.plan !== 'FREE') return true;

        const today = new Date().toISOString().split('T')[0];
        const { count } = await supabase
            .from('reports')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', user.id)
            .gte('timestamp', today);

        return count < 3;
    };

    // POST /api/whatsapp/webhook
    router.post('/webhook', async (req, res) => {
        const From = req.body.From || req.body.from;
        const Body = req.body.Body || req.body.text || req.body.body;
        const NumMedia = parseInt(req.body.NumMedia || req.body.numMedia || (req.body.media ? 1 : 0));
        const MediaUrl0 = req.body.MediaUrl0 || req.body.mediaUrl0 || req.body.media;
        const MediaContentType0 = req.body.MediaContentType0 || req.body.mediaContentType0 || req.body.contentType;

        console.log(`📱 [WHATSAPP IN] De: ${From} | Mensagem: ${Body || '[Mídia]'}`);

        try {
            // 1. Find User
            const user = await getWhatsAppUser(From);

            // 2. Check Quota
            const hasQuota = await checkWhatsAppQuota(user);
            const cleanNumber = From.replace('whatsapp:', '');
            const salesLink = `https://shieldcheckai.com/plans?auto=solo_bot&wa=${cleanNumber}`;

            if (!hasQuota) {
                return await sendWhatsAppReply(From, `⚠️ Você atingiu seu limite diário de 3 análises gratuitas.\n\n🚀 *QUER USO ILIMITADO?*\nAssine o plano Solo Bot e proteja-se sem limites:\n${salesLink}`);
            }

            let analysisResult = null;
            let transcribedText = null;
            let finalType = 'text';


            // 3. Process Content
            if (NumMedia > 0) {
                const mediaUrl = MediaUrl0;
                const contentType = MediaContentType0;

                // Limpar extensão (remover parâmetros como ;codecs=opus)
                let extension = 'bin';
                if (contentType.includes('audio/')) extension = 'ogg'; // WhatsApp padrão
                else if (contentType.includes('image/')) extension = contentType.split('/')[1].split(';')[0] || 'jpg';

                const filename = `wa_media_${Date.now()}.${extension}`;
                console.log(`📥 [WHATSAPP MEDIA] Tipo: ${contentType} | Baixando: ${filename}`);

                try {
                    const filePath = await downloadWhatsAppMedia(mediaUrl, filename);
                    console.log(`📁 [WHATSAPP MEDIA] Arquivo salvo em: ${filePath}`);

                    if (contentType.startsWith('audio/')) {
                        console.log("🎙️ Whisper: Transcrevendo áudio...");
                        transcribedText = await transcribeMedia(openai, filePath);
                        console.log(`📝 [WHATSAPP MEDIA] Transcrição: ${transcribedText}`);

                        analysisResult = await analyzeContent(openai, transcribedText, 'audio');
                        finalType = 'audio';
                    } else if (contentType.startsWith('image/')) {
                        console.log("📸 Vision: Analisando imagem...");
                        analysisResult = await analyzeImage(openai, filePath);
                        finalType = 'image';
                    }

                    if (fs.existsSync(filePath)) {
                        fs.unlinkSync(filePath);
                        console.log(`🗑️ [WHATSAPP MEDIA] Temp file removed.`);
                    }
                } catch (mediaErr) {
                    console.error("❌ [WHATSAPP MEDIA] Falha no processamento de mídia:", mediaErr);
                    await sendWhatsAppReply(From, "⚠️ Tive um problema ao baixar seu arquivo. Verifique se o arquivo não é muito grande ou tente enviar novamente.");
                }
            } else if (Body) {
                console.log("💬 ChatGPT: Analisando texto...");
                analysisResult = await analyzeContent(openai, Body, 'text');
                finalType = 'text';
            }

            // 4. Save History & Send Reply
            if (analysisResult) {
                // Save to DB
                await supabase.from('reports').insert([{
                    user_id: user ? user.id : null,
                    content: transcribedText || Body || "[Mídia]",
                    type: finalType,
                    risk_score: analysisResult.score
                }]);

                const botNumber = (req.body.To || "").replace('whatsapp:', '');
                const shareLink = 'https://shieldcheckai.com/indicar';

                // Format Reply
                const score = analysisResult.score;
                const scoreChar = score > 60 ? '🔴' : score > 30 ? '🟡' : '🟢';

                // Premium visual risk bar
                const totalBlocks = 8;
                const filledBlocks = Math.round((score / 100) * totalBlocks);
                const barEmoji = score > 60 ? '🟥' : score > 30 ? '🟨' : '🟩';
                const riskLine = Array(filledBlocks).fill(barEmoji).join('') + Array(totalBlocks - filledBlocks).fill('⬜').join('');

                let reply = `*🛡️ RELATÓRIO DE SEGURANÇA SHIELDCHECK*\n`;
                reply += `*================================*\n\n`;

                reply += `${scoreChar} *STATUS:* ${analysisResult.status.toUpperCase()}\n`;
                reply += `📊 *NÍVEL DE RISCO:* [ ${riskLine} ] *${score}%*\n\n`;

                if (transcribedText) {
                    reply += `📝 *CONTEÚDO ANALISADO:*\n_"${transcribedText}"_\n\n`;
                }

                reply += `🔍 *SINAIS DETECTADOS:*\n`;
                analysisResult.signals.forEach(sig => {
                    reply += `  • ${sig}\n`;
                });

                reply += `\n💡 *RECOMENDAÇÃO:* ${analysisResult.recommendation}\n\n`;

                reply += `*================================*\n`;

                // Add Upgrade link for FREE users
                if (!user || user.plan === 'FREE') {
                    reply += `🚀 *QUER USO ILIMITADO?*\n`;
                    reply += `Assine o plano Solo Bot e proteja-se sem limites:\n`;
                    reply += `${salesLink}\n\n`;
                    reply += `*================================*\n`;
                }

                reply += `📢 *CAMPANHA ANTI-GOLPE:* Proteja seus amigos e familiares! Encaminhe este alerta para seus grupos.\n\n`;
                reply += `👤 *INDIQUE O BOT:* Toque no link abaixo para compartilhar com um colega:\n`;
                reply += `${shareLink}\n\n`;
                reply += `🛡️ _Protegido por ShieldCheck AI_`;

                await sendWhatsAppReply(From, reply);
            } else if (!Body && NumMedia === 0) {
                const welcomeMsg = `👋 Olá! Eu sou o assistente do *ShieldCheck AI*.\n\n` +
                    `Me envie um texto, áudio ou print suspeito para que eu possa analisar para você.\n\n` +
                    `📌 *DICA DE SEGURANÇA:* Segure o dedo nesta conversa e selecione *FIXAR (Pin)* para que eu esteja sempre no topo e você me acesse rápido em caso de emergência! 🛡️`;
                await sendWhatsAppReply(From, welcomeMsg);
            }

        } catch (error) {
            console.error("WhatsApp Webhook Error:", error);
            await sendWhatsAppReply(From, "⚠️ Desculpe, tive um problema ao analisar sua mensagem. Tente novamente em instantes.");
        }

        res.type('text/xml').send('<Response></Response>');
    });

    return router;
};
