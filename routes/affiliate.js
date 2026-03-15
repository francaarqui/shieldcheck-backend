const express = require('express');
const router = express.Router();
const crypto = require('crypto');

module.exports = function (supabase, authenticateToken) {

    // Rota Única e Estável para Afiliados
    router.get('/referrals', authenticateToken, async (req, res) => {
        try {
            const userId = req.user.id;

            // 1. Gerar o código de indicação do próprio usuário (MD5)
            const referralCode = crypto.createHash('md5').update(String(userId)).digest('hex').substring(0, 8).toUpperCase();

            // 2. Buscar logs de indicação na tabela 'reports' como audit log
            // Filtramos por user_id (quem indicou) e tipo 'referral'
            const { data: logs, error: logError } = await supabase
                .from('reports')
                .select('*')
                .eq('user_id', userId)
                .eq('type', 'referral');

            if (logError) {
                console.error("[AFFILIATE] Error fetching logs:", logError);
                throw logError;
            }

            // 3. Formatar a lista processando as strings do content
            const list = (logs || []).map(log => {
                const parts = log.content.split('|');
                const [action, ...details] = parts;

                // Formato esperado: REFERRAL_LINKED|id|name|code
                if (action === 'REFERRAL_LINKED' && details.length >= 2) {
                    return {
                        id: details[0],
                        name: details[1],
                        date: new Date(log.timestamp).toLocaleDateString('pt-BR'),
                        status: 'Ativo',
                        reward: 'R$ 10,00'
                    };
                }
                return null;
            }).filter(Boolean);

            // 4. Calcular estatísticas
            const totalEarnings = list.length * 10;
            const conversionRate = list.length > 0 ? '100%' : '0%';

            const stats = {
                referralCode: referralCode,
                totalReferrals: list.length,
                totalEarnings: totalEarnings,
                conversions: conversionRate
            };

            res.status(200).json({ stats, list });
        } catch (error) {
            console.error('Affiliate dynamic log fetch failure:', error);
            res.status(500).json({ error: 'Erro ao processar dados de afiliados via log.' });
        }
    });

    // Fallback para stats se o frontend ainda chamar separadamente
    router.get('/stats', authenticateToken, async (req, res) => {
        try {
            const userId = req.user.id;
            const { count } = await supabase
                .from('reports')
                .select('id', { count: 'exact', head: true })
                .eq('user_id', userId)
                .eq('type', 'referral');

            res.status(200).json({ totalReferrals: count || 0, totalEarnings: (count || 0) * 10, conversions: count > 0 ? "100%" : "0%" });
        } catch (e) {
            res.status(200).json({ totalReferrals: 0, totalEarnings: 0, conversions: "0%" });
        }
    });

    return router;
};
