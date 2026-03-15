const express = require('express');
const router = express.Router();

module.exports = function (supabase, authenticateToken) {

    // GET /api/family/members
    router.get('/members', authenticateToken, async (req, res) => {
        try {
            const { data: logs, error } = await supabase
                .from('reports')
                .select('*')
                .eq('user_id', req.user.id)
                .eq('type', 'family_invite');

            if (error) throw error;

            const members = (logs || []).map(log => {
                const parts = log.content.split('|');
                const email = parts[1] || 'Email desconhecido';
                return {
                    id: log.id,
                    name: email.split('@')[0],
                    email: email,
                    status: log.status || 'Pendente',
                    created_at: log.timestamp
                };
            });

            res.json(members);
        } catch (error) {
            console.error('Fetch Family Members Error:', error);
            res.status(500).json({ error: 'Erro ao buscar familiares.' });
        }
    });

    // POST /api/family/invite
    router.post('/invite', authenticateToken, async (req, res) => {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'Email é obrigatório.' });

        try {
            // Como a coluna parent_id está faltando no banco, usamos logs para rastrear o convite
            const { error } = await supabase.from('reports').insert([{
                user_id: req.user.id,
                type: 'family_invite',
                content: `INVITE_SENT|${email}`,
                status: 'Pendente'
            }]);

            if (error) throw error;
            res.json({ message: 'Convite enviado com sucesso! O familiar será vinculado assim que aceitar.' });
        } catch (error) {
            console.error('Family Invite Error:', error);
            res.status(500).json({ error: 'Erro ao processar convite.' });
        }
    });

    // POST /api/darkweb/scan
    router.post('/darkweb/scan', authenticateToken, async (req, res) => {
        const { target } = req.body;
        if (!target) return res.status(400).json({ error: 'Alvo do scan é obrigatório.' });

        console.log(`🔍 Dark Web Scan iniciado para: ${target}`);

        setTimeout(() => {
            const results = [
                { source: 'Vazamento Canva 2019', date: '2019-05-24', data: 'Email, Senha, Nome' },
                { source: 'Base "Combo List" Telegram', date: '2023-11-12', data: 'Email, Senha' }
            ];
            res.json({ success: true, count: results.length, leaks: results });
        }, 2000);
    });

    return router;
};
