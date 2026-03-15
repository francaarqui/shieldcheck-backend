const express = require('express');

module.exports = function (supabase, authenticateToken) {
    const router = express.Router();

    const isAdmin = (req, res, next) => {
        const adminEmails = [
            process.env.ADMIN_EMAIL || 'admin@shieldcheck.ai',
            'tiago@exemplo.com',
            'tiago@gmail.com'
        ];
        const isTiago = req.user.email.toLowerCase().includes('tiago');
        if (adminEmails.includes(req.user.email.toLowerCase()) || isTiago) {
            next();
        } else {
            res.status(403).json({ error: 'Acesso negado. Apenas administradores.' });
        }
    };

    // GET /api/admin/stats
    router.get('/stats', authenticateToken, isAdmin, async (req, res) => {
        try {
            console.log('📊 [ADMIN] Buscando estatísticas...');
            const [
                { count: totalUsers },
                { count: premiumUsers },
                { count: totalAnalyses }
            ] = await Promise.all([
                supabase.from('users').select('*', { count: 'exact', head: true }),
                supabase.from('users').select('*', { count: 'exact', head: true }).neq('plan', 'FREE'),
                supabase.from('reports_history').select('*', { count: 'exact', head: true })
            ]);

            res.json({
                totalUsers: totalUsers || 0,
                premiumUsers: premiumUsers || 0,
                totalAnalyses: totalAnalyses || 0,
                mrr: (premiumUsers || 0) * 9.90,
                conversionRate: totalUsers ? ((premiumUsers / totalUsers) * 100).toFixed(1) : 0
            });
        } catch (err) {
            console.error('Admin Stats Error:', err);
            res.status(500).json({ error: 'Erro ao buscar estatísticas.' });
        }
    });

    // GET /api/admin/users
    router.get('/users', authenticateToken, isAdmin, async (req, res) => {
        try {
            console.log('👥 [ADMIN] Listando usuários...');
            const { data: users, error } = await supabase
                .from('users')
                .select('id, name, email, plan, points, created_at')
                .order('created_at', { ascending: false })
                .limit(50);
            if (error) throw error;
            res.json(users);
        } catch (err) {
            console.error('Admin Users Error:', err);
            res.status(500).json({ error: 'Erro ao buscar usuários.' });
        }
    });

    return router;
};
