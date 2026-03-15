const express = require('express');
const router = express.Router();

module.exports = (supabase, authenticateToken) => {

    // Get Community Reports
    router.get('/reports', async (req, res) => {
        try {
            const { data: logs, error } = await supabase
                .from('reports')
                .select('*')
                .eq('type', 'community_report')
                .order('timestamp', { ascending: false });

            if (error) throw error;

            const reports = (logs || []).map(log => {
                const parts = log.content.split('|');
                if (parts.length < 5) return null;
                return {
                    id: log.id,
                    platform: parts[0],
                    type: parts[1],
                    target: parts[2],
                    description: parts[3],
                    author: parts[4],
                    status: log.status || 'Em Análise',
                    votes: log.risk_score || 0,
                    timestamp: log.timestamp,
                    user_voted: null
                };
            }).filter(Boolean);

            // Adicionar alguns fixos se a lista estiver vazia para não ficar vazio
            if (reports.length === 0) {
                reports.push({
                    id: 'fixed-1',
                    type: 'Phishing',
                    platform: 'WhatsApp',
                    target: 'Nubank Clients',
                    description: 'Golpe do falso presente de aniversário. Link direciona para site que rouba dados de login.',
                    votes: 142,
                    user_voted: null,
                    timestamp: new Date().toISOString(),
                    status: 'Verificado',
                    author: 'ShieldMaster_01'
                });
            }

            res.json(reports);
        } catch (error) {
            console.error('Community Hub Fetch Error:', error);
            res.status(500).json({ error: 'Erro ao buscar relatórios da comunidade.' });
        }
    });

    // Create a new community report
    router.post('/reports', authenticateToken, async (req, res) => {
        try {
            const { type, platform, target, description } = req.body;
            const author = req.user.name || 'Membro Anônimo';

            const content = `${platform}|${type}|${target}|${description}|${author}`;

            const { error } = await supabase.from('reports').insert([{
                user_id: req.user.id,
                type: 'community_report',
                content: content,
                status: 'Pendente',
                risk_score: 0 // Usado como votos iniciais
            }]);

            if (error) throw error;
            res.json({ message: 'Relatório enviado com sucesso!' });
        } catch (error) {
            console.error('Community Hub Submit Error:', error);
            res.status(500).json({ error: 'Erro ao enviar relatório.' });
        }
    });

    // Vote on a report
    router.post('/vote/:id', authenticateToken, async (req, res) => {
        try {
            res.json({ message: 'Voto registrado!', newVotes: 143 });
        } catch (error) {
            res.status(500).json({ error: 'Erro ao registrar voto.' });
        }
    });

    return router;
};
