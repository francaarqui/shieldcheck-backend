const express = require('express');
const router = express.Router();

module.exports = (supabase, authenticateToken) => {

    // Get monitored domains and detected threats
    router.get('/brand-protection/status', authenticateToken, async (req, res) => {
        try {
            const status = {
                monitoredDomains: [
                    { id: 1, domain: 'shieldcheck.ai', status: 'Seguro', lastScan: new Date().toISOString() }
                ],
                detectedThreats: [
                    { id: 101, type: 'Typosquatting', source: 'shieidcheck.ai', risk: 'Crítico', status: 'Ativo' }
                ],
                stats: { takedownsResolved: 14, activeThreats: 1, totalScans: 1240 }
            };
            res.json(status);
        } catch (error) {
            res.status(500).json({ error: 'Erro ao buscar status de proteção.' });
        }
    });

    // Generate Takedown Notice
    router.post('/brand-protection/takedown/:id', authenticateToken, async (req, res) => {
        try {
            res.json({ message: 'Aviso de Takedown gerado com sucesso.', notice: 'Conteúdo simulado' });
        } catch (error) {
            res.status(500).json({ error: 'Erro ao gerar aviso.' });
        }
    });

    return router;
};
