const express = require('express');
const router = express.Router();

module.exports = (supabase, authenticateToken) => {

    // Get Enterprise aggregated analytics
    router.get('/analytics/enterprise', authenticateToken, async (req, res) => {
        try {
            const analytics = {
                overallScore: 78,
                riskTrend: 'Estável',
                departmentMetrics: [
                    { name: 'Financeiro', riskLevel: 'Baixo', awarenessScore: 92, activeUsers: 14 },
                    { name: 'Vendas', riskLevel: 'Alto', awarenessScore: 42, activeUsers: 19 }
                ],
                threatExposure: { phishing: 65, voiceCloning: 12, socialEngineering: 23 },
                simulatorPerformance: { averageCompletionTime: '4m 30s', passRate: '72%' }
            };
            res.json(analytics);
        } catch (error) {
            res.status(500).json({ error: 'Erro ao buscar métricas empresariais.' });
        }
    });

    return router;
};
