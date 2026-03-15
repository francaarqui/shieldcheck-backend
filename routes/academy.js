const express = require('express');
const router = express.Router();

module.exports = (supabase, authenticateToken) => {

    // Get Audio Lab Scenarios
    router.get('/academy/audio-scenarios', async (req, res) => {
        try {
            const scenarios = [
                { id: 1, character: "Emergência", script: "Mensagem teste áudio.", isSynthetic: true }
            ];
            res.json(scenarios);
        } catch (error) {
            res.status(500).json({ error: 'Erro ao buscar cenários.' });
        }
    });

    return router;
};
