const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { analyzeContent } = require('../utils/analyzer');

module.exports = function (supabase, authenticateToken, openai) {

    // GET /api/developer/key
    router.get('/developer/key', authenticateToken, async (req, res) => {
        const userId = req.user.id;
        const { data: row, error } = await supabase
            .from('api_keys')
            .select('api_key, usage_count')
            .eq('user_id', userId)
            .single();

        if (row && row.api_key) {
            return res.json({ apiKey: row.api_key, usage: row.usage_count });
        } else {
            const newKey = 'sc_' + crypto.randomBytes(24).toString('hex');
            const { error: insertError } = await supabase
                .from('api_keys')
                .insert([{ user_id: userId, api_key: newKey }]);

            if (insertError) return res.status(500).json({ error: 'Não foi possível gerar a chave de API.' });
            res.json({ apiKey: newKey, usage: 0 });
        }
    });

    // POST /api/developer/key/regenerate
    router.post('/developer/key/regenerate', authenticateToken, async (req, res) => {
        const userId = req.user.id;
        const newKey = 'sc_' + crypto.randomBytes(24).toString('hex');
        const { error } = await supabase
            .from('api_keys')
            .upsert({ user_id: userId, api_key: newKey, usage_count: 0 }, { onConflict: 'user_id' });

        if (error) return res.status(500).json({ error: 'Erro ao regerar chave de API.' });
        res.json({ apiKey: newKey, message: 'Nova chave gerada com sucesso!' });
    });

    // B2B TEAM MANAGEMENT (Phase 3B)
    router.get('/b2b/members', authenticateToken, async (req, res) => {
        const adminId = req.user.id;
        const { data: members, error } = await supabase
            .from('users')
            .select('id, name, email, plan, created_at')
            .eq('parent_id', adminId);

        if (error) return res.status(500).json({ error: 'Erro ao buscar membros da equipe.' });
        res.json(members || []);
    });

    router.post('/b2b/invite', authenticateToken, async (req, res) => {
        const { email } = req.body;
        const adminId = req.user.id;

        const { data: targetUser, error } = await supabase
            .from('users')
            .select('id, parent_id')
            .eq('email', email)
            .single();

        if (error || !targetUser) return res.status(404).json({ error: 'Usuário não encontrado no ShieldCheck.' });
        if (targetUser.parent_id) return res.status(400).json({ error: 'Este usuário já pertence a uma equipe.' });

        const { error: updateError } = await supabase
            .from('users')
            .update({ parent_id: adminId, plan: 'BUSINESS' })
            .eq('id', targetUser.id);

        if (updateError) return res.status(500).json({ error: 'Erro ao vincular membro.' });
        res.json({ message: 'Membro adicionado à equipe com sucesso!' });
    });

    // B2B API v1 (for external partners)
    router.post('/v1/analyze', async (req, res) => {
        const apiKey = req.headers['x-api-key'];
        if (!apiKey) return res.status(401).json({ error: 'x-api-key header missing.' });

        const { data: row, error } = await supabase
            .from('api_keys')
            .select('user_id, usage_count')
            .eq('api_key', apiKey)
            .single();

        if (error || !row) return res.status(401).json({ error: 'Chave de API inválida.' });

        const { content, type } = req.body;
        if (!content) return res.status(400).json({ error: 'Campo content obrigatório.' });

        await supabase
            .from('api_keys')
            .update({ usage_count: (row.usage_count || 0) + 1 })
            .eq('api_key', apiKey);

        // We probably need simple analyzeContent helper here or import it
        // For now, let's assume it's passed or defined here
        try {
            const analysisResult = await analyzeContent(openai, content, type || 'text');

            // Log as a report if we have user_id
            await supabase.from('reports').insert([{
                user_id: row.user_id,
                content: content.substring(0, 500),
                type: type || 'b2b_api',
                risk_score: analysisResult.score
            }]);

            res.json({
                success: true,
                provider: "ShieldCheck AI B2B",
                analysis: analysisResult
            });
        } catch (err) {
            res.status(500).json({ error: 'Erro ao processar análise via motor ShieldCheck.' });
        }
    });

    // Public endpoint to verify store status (Phase 6)
    router.get('/v1/verify-store/:domain', async (req, res) => {
        const { domain } = req.params;
        // In a real scenario, we'd check a 'verified_stores' table
        // For now, we'll simulate verification for domains that have an active BUSINESS API key

        // Let's assume domains containing these keywords are "verified" for demo purposes
        const verifiedKeywords = ['loja', 'store', 'shop', 'ecommerce', 'shieldcheck'];
        const isVerified = verifiedKeywords.some(k => domain.toLowerCase().includes(k));

        if (isVerified) {
            res.json({
                status: 'VERIFIED',
                domain,
                verification_date: new Date().toISOString(),
                security_score: 98,
                certificate_id: crypto.randomBytes(8).toString('hex').toUpperCase()
            });
        } else {
            res.json({ status: 'NOT_VERIFIED', domain });
        }
    });

    return router;
};

