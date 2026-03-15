const express = require('express');
const router = express.Router();

module.exports = function (supabase, optionalAuthenticateToken) {

    // POST /api/extension/report
    router.post('/report', optionalAuthenticateToken, async (req, res) => {
        const { url, reason, category } = req.body;
        const userId = req.user ? req.user.id : null;

        if (!url) return res.status(400).json({ error: 'URL é obrigatória.' });

        console.log(`📢 Denúncia via Extensão: ${url} [${category}]`);

        const { data: pattern, error: selectError } = await supabase
            .from('scam_patterns')
            .select('id, report_count')
            .eq('pattern_text', url)
            .maybeSingle();

        if (pattern) {
            await supabase
                .from('scam_patterns')
                .update({ report_count: pattern.report_count + 1 })
                .eq('id', pattern.id);
        } else {
            await supabase
                .from('scam_patterns')
                .insert([{
                    pattern_text: url,
                    pattern_type: category || 'extension_report',
                    report_count: 1,
                    description: reason || 'Reportado via ShieldCheck Browser Guard'
                }]);
        }

        res.json({ success: true, message: 'Obrigado por sua denúncia! Nossa inteligência já está processando.' });
    });

    return router;
};
