const express = require('express');
const router = express.Router();

module.exports = function (stripe, authenticateToken) {

    // POST /api/create-checkout-session
    router.post('/create-checkout-session', authenticateToken, async (req, res) => {
        const { planId, planName } = req.body;
        const userId = req.user.id;

        const priceMap = {
            'solo_bot_monthly': process.env.STRIPE_PRICE_SOLO_BOT_MONTHLY,
            'solo_bot_yearly': process.env.STRIPE_PRICE_SOLO_BOT_YEARLY,
            'premium_monthly': process.env.STRIPE_PRICE_PREMIUM_MONTHLY,
            'premium_yearly': process.env.STRIPE_PRICE_PREMIUM_YEARLY,
            'business_monthly': process.env.STRIPE_PRICE_STARTER_MONTHLY,
            'business_yearly': process.env.STRIPE_PRICE_STARTER_YEARLY,
            'pro_monthly': process.env.STRIPE_PRICE_PRO_MONTHLY,
            'pro_yearly': process.env.STRIPE_PRICE_PRO_YEARLY
        };

        const priceId = priceMap[planId];

        // Detectar a origem da requisição
        const origin = req.get('origin');

        // Determinar o baseUrl de retorno de forma ultra-segura
        let baseUrl = process.env.FRONTEND_URL;

        if (!baseUrl) {
            // Se houver um origin válido (vinda do browser), usamos ele como base
            if (origin) {
                baseUrl = origin;
            } else if (process.env.NODE_ENV === 'production') {
                baseUrl = 'https://www.shieldcheckai.com';
            } else {
                baseUrl = 'http://localhost:5173';
            }
        }

        // Remover barra final se existir para evitar URLs duplas //
        if (baseUrl.endsWith('/')) baseUrl = baseUrl.slice(0, -1);

        console.log(`[PAYMENT DEBUG] Requested planId: ${planId}`);
        console.log(`[PAYMENT DEBUG] Environment: ${process.env.NODE_ENV}`);
        console.log(`[PAYMENT DEBUG] Origin detected: ${origin}`);
        console.log(`[PAYMENT DEBUG] Final baseUrl for return: ${baseUrl}`);

        if (!priceId) {
            console.error(`❌ [PAYMENT ERROR]: Price ID not found for planId: ${planId}`);
            return res.status(400).json({ error: `Plano inválido ou ID de preço não configurado (${planId}).` });
        }

        try {
            console.log(`[PAYMENT DEBUG] Creating session for priceId: ${priceId}...`);
            const trialDays = planId.startsWith('solo_bot') ? 7 : 0;

            const sessionOptions = {
                mode: 'subscription',
                payment_method_types: ['card'],
                line_items: [{ price: priceId, quantity: 1 }],
                client_reference_id: userId,
                metadata: { userId },
                success_url: `${baseUrl}/success?session_id={CHECKOUT_SESSION_ID}&plan=${planName || 'PREMIUM'}`,
                cancel_url: `${baseUrl}/plans`, // Voltando para planos se cancelar
            };

            if (trialDays > 0) {
                sessionOptions.subscription_data = {
                    trial_period_days: trialDays,
                    metadata: { userId }
                };
            } else {
                sessionOptions.subscription_data = {
                    metadata: { userId }
                };
            }

            const session = await stripe.checkout.sessions.create(sessionOptions);
            console.log(`✅ [PAYMENT SUCCESS] Session created: ${session.id} | Return to: ${baseUrl}`);
            res.json({ url: session.url, debug_baseUrl: baseUrl });
        } catch (error) {
            console.error('❌ [STRIPE ERROR]:', error.message);
            res.status(500).json({
                error: 'Erro ao criar sessão de pagamento.',
                details: error.message
            });
        }
    });

    return router;
};
