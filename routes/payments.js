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
        const baseUrl = process.env.FRONTEND_URL || 'http://localhost:5173';

        console.log(`[PAYMENT DEBUG] Requested planId: ${planId}`);
        console.log(`[PAYMENT DEBUG] baseUrl: ${baseUrl}`);
        console.log(`[PAYMENT DEBUG] Resolved priceId: ${priceId}`);

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
                cancel_url: `${baseUrl}/dashboard`,
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
            console.log(`✅ [PAYMENT SUCCESS] Session created: ${session.id}`);
            res.json({ url: session.url });
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
