const express = require('express');
const router = express.Router();

module.exports = function (supabase, stripe, STRIPE_WEBHOOK_SECRET) {

    // POST /api/webhook/stripe
    router.post('/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
        const signature = req.headers['stripe-signature'];
        let event;

        try {
            if (STRIPE_WEBHOOK_SECRET) {
                event = stripe.webhooks.constructEvent(req.body, signature, STRIPE_WEBHOOK_SECRET);
            } else {
                event = JSON.parse(req.body.toString());
            }
        } catch (err) {
            console.error(`⚠️ Webhook signature verification failed.`, err.message);
            return res.status(400).send(`Webhook Error: ${err.message}`);
        }

        if (event.type === 'checkout.session.completed') {
            const session = event.data.object;
            const userId = session.client_reference_id;
            const waNumber = session.metadata?.waNumber;

            console.log(`💰 Checkout concluído! Usuário ${userId}. WA: ${waNumber || 'N/A'}`);

            if (userId && waNumber) {
                console.log(`📱 Vinculando WhatsApp ${waNumber} ao usuário ${userId}`);
                await supabase.from('users').update({ whatsapp_number: waNumber }).eq('id', userId);
            }
        }

        if (event.type === 'customer.subscription.created' || event.type === 'customer.subscription.updated') {
            const subscription = event.data.object;
            const userId = subscription.metadata.userId;
            const waNumber = subscription.metadata.waNumber;

            if (userId) {
                const status = subscription.status;
                const priceId = subscription.items.data[0].price.id;

                let planName = 'FREE';
                if (priceId === process.env.STRIPE_PRICE_SOLO_BOT_MONTHLY || priceId === process.env.STRIPE_PRICE_SOLO_BOT_YEARLY) planName = 'SOLO_BOT';
                else if (priceId === process.env.STRIPE_PRICE_PREMIUM_MONTHLY || priceId === process.env.STRIPE_PRICE_PREMIUM_YEARLY) planName = 'PREMIUM';
                else if (priceId === process.env.STRIPE_PRICE_STARTER_MONTHLY || priceId === process.env.STRIPE_PRICE_STARTER_YEARLY) planName = 'BUSINESS';
                else if (priceId === process.env.STRIPE_PRICE_PRO_MONTHLY || priceId === process.env.STRIPE_PRICE_PRO_YEARLY) planName = 'PRO';

                const updateData = { plan: planName };
                if (waNumber) updateData.whatsapp_number = waNumber;

                if (status === 'active' || status === 'trialing') {
                    await supabase.from('users').update(updateData).eq('id', userId);
                } else if (status === 'past_due' || status === 'unpaid' || status === 'canceled') {
                    await supabase.from('users').update({ plan: 'FREE' }).eq('id', userId);
                }
            }
        }

        if (event.type === 'customer.subscription.deleted') {
            const subscription = event.data.object;
            const userId = subscription.metadata.userId;
            if (userId) {
                await supabase.from('users').update({ plan: 'FREE' }).eq('id', userId);
            }
        }

        res.json({ received: true });
    });

    return router;
};
