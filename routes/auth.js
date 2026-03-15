const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { authenticator } = require('otplib');
const qrcode = require('qrcode');

module.exports = function (supabase, JWT_SECRET, authenticateToken) {

    // POST /api/register
    router.post('/register', async (req, res) => {
        const { name, email, password, referralCode } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Preencha todos os campos.' });
        }

        if (referralCode) {
            console.log(`[REFERRAL] Registration attempt with code: ${referralCode} for email: ${email}`);
        }

        try {
            const hashedPassword = await bcrypt.hash(password, 10);

            // 1. Criar o novo usuário
            const { data: newUser, error: createError } = await supabase
                .from('users')
                .insert([{ name, email, password_hash: hashedPassword }])
                .select()
                .single();

            if (createError) {
                if (createError.code === '23505') {
                    return res.status(400).json({ error: 'E-mail já cadastrado.' });
                }
                console.error("[REGISTER] DB Error:", createError);
                return res.status(500).json({ error: 'Erro ao criar usuário.' });
            }

            // 2. Processar indicação se houver referralCode
            if (referralCode) {
                try {
                    // Buscar o usuário que possui este código
                    const { data: allUsers, error: fetchAllError } = await supabase.from('users').select('id');

                    if (!fetchAllError && allUsers) {
                        const referrer = allUsers.find(u => {
                            const code = require('crypto').createHash('md5').update(String(u.id)).digest('hex').substring(0, 8).toUpperCase();
                            return code === referralCode;
                        });

                        if (referrer) {
                            console.log(`[AFFILIATE] Vínculo via Audit Log: ${referrer.id} indicou ${newUser.id}`);
                            // Usamos a tabela 'reports' como fallback persistente para auditoria de indicações
                            await supabase.from('reports').insert([
                                {
                                    user_id: referrer.id,
                                    content: `REFERRAL_LINKED|${newUser.id}|${newUser.name}|${referralCode}`,
                                    type: 'referral',
                                    risk_score: 0
                                }
                            ]);
                        } else {
                            console.log(`[AFFILIATE] Código ${referralCode} não associado a nenhum usuário.`);
                        }
                    }
                } catch (affilError) {
                    console.error("[AFFILIATE] Erro ao registrar vínculo no Audit Log:", affilError);
                }
            }

            const token = jwt.sign({ id: newUser.id, email, name: newUser.name, plan: 'FREE' }, JWT_SECRET, { expiresIn: '7d' });
            res.json({ token, user: { id: newUser.id, name: newUser.name, email, plan: 'FREE', points: newUser.points || 0 } });
        } catch (err) {
            console.error("[REGISTER] Critical Error:", err);
            res.status(500).json({ error: 'Erro no servidor.' });
        }
    });

    // POST /api/login
    router.post('/login', async (req, res) => {
        const { email, password, mfaToken } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Preencha todos os campos.' });

        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();

        if (error || !user) return res.status(400).json({ error: 'Usuário não encontrado.' });

        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return res.status(400).json({ error: 'Senha incorreta.' });

        // MFA CHECK
        if (user.mfa_enabled) {
            if (!mfaToken) {
                return res.json({ mfaRequired: true, message: 'Autenticação de dois fatores necessária.' });
            }
            const isValid = authenticator.check(mfaToken, user.mfa_secret);
            if (!isValid) {
                return res.status(400).json({ error: 'Código MFA inválido.' });
            }
        }

        const token = jwt.sign({ id: user.id, email: user.email, name: user.name, plan: user.plan }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, user: { id: user.id, name: user.name, email: user.email, plan: user.plan, points: user.points || 0 } });
    });

    // POST /api/mfa/setup (Phase 6)
    router.post('/mfa/setup', authenticateToken, async (req, res) => {
        const userId = req.user.id;
        const secret = authenticator.generateSecret();
        const otpauth = authenticator.keyuri(req.user.email, 'ShieldCheck AI', secret);

        try {
            const qrCodeUrl = await qrcode.toDataURL(otpauth);
            // Save secret temporarily (we ideally only enable MFA after verification)
            await supabase.from('users').update({ mfa_secret: secret }).eq('id', userId);
            res.json({ secret, qrCodeUrl });
        } catch (err) {
            res.status(500).json({ error: 'Erro ao gerar QR Code de segurança.' });
        }
    });

    // POST /api/mfa/verify (Phase 6)
    router.post('/mfa/verify', authenticateToken, async (req, res) => {
        const { token } = req.body;
        const userId = req.user.id;

        const { data: user } = await supabase.from('users').select('mfa_secret').eq('id', userId).single();
        if (!user || !user.mfa_secret) return res.status(400).json({ error: 'Segredo MFA não encontrado.' });

        const isValid = authenticator.check(token, user.mfa_secret);
        if (isValid) {
            await supabase.from('users').update({ mfa_enabled: true }).eq('id', userId);
            res.json({ success: true, message: 'MFA ativado com sucesso!' });
        } else {
            res.status(400).json({ error: 'Código de verificação inválido.' });
        }
    });

    // GET /api/me
    router.get('/me', authenticateToken, async (req, res) => {
        const { data: user, error } = await supabase
            .from('users')
            .select('id, name, email, plan, points, created_at')
            .eq('id', req.user.id)
            .single();

        if (error || !user) return res.status(404).json({ error: 'Usuário não encontrado.' });
        res.json(user);
    });

    // PUT /api/users/settings
    router.put('/users/settings', authenticateToken, async (req, res) => {
        const { name, email, whatsapp_number, newPassword } = req.body;
        const updates = {};

        if (name) updates.name = name;
        if (email) updates.email = email;
        if (whatsapp_number !== undefined) updates.whatsapp_number = whatsapp_number;
        if (newPassword) updates.password_hash = await bcrypt.hash(newPassword, 10);

        if (Object.keys(updates).length === 0) return res.status(400).json({ error: 'Nenhum dado para atualizar.' });

        const { error } = await supabase
            .from('users')
            .update(updates)
            .eq('id', req.user.id);

        if (error) return res.status(500).json({ error: 'Erro ao atualizar configurações.' });
        res.json({ message: 'Configurações atualizadas com sucesso.' });
    });

    return router;
};
