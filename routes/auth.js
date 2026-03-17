const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { authenticator } = require('otplib');
const qrcode = require('qrcode');
const { OAuth2Client } = require('google-auth-library');

module.exports = function (supabase, JWT_SECRET, authenticateToken, resend) {

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

    // POST /api/google-login
    router.post('/google-login', async (req, res) => {
        const { idToken } = req.body;
        if (!idToken) return res.status(400).json({ error: 'Token do Google ausente.' });

        try {
            const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
            const ticket = await client.verifyIdToken({
                idToken,
                audience: process.env.GOOGLE_CLIENT_ID,
            });
            const payload = ticket.getPayload();
            const { sub: googleId, email, name, picture } = payload;

            // 1. Verificar se o usuário já existe no banco
            let { data: user, error: fetchError } = await supabase
                .from('users')
                .select('*')
                .eq('email', email)
                .single();

            if (fetchError && fetchError.code !== 'PGRST116') {
                console.error("[GOOGLE LOGIN] Error fetching user:", fetchError);
            }

            if (!user) {
                // 2. Se não existir, criar novo usuário
                // Usamos uma senha aleatória complexa já que o login é via OAuth
                const randomPassword = require('crypto').randomBytes(16).toString('hex');
                const hashedPassword = await bcrypt.hash(randomPassword, 10);

                const { data: newUser, error: createError } = await supabase
                    .from('users')
                    .insert([{
                        name,
                        email,
                        password_hash: hashedPassword,
                        avatar_url: picture,
                        plan: 'FREE'
                    }])
                    .select()
                    .single();

                if (createError) {
                    console.error("[GOOGLE LOGIN] Error creating user:", createError);
                    return res.status(500).json({ error: 'Erro ao criar conta via Google.' });
                }
                user = newUser;
            }

            // 3. Gerar JWT do projeto
            const token = jwt.sign(
                { id: user.id, email: user.email, name: user.name, plan: user.plan },
                JWT_SECRET,
                { expiresIn: '7d' }
            );

            res.json({
                token,
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    plan: user.plan,
                    points: user.points || 0,
                    avatar_url: user.avatar_url
                }
            });

        } catch (err) {
            console.error("[GOOGLE LOGIN] Verification Error:", err);
            res.status(401).json({ error: 'Token do Google inválido ou expirado.' });
        }
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

    // POST /api/forgot-password
    router.post('/forgot-password', async (req, res) => {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'E-mail é obrigatório.' });

        try {
            const { data: user, error } = await supabase
                .from('users')
                .select('id, name')
                .eq('email', email)
                .single();

            if (error || !user) {
                // For security, don't reveal if user exists
                return res.json({ message: 'Se o e-mail estiver cadastrado, você receberá um link de recuperação em breve.' });
            }

            const resetToken = jwt.sign({ id: user.id, purpose: 'password_reset' }, JWT_SECRET, { expiresIn: '1h' });

            // Determinar a URL do site (produção ou local)
            const origin = req.get('origin') || 'https://www.shieldcheckai.com';
            const resetLink = `${origin}/reset-password/${resetToken}`;

            const { data, error: emailError } = await resend.emails.send({
                from: 'ShieldCheck AI <suporte@shieldcheckai.com>',
                to: [email],
                subject: 'Recuperação de Senha - ShieldCheck AI',
                html: `
                    <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; color: #334155;">
                        <h1 style="color: #4f46e5;">Recuperação de Senha</h1>
                        <p>Olá, <strong>${user.name}</strong>!</p>
                        <p>Recebemos uma solicitação para redefinir sua senha no ShieldCheck AI. Clique no botão abaixo para escolher uma nova senha:</p>
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="${resetLink}" style="background-color: #4f46e5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; font-weight: bold; display: inline-block;">Redefinir Minha Senha</a>
                        </div>
                        <p style="font-size: 14px; color: #64748b;">Este link é válido por 1 hora. Se você não solicitou essa mudança, pode ignorar este e-mail.</p>
                        <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 20px 0;">
                        <p style="font-size: 12px; color: #94a3b8; text-align: center;">&copy; 2026 ShieldCheck AI. Todos os direitos reservados.</p>
                    </div>
                `,
            });

            if (emailError) {
                console.error("[EMAIL ERROR]", emailError);
                return res.status(500).json({ error: 'Erro ao enviar e-mail de recuperação.' });
            }

            res.json({ message: 'Se o e-mail estiver cadastrado, você receberá um link de recuperação em breve.' });
        } catch (err) {
            console.error("[FORGOT PASSWORD] Critical Error:", err);
            res.status(500).json({ error: 'Erro interno no servidor.' });
        }
    });

    // POST /api/reset-password
    router.post('/reset-password', async (req, res) => {
        const { token, newPassword } = req.body;
        if (!token || !newPassword) return res.status(400).json({ error: 'Dados incompletos.' });

        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            if (decoded.purpose !== 'password_reset') {
                return res.status(400).json({ error: 'Token inválido para redefinição de senha.' });
            }

            const hashedPassword = await bcrypt.hash(newPassword, 10);

            const { error } = await supabase
                .from('users')
                .update({ password_hash: hashedPassword })
                .eq('id', decoded.id);

            if (error) {
                console.error("[RESET PASSWORD] DB Error:", error);
                return res.status(500).json({ error: 'Erro ao atualizar a senha.' });
            }

            res.json({ message: 'Sua senha foi redefinida com sucesso! Você já pode fazer login.' });
        } catch (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(400).json({ error: 'O link de recuperação expirou. Solicite um novo.' });
            }
            return res.status(400).json({ error: 'Link de recuperação inválido.' });
        }
    });

    return router;
};
