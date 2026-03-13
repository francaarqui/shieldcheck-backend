const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const Stripe = require('stripe');
const OpenAI = require('openai');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const twilio = require('twilio');

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-shieldcheck-key-2026';
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const stripe = Stripe(STRIPE_SECRET_KEY);

const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY,
});

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false })); // Importante para o Twilio!

// --- Webhook do WhatsApp (Twilio) ---
app.post('/api/whatsapp/webhook', async (req, res) => {
    const message = req.body.Body;
    const from = req.body.From;

    console.log(`Mensagem de WhatsApp de ${from}: ${message}`);
    
    // ... Lógica de análise de IA ...
    // Utilize o código completo que geramos hoje!
    
    res.send('<Response></Response>');
});

// --- Leads B2B ---
app.post('/api/leads/b2b', async (req, res) => {
    const { name, company, email, phone, business_type, message } = req.body;
    const { error } = await supabase.from('leads').insert([{
        name, company, email, phone, business_type, message
    }]);
    res.json({ success: !error });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Rodando na porta ${PORT}`));
// 2. FRONTEND - Empresas.jsx (Crie este arquivo se não existir)
// No repositório shieldcheck-ai (Frontend) em src/pages/Empresas.jsx
import React, { useState } from 'react';
import { Link } from 'react-router-dom';

export default function Empresas() {
    // ... Todo o código da página B2B com hero, planos e formulário ...
    // (Aquele que mostrei o print agora pouco)
    return (
        <div className="w-full">
            {/* Seção Hero e Planos B2B */}
        </div>
    );
}
// 3. FRONTEND - Plans.jsx (Atualização do ID do Stripe)
// Local: src/pages/Plans.jsx
<stripe-pricing-table
    pricing-table-id="prctbl_1TAJlQ98y67vPsr0U43gHQTy"
    publishable-key="pk_test_51T47Vc98y67vPsr0ZkNSafsEaQLLhQTskQxAs8XERImnxF5fcgEGiiGaXFK6PMVGtN2fS9D7XdwusK5eKSHDanUu00aEm1ECCw"
    client-reference-id={user?.id}
>
</stripe-pricing-table>
