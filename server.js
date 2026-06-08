require('dotenv').config();
const { PrismaClient } = require('@prisma/client');
const express = require('express');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

BigInt.prototype.toJSON = function() { return this.toString(); };

const app = express();
const prisma = new PrismaClient();

app.use(express.json());
app.use(helmet());

const ACC_STATUS = { REGISTERED: 0, PENDING: 1, ACTIVE: 2, BLOCKED: 3 };

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: 'Слишком много попыток входа' }
});

app.use((req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || authHeader !== `Bearer ${process.env.API_TOKEN}`) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
    const { identifier, password } = req.body;

    if (!identifier || !password) {
        return res.status(400).json({ error: 'Не указан логин или пароль' });
    }

    try {
        const account = await prisma.accounts.findFirst({
            where: { OR: [{ email: identifier }, { login: identifier }] }
        });

        if (!account) {
            return res.status(401).json({ error: 'Неверный логин или пароль' });
        }

        const isMatch = await bcrypt.compare(password, account.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Неверный логин или пароль' });
        }

        if (account.accstatus === ACC_STATUS.BLOCKED) {
            return res.status(403).json({ error: account.statusReason || 'Аккаунт заблокирован' });
        }

        if (account.accstatus !== ACC_STATUS.ACTIVE) {
            return res.status(403).json({ error: 'Аккаунт ожидает подтверждения' });
        }

        await prisma.accounts.update({
            where: { id: account.id },
            data: { lastLogin: new Date() }
        });

        res.json({
            status: 'success',
            account: {
                id: account.id,
                login: account.login,
                adminlevel: account.adminlevel
            }
        });
    } catch (err) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/accounts/count', async (req, res) => {
    try {
        const count = await prisma.accounts.count();
        res.json({ count });
    } catch (err) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/characters/:accountId', async (req, res) => {
    let accountId;
    try {
        accountId = BigInt(req.params.accountId);
    } catch (e) {
        return res.status(400).json({ error: 'Некорректный ID аккаунта' });
    }

    try {
        const account = await prisma.accounts.findUnique({ where: { id: accountId } });
        if (!account) {
            return res.status(404).json({ error: 'Аккаунт не найден' });
        }

        const characters = await prisma.characters.findMany({
            where: { accountId: accountId, deleted: false },
            orderBy: { lastPlayed: 'desc' }
        });

        res.json({ status: 'success', characters });
    } catch (err) {
        console.error('[API ERROR] characters:', err);
        res.status(500).json({ error: 'Ошибка сервера при получении персонажей' });
    }
});

app.post('/api/characters/:accountId', async (req, res) => {
    let accountId;
    try {
        accountId = BigInt(req.params.accountId);
    } catch (e) {
        return res.status(400).json({ error: 'Некорректный ID аккаунта' });
    }

    const { firstname, lastname, dateofbirth, nationality, height, weight } = req.body;

    if (!firstname || !lastname || !dateofbirth || !nationality) {
        return res.status(400).json({ error: 'Заполнены не все поля' });
    }

    const clean = (s) => String(s).trim().slice(0, 32);
    const num = (v, def, lo, hi) => {
        const n = parseInt(v, 10);
        if (isNaN(n)) return def;
        return Math.min(hi, Math.max(lo, n));
    };

    try {
        const account = await prisma.accounts.findUnique({ where: { id: accountId } });
        if (!account) {
            return res.status(404).json({ error: 'Аккаунт не найден' });
        }

        const count = await prisma.characters.count({
            where: { accountId: accountId, deleted: false }
        });

        if (count >= 3) {
            return res.status(409).json({ error: 'Достигнут лимит персонажей (3)' });
        }

        const character = await prisma.characters.create({
            data: {
                accountId: accountId,
                firstname: clean(firstname),
                lastname: clean(lastname),
                dateofbirth: clean(dateofbirth),
                nationality: clean(nationality),
                height: num(height, 180, 140, 220),
                weight: num(weight, 80, 40, 200)
            }
        });

        res.json({ status: 'success', character });
    } catch (err) {
        console.error('[API ERROR] create character:', err);
        res.status(500).json({ error: 'Ошибка сервера при создании персонажа' });
    }
});

const RETRYABLE_PRISMA_CODES = ['P1001', 'P1002', 'P1003', 'P1008', 'P1017', 'P2024', 'P2034'];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function withRetry(fn, attempts = 3) {
    let lastErr = null;
    for (let i = 0; i < attempts; i++) {
        try {
            return await fn();
        } catch (err) {
            lastErr = err;
            const retryable = err && err.code && RETRYABLE_PRISMA_CODES.includes(err.code);
            if (!retryable || i === attempts - 1) throw err;
            await sleep(200 * Math.pow(2, i));
        }
    }
    throw lastErr;
}

app.put('/api/characters/appearance/:characterId', async (req, res) => {
    try {
        const characterId = parseInt(req.params.characterId, 10);
        if (isNaN(characterId)) {
            return res.status(400).json({ error: 'Некорректный ID персонажа' });
        }

        const { appearance } = req.body;
        if (!appearance || typeof appearance !== 'object' || Array.isArray(appearance)) {
            return res.status(400).json({ error: 'Некорректные данные внешности' });
        }
        if (!appearance.model || !appearance.components) {
            return res.status(400).json({ error: 'Неполные данные внешности' });
        }

        const character = await withRetry(() =>
            prisma.characters.update({
                where: { id: characterId },
                data: { appearance: appearance }
            })
        );

        res.json({ status: 'success', character });
    } catch (err) {
        console.error('[API ERROR] update appearance:', err.code || '', err.message);
        res.status(500).json({ error: 'Ошибка сервера при сохранении внешности' });
    }
});

app.get('/api/character/:characterId', async (req, res) => {
    let characterId;
    try {
        characterId = BigInt(req.params.characterId);
    } catch (e) {
        return res.status(400).json({ error: 'Некорректный ID персонажа' });
    }

    try {
        const character = await prisma.characters.findUnique({ where: { id: characterId } });
        if (!character || character.deleted) {
            return res.status(404).json({ error: 'Персонаж не найден' });
        }
        res.json({ status: 'success', character });
    } catch (err) {
        console.error('[API ERROR] get character:', err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.put('/api/characters/state/:characterId', async (req, res) => {
    let characterId;
    try {
        characterId = BigInt(req.params.characterId);
    } catch (e) {
        return res.status(400).json({ error: 'Некорректный ID персонажа' });
    }

    const clampInt = (v, lo, hi) => Math.min(hi, Math.max(lo, parseInt(v, 10) || 0));
    const data = {};

    if (req.body.hunger !== undefined) data.hunger = clampInt(req.body.hunger, 0, 100);
    if (req.body.thirst !== undefined) data.thirst = clampInt(req.body.thirst, 0, 100);
    if (req.body.jobGrade !== undefined) data.jobGrade = clampInt(req.body.jobGrade, 0, 100);
    if (req.body.cash !== undefined) data.cash = parseInt(req.body.cash, 10) || 0;
    if (req.body.bank !== undefined) data.bank = parseInt(req.body.bank, 10) || 0;
    if (req.body.job !== undefined) data.job = String(req.body.job).slice(0, 32);

    if (Object.keys(data).length === 0) {
        return res.status(400).json({ error: 'Нет данных для обновления' });
    }

    try {
        const character = await withRetry(() =>
            prisma.characters.update({ where: { id: characterId }, data })
        );
        res.json({ status: 'success', character });
    } catch (err) {
        console.error('[API ERROR] update state:', err.code || '', err.message);
        res.status(500).json({ error: 'Ошибка сервера при обновлении состояния персонажа' });
    }
});

const port = process.env.API_PORT || 3000;

prisma.$connect()
    .then(() => {
        console.log('[API] PostgreSQL connection established!');
        app.listen(port, '127.0.0.1', () => console.log(`[API] Running on 127.0.0.1:${port}`));
    })
    .catch((err) => {
        console.error('[API] Prisma error:', err.message);
        process.exit(1);
    });
