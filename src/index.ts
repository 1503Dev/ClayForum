import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import multer from 'multer';
import { LDB } from './modules/LDB';
import { ThemeRender } from './modules/ThemeRender';
import { loadAccountConfig } from './modules/AccountConfig';
import { UserService, PublicUser } from './modules/UserService';
import { UserProfileService } from './modules/UserProfileService';
import { JwtService, loadJwtConfig } from './modules/JwtService';
import { CaptchaService, CaptchaChallenge } from './modules/CaptchaService';
import { loadUploadConfig } from './modules/UploadConfig';
import { ImageUploadService } from './modules/ImageUploadService';
import { SectionService } from './modules/SectionService';
import { TagService, normalizeTagName } from './modules/TagService';
import { PostService } from './modules/PostService';

const configPath = path.join(process.cwd(), 'config.json');
const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));

const app = express();
const port = config.port || 4555;
const themeName = config.theme || config.forum?.theme || 'default';
let themePath = path.join(__dirname, 'themes', themeName);
if (themeName !== 'default') {
    themePath = path.join(process.cwd(), 'themes', themeName);
}

const db = {
    user: LDB.open(config.database.user_path || 'database/user', {
        encryptionKey: config.database.encryption_key,
    }),
    user_profile: LDB.open(config.database.user_profile_path || 'database/user_profile'),
    data: LDB.open(config.database.data_path || 'database/data'),
};

const accountConfig = loadAccountConfig(config.account);
const jwtConfig = loadJwtConfig(config.jwt);
const uploadConfig = loadUploadConfig(config.upload);
const profileService = new UserProfileService(db.user_profile);
const userService = new UserService(db.user, profileService, accountConfig);
const jwtService = new JwtService(jwtConfig);
const captchaService = new CaptchaService(accountConfig);
const captchaStore = new Map<string, CaptchaChallenge>();
const sectionService = new SectionService(db.data);
const tagService = new TagService(db.data);
const postService = new PostService(db.data, sectionService, tagService);
const imageUploadService = new ImageUploadService(uploadConfig);
const imageUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: imageUploadService.maxBytes },
});

const requestRoot = config.request_root || '/';
const renderer = new ThemeRender(themePath, requestRoot);
const forumName = config.forum?.name || config.forum_name || 'ClayForum';

const router: { statics: express.Router; pages: express.Router; api: express.Router; uploads: express.Router } = {
    statics: express.Router(),
    pages: express.Router(),
    api: express.Router(),
    uploads: express.Router(),
};

app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: '1mb' }));

function setContentSecurityPolicy(res: express.Response): void {
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    );
}

function parseLimitOffset(query: express.Request['query']): { limit: number; offset: number } {
    let limit = Number(query.limit);
    let offset = Number(query.offset);
    if (!Number.isFinite(limit) || limit <= 0) limit = 20;
    if (!Number.isFinite(offset) || offset < 0) offset = 0;
    return { limit: Math.min(Math.floor(limit), 100), offset: Math.floor(offset) };
}

async function resolveCurrentUser(req: express.Request): Promise<PublicUser | null> {
    const token = jwtService.parseCookie(req.headers.cookie);
    const payload = jwtService.verify(token);
    if (!payload) return null;
    const user = await userService.getByUuid(payload.uuid);
    if (!user) return null;
    return userService.toPublicUser(user);
}

function renderPage(template: string, data: Record<string, unknown> = {}): string {
    return renderer.render(template, {
        forum_name: forumName,
        ...data,
    });
}

async function renderWithUser(
    req: express.Request,
    template: string,
    data: Record<string, unknown> = {},
): Promise<string> {
    const current_user = await resolveCurrentUser(req);
    return renderPage(template, { current_user, ...data });
}

type AuthedRequest = express.Request & { currentUser: PublicUser; userUuid: string };

async function resolveAuthedRequest(req: express.Request): Promise<{
    currentUser: PublicUser;
    userUuid: string;
} | null> {
    const token = jwtService.parseCookie(req.headers.cookie);
    const payload = jwtService.verify(token);
    if (!payload) return null;
    const user = await userService.getByUuid(payload.uuid);
    if (!user) return null;
    return {
        currentUser: await userService.toPublicUser(user),
        userUuid: payload.uuid,
    };
}

async function requireAuth(
    req: express.Request,
    res: express.Response,
    next: express.NextFunction,
): Promise<void> {
    const authed = await resolveAuthedRequest(req);
    if (!authed) {
        res.status(401).json({ ok: false, message: '请先登录' });
        return;
    }
    (req as AuthedRequest).currentUser = authed.currentUser;
    (req as AuthedRequest).userUuid = authed.userUuid;
    next();
}

async function requireAuthPage(
    req: express.Request,
    res: express.Response,
    next: express.NextFunction,
): Promise<void> {
    const authed = await resolveAuthedRequest(req);
    if (!authed) {
        res.redirect('/login');
        return;
    }
    (req as AuthedRequest).currentUser = authed.currentUser;
    (req as AuthedRequest).userUuid = authed.userUuid;
    next();
}

function parseCookieValue(cookieHeader: string | undefined, name: string): string | undefined {
    if (!cookieHeader) return undefined;
    for (const part of cookieHeader.split(';')) {
        const [key, ...rest] = part.trim().split('=');
        if (key === name) return rest.join('=') || undefined;
    }
    return undefined;
}

function verifyCaptcha(req: express.Request, input: string | undefined): boolean {
    const token = parseCookieValue(req.headers.cookie, 'cf_captcha');
    if (!token) return false;
    const challenge = captchaStore.get(token);
    captchaStore.delete(token);
    return captchaService.verify(challenge, input);
}

function clearCaptchaCookie(res: express.Response): void {
    res.append('Set-Cookie', 'cf_captcha=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
}

router.pages.get('/captcha', (req, res) => {
    const { challenge, svg } = captchaService.generate();
    const token = crypto.randomBytes(16).toString('hex');
    captchaStore.set(token, challenge);
    res.setHeader('Set-Cookie', `cf_captcha=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`);
    res.type('image/svg+xml').send(svg);
});

router.pages.get('/login', async (req, res) => {
    const current_user = await resolveCurrentUser(req);
    if (current_user) {
        res.redirect('/');
        return;
    }
    const html = await renderWithUser(req, 'login', {
        active_nav: 'login',
        page_title: '登录',
        account: accountConfig,
        error: null,
        form: {},
    });
    res.send(html);
});

router.pages.post('/login', async (req, res) => {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');
    const captcha = String(req.body.captcha || '');

    const form = { username };
    const fail = async (error: string) => {
        clearCaptchaCookie(res);
        const html = await renderWithUser(req, 'login', {
            active_nav: 'login',
            page_title: '登录',
            account: accountConfig,
            error,
            form,
        });
        res.status(400).send(html);
    };

    if (accountConfig.login_captcha && !verifyCaptcha(req, captcha)) {
        await fail('验证码错误或已过期');
        return;
    }

    const result = await userService.login(username, password);
    if (!result.ok || !result.uuid || !result.user) {
        await fail(result.message || '用户名或密码错误');
        return;
    }

    const token = jwtService.sign({
        uuid: result.uuid,
        uid: result.user.uid,
        username: result.user.username,
    });
    res.setHeader('Set-Cookie', jwtService.buildSetCookie(token));
    clearCaptchaCookie(res);
    res.redirect('/');
});

router.pages.get('/register', async (req, res) => {
    const current_user = await resolveCurrentUser(req);
    if (current_user) {
        res.redirect('/');
        return;
    }
    const html = await renderWithUser(req, 'register', {
        active_nav: 'register',
        page_title: '注册',
        account: accountConfig,
        error: null,
        form: {},
    });
    res.send(html);
});

router.pages.post('/register', async (req, res) => {
    const username = String(req.body.username || '').trim();
    const displayName = String(req.body.display_name || '').trim();
    const password = String(req.body.password || '');
    const confirmPassword = String(req.body.confirm_password || '');
    const captcha = String(req.body.captcha || '');

    const form = { username, display_name: displayName };
    const fail = async (error: string) => {
        clearCaptchaCookie(res);
        const html = await renderWithUser(req, 'register', {
            active_nav: 'register',
            page_title: '注册',
            account: accountConfig,
            error,
            form,
        });
        res.status(400).send(html);
    };

    if (accountConfig.register_captcha && !verifyCaptcha(req, captcha)) {
        await fail('验证码错误或已过期');
        return;
    }

    const result = await userService.register(
        username,
        password,
        displayName,
        accountConfig.register_confirm_password ? confirmPassword : undefined,
    );
    if (!result.ok || !result.user || !result.uuid) {
        await fail(result.message || '注册失败');
        return;
    }

    const token = jwtService.sign({
        uuid: result.uuid,
        uid: result.user.uid,
        username: result.user.username,
    });
    res.setHeader('Set-Cookie', jwtService.buildSetCookie(token));
    clearCaptchaCookie(res);
    res.redirect('/');
});

router.pages.post('/logout', async (req, res) => {
    res.setHeader('Set-Cookie', jwtService.buildClearCookie());
    res.redirect('/');
});

router.api.get('/posts', async (req, res) => {
    const { limit, offset } = parseLimitOffset(req.query);
    const sectionId = Number(req.query.section_id);
    const tag = typeof req.query.tag === 'string' ? req.query.tag : undefined;

    let posts;
    if (Number.isInteger(sectionId) && sectionId > 0) {
        posts = await postService.listBySection(sectionId, limit, offset);
    } else if (tag) {
        posts = await postService.listByTag(tag, limit, offset);
    } else {
        posts = await postService.listAll(limit, offset);
    }
    res.json({ ok: true, posts });
});

router.api.get('/posts/:id', async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
        res.status(400).json({ ok: false, message: '无效的帖子 ID' });
        return;
    }
    const post = await postService.getDetail(id);
    if (!post) {
        res.status(404).json({ ok: false, message: '帖子不存在' });
        return;
    }
    res.json({ ok: true, post });
});

router.api.post('/posts/preview', requireAuth, async (req, res) => {
    const content = String(req.body?.content ?? '');
    const preview = postService.preview(content);
    res.json({ ok: true, html: preview.html });
});

router.api.post('/posts', requireAuth, async (req, res) => {
    const authedReq = req as AuthedRequest;
    const result = await postService.create({
        title: String(req.body?.title ?? ''),
        content: String(req.body?.content ?? ''),
        section_id: Number(req.body?.section_id),
        tags: req.body?.tags,
        author_uuid: authedReq.userUuid,
        author_uid: authedReq.currentUser.uid,
        author_name: authedReq.currentUser.display_name,
    });

    if (!result.ok || !result.post) {
        res.status(400).json({ ok: false, message: result.message || '发帖失败' });
        return;
    }

    res.status(201).json({ ok: true, post: result.post });
});

router.api.get('/sections', async (_req, res) => {
    const sections = await sectionService.list(true);
    res.json({ ok: true, sections });
});

router.api.get('/sections/:id', async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
        res.status(400).json({ ok: false, message: '无效的板块 ID' });
        return;
    }
    const section = await sectionService.getById(id);
    if (!section) {
        res.status(404).json({ ok: false, message: '板块不存在' });
        return;
    }
    const { limit, offset } = parseLimitOffset(req.query);
    const posts = await postService.listBySection(id, limit, offset);
    res.json({ ok: true, section, posts });
});

router.api.get('/tags', async (_req, res) => {
    const tags = await tagService.list(true);
    res.json({ ok: true, tags });
});

router.api.get('/tags/:name', async (req, res) => {
    const name = normalizeTagName(decodeURIComponent(req.params.name));
    if (!name) {
        res.status(400).json({ ok: false, message: '无效的标签名' });
        return;
    }
    const tag = await tagService.get(name);
    if (!tag) {
        res.status(404).json({ ok: false, message: '标签不存在' });
        return;
    }
    const { limit, offset } = parseLimitOffset(req.query);
    const posts = await postService.listByTag(name, limit, offset);
    res.json({ ok: true, tag, posts });
});

router.api.post('/upload/image', requireAuth, (req, res, next) => {
    imageUpload.single('image')(req, res, (err: unknown) => {
        if (err) {
            const multerErr = err as multer.MulterError;
            if (multerErr.code === 'LIMIT_FILE_SIZE') {
                res.status(400).json({
                    ok: false,
                    message: `图片大小不能超过 ${uploadConfig.max_image_size} KB`,
                });
                return;
            }
            res.status(400).json({ ok: false, message: '上传失败' });
            return;
        }
        next();
    });
}, async (req, res) => {
    const file = req.file;
    if (!file) {
        res.status(400).json({ ok: false, message: '请选择图片文件' });
        return;
    }
    const result = await imageUploadService.save(file.buffer, file.mimetype);
    if (!result.ok) {
        res.status(400).json(result);
        return;
    }
    res.json(result);
});

router.pages.get('/', async (req, res) => {
    try {
        setContentSecurityPolicy(res);
        const [sections, tags, posts] = await Promise.all([
            sectionService.list(true),
            tagService.list(true),
            postService.listAll(20, 0),
        ]);
        const html = await renderWithUser(req, 'index', {
            active_nav: 'home',
            sections: sections.slice(0, 8),
            tags: tags.slice(0, 12),
            posts,
        });
        res.send(html);
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal Server Error');
    }
});

router.pages.get('/sections', async (req, res) => {
    try {
        setContentSecurityPolicy(res);
        const sections = await sectionService.list(true);
        const html = await renderWithUser(req, 'sections', { active_nav: 'sections', sections });
        res.send(html);
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal Server Error');
    }
});

router.pages.get('/tags', async (req, res) => {
    try {
        setContentSecurityPolicy(res);
        const tags = await tagService.list(true);
        const html = await renderWithUser(req, 'tags', { active_nav: 'tags', tags });
        res.send(html);
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal Server Error');
    }
});

router.pages.get('/create', requireAuthPage, async (req, res) => {
    try {
        setContentSecurityPolicy(res);
        const sections = await sectionService.list(false);
        const html = await renderWithUser(req, 'create', {
            page_title: '发帖',
            sections,
            upload: uploadConfig,
            error: null,
            form: {},
        });
        res.send(html);
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal Server Error');
    }
});

router.pages.post('/create', requireAuthPage, async (req, res) => {
    const authedReq = req as AuthedRequest;
    const form = {
        title: String(req.body.title || ''),
        content: String(req.body.content || ''),
        section_id: String(req.body.section_id || ''),
        tags: String(req.body.tags || ''),
    };

    const result = await postService.create({
        title: form.title,
        content: form.content,
        section_id: Number(form.section_id),
        tags: form.tags,
        author_uuid: authedReq.userUuid,
        author_uid: authedReq.currentUser.uid,
        author_name: authedReq.currentUser.display_name,
    });

    if (!result.ok || !result.post) {
        const sections = await sectionService.list(false);
        setContentSecurityPolicy(res);
        const html = await renderWithUser(req, 'create', {
            page_title: '发帖',
            sections,
            upload: uploadConfig,
            error: result.message || '发帖失败',
            form,
        });
        res.status(400).send(html);
        return;
    }

    res.redirect(`/post/${result.post.id}`);
});

router.pages.get('/post/:id', async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
        res.status(404).send('Not Found');
        return;
    }
    const post = await postService.incrementViews(id);
    if (!post) {
        res.status(404).send('Not Found');
        return;
    }
    const section = await sectionService.getById(post.section_id);
    setContentSecurityPolicy(res);
    const html = await renderWithUser(req, 'post', {
        page_title: post.title,
        post,
        section_name: section?.name || '未知板块',
    });
    res.send(html);
});

router.pages.get('/section/:id', async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
        res.status(404).send('Not Found');
        return;
    }
    const section = await sectionService.getById(id);
    if (!section) {
        res.status(404).send('Not Found');
        return;
    }
    await sectionService.incrementViews(id);
    const posts = await postService.listBySection(id, 50, 0);
    setContentSecurityPolicy(res);
    const html = await renderWithUser(req, 'section', {
        page_title: section.name,
        section,
        posts,
    });
    res.send(html);
});

router.pages.get('/tag/:name', async (req, res) => {
    const name = normalizeTagName(decodeURIComponent(req.params.name));
    if (!name) {
        res.status(404).send('Not Found');
        return;
    }
    const tag = await tagService.get(name);
    if (!tag) {
        res.status(404).send('Not Found');
        return;
    }
    const posts = await postService.listByTag(name, 50, 0);
    setContentSecurityPolicy(res);
    const html = await renderWithUser(req, 'tag', {
        page_title: `#${tag.name}`,
        tag,
        posts,
    });
    res.send(html);
});

router.pages.get('/:page', async (req, res) => {
    const pageName = req.params.page;
    if (pageName === 'login' || pageName === 'register' || pageName === 'captcha') {
        res.redirect(`/${pageName}`);
        return;
    }
    try {
        const activeNav = pageName === 'sections' ? 'sections' : pageName === 'tags' ? 'tags' : undefined;
        const html = await renderWithUser(req, pageName, { active_nav: activeNav });
        res.send(html);
    } catch (err: unknown) {
        let status = 500;
        let message = 'Internal Server Error';

        if (err instanceof Error) {
            const errWithCode = err as Error & { code?: string };
            if (errWithCode.code === 'ENOENT' || err.message?.includes('ENOENT') || err.message?.includes('not f')) {
                status = 404;
                message = 'Page Not Found';
            } else if (errWithCode.code === 'EACCES' || err.message?.includes('permission')) {
                status = 403;
                message = 'Permission Denied';
            } else {
                console.error('Error: ', err, ' at ', req);
            }
        } else if (typeof err === 'string') {
            message = err;
        }

        try {
            const html = await renderWithUser(req, 'error', {
                status,
                message,
                error: err,
            });
            res.status(status).send(html);
        } catch {
            res.status(status).send(`${status} ${message}`);
        }
    }
});

router.statics.use('/theme', express.static(path.join(themePath, 'statics')));
router.statics.use('/', express.static(path.join(process.cwd(), 'statics')));

router.uploads.use('/images', express.static(path.join(process.cwd(), 'uploads/images')));

app.use(path.posix.join(requestRoot, 'api'), router.api);
app.use(path.posix.join(requestRoot, 'statics'), router.statics);
app.use(requestRoot, router.pages);
app.use(path.posix.join(requestRoot, 'uploads'), router.uploads);

async function start(): Promise<void> {
    await sectionService.ensureDefaults();
    app.listen(port, () => {
        console.log(`ClayForum is running at http://localhost:${port}`);
    });
}

start().catch(err => {
    console.error('Failed to start ClayForum:', err);
    process.exit(1);
});

process.on('uncaughtException', (err: Error) => {
    console.error(err);
});

let isExiting = false;

function onExit() {
    if (isExiting) return;
    isExiting = true;
    console.log('ClayForum is exiting...');
    db.user.close().then(() => console.log('User database closed.'));
    db.user_profile.close().then(() => console.log('User profile database closed.'));
    db.data.close().then(() => console.log('Data database closed.'));
}

process.on('exit', onExit);
process.on('SIGINT', onExit);
process.on('SIGTERM', onExit);
