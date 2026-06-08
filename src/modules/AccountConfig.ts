export type CaptchaType = 'math' | 'text';

export interface AccountConfig {
    primary_userid: number;
    max_username_length: number;
    min_username_length: number;
    max_password_length: number;
    min_password_length: number;
    username_pattern: string;
    username_requirements: string;
    password_pattern: string;
    password_requirements: string;
    login_captcha: boolean;
    register_captcha: boolean;
    register_confirm_password: boolean;
    captcha_type: CaptchaType;
    captcha_length: number;
    captcha_max_length: number;
    captcha_ignore_chars: string;
    captcha_char_preset: string;
    captcha_requirements: string;
    min_display_name_length: number;
    max_display_name_length: number;
}

const DEFAULT_ACCOUNT: AccountConfig = {
    primary_userid: 1,
    max_username_length: 32,
    min_username_length: 3,
    max_password_length: 128,
    min_password_length: 6,
    username_pattern: '^[a-z0-9_]+$',
    username_requirements: '用户名仅可包含小写字母、数字和下划线',
    password_pattern: '',
    password_requirements: '密码长度至少6位',
    login_captcha: false,
    register_captcha: false,
    register_confirm_password: true,
    captcha_type: 'math',
    captcha_length: 4,
    captcha_max_length: 4,
    captcha_ignore_chars: '0oO1ilI',
    captcha_char_preset: '',
    captcha_requirements: '请计算图片中的算式结果',
    min_display_name_length: 1,
    max_display_name_length: 32,
};

export function loadAccountConfig(raw: Record<string, unknown> | undefined): AccountConfig {
    if (!raw) return { ...DEFAULT_ACCOUNT };
    return {
        primary_userid: typeof raw.primary_userid === 'number' ? raw.primary_userid : DEFAULT_ACCOUNT.primary_userid,
        max_username_length: typeof raw.max_username_length === 'number' ? raw.max_username_length : DEFAULT_ACCOUNT.max_username_length,
        min_username_length: typeof raw.min_username_length === 'number' ? raw.min_username_length : DEFAULT_ACCOUNT.min_username_length,
        max_password_length: typeof raw.max_password_length === 'number' ? raw.max_password_length : DEFAULT_ACCOUNT.max_password_length,
        min_password_length: typeof raw.min_password_length === 'number' ? raw.min_password_length : DEFAULT_ACCOUNT.min_password_length,
        username_pattern: typeof raw.username_pattern === 'string' ? raw.username_pattern : DEFAULT_ACCOUNT.username_pattern,
        username_requirements: typeof raw.username_requirements === 'string' ? raw.username_requirements : DEFAULT_ACCOUNT.username_requirements,
        password_pattern: typeof raw.password_pattern === 'string' ? raw.password_pattern : DEFAULT_ACCOUNT.password_pattern,
        password_requirements: typeof raw.password_requirements === 'string' ? raw.password_requirements : DEFAULT_ACCOUNT.password_requirements,
        login_captcha: typeof raw.login_captcha === 'boolean' ? raw.login_captcha : DEFAULT_ACCOUNT.login_captcha,
        register_captcha: typeof raw.register_captcha === 'boolean' ? raw.register_captcha : DEFAULT_ACCOUNT.register_captcha,
        register_confirm_password: typeof raw.register_confirm_password === 'boolean' ? raw.register_confirm_password : DEFAULT_ACCOUNT.register_confirm_password,
        captcha_type: raw.captcha_type === 'text' || raw.captcha_type === 'math' ? raw.captcha_type : DEFAULT_ACCOUNT.captcha_type,
        captcha_length: typeof raw.captcha_length === 'number' ? raw.captcha_length : DEFAULT_ACCOUNT.captcha_length,
        captcha_max_length: typeof raw.captcha_max_length === 'number' ? raw.captcha_max_length : DEFAULT_ACCOUNT.captcha_max_length,
        captcha_ignore_chars: typeof raw.captcha_ignore_chars === 'string' ? raw.captcha_ignore_chars : DEFAULT_ACCOUNT.captcha_ignore_chars,
        captcha_char_preset: typeof raw.captcha_char_preset === 'string' ? raw.captcha_char_preset : DEFAULT_ACCOUNT.captcha_char_preset,
        captcha_requirements: typeof raw.captcha_requirements === 'string' ? raw.captcha_requirements : DEFAULT_ACCOUNT.captcha_requirements,
        min_display_name_length: typeof raw.min_display_name_length === 'number' ? raw.min_display_name_length : DEFAULT_ACCOUNT.min_display_name_length,
        max_display_name_length: typeof raw.max_display_name_length === 'number' ? raw.max_display_name_length : DEFAULT_ACCOUNT.max_display_name_length,
    };
}

export function normalizeUsername(username: string): string {
    return username.trim().toLowerCase();
}

export interface ValidationResult {
    ok: boolean;
    message?: string;
}

export function validateDisplayName(displayName: string, account: AccountConfig): ValidationResult {
    if (!displayName || displayName.trim() === '') {
        return { ok: false, message: '请输入昵称' };
    }
    const trimmed = displayName.trim();
    if (trimmed.length < account.min_display_name_length) {
        return { ok: false, message: `昵称长度不能少于 ${account.min_display_name_length} 个字符` };
    }
    if (trimmed.length > account.max_display_name_length) {
        return { ok: false, message: `昵称长度不能超过 ${account.max_display_name_length} 个字符` };
    }
    return { ok: true };
}

export function validateUsername(username: string, account: AccountConfig): ValidationResult {
    if (!username) {
        return { ok: false, message: '请输入用户名' };
    }
    if (username !== username.toLowerCase()) {
        return { ok: false, message: '用户名必须为小写字母' };
    }
    if (username.length < account.min_username_length) {
        return { ok: false, message: `用户名长度不能少于 ${account.min_username_length} 个字符` };
    }
    if (username.length > account.max_username_length) {
        return { ok: false, message: `用户名长度不能超过 ${account.max_username_length} 个字符` };
    }
    try {
        const pattern = new RegExp(account.username_pattern);
        if (!pattern.test(username)) {
            return { ok: false, message: account.username_requirements || '用户名格式不符合要求' };
        }
    } catch {
        return { ok: false, message: '用户名验证规则配置错误' };
    }
    return { ok: true };
}

export function validatePassword(password: string, account: AccountConfig): ValidationResult {
    if (!password) {
        return { ok: false, message: '请输入密码' };
    }
    if (password.length < account.min_password_length) {
        return { ok: false, message: `密码长度不能少于 ${account.min_password_length} 个字符` };
    }
    if (password.length > account.max_password_length) {
        return { ok: false, message: `密码长度不能超过 ${account.max_password_length} 个字符` };
    }
    if (account.password_pattern) {
        try {
            const pattern = new RegExp(account.password_pattern);
            if (!pattern.test(password)) {
                return { ok: false, message: account.password_requirements || '密码格式不符合要求' };
            }
        } catch {
            return { ok: false, message: '密码验证规则配置错误' };
        }
    }
    return { ok: true };
}
