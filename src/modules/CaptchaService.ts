import { create, createMathExpr } from 'svg-captcha';
import { AccountConfig } from './AccountConfig';

const CAPTCHA_TTL_MS = 5 * 60 * 1000;

export interface CaptchaChallenge {
    code: string;
    type: 'math' | 'text';
    expires_at: number;
}

export class CaptchaService {
    constructor(private account: AccountConfig) {}

    generate(): { challenge: CaptchaChallenge; svg: string } {
        const common = {
            width: 96,
            height: 28,
            fontSize: 22,
            noise: 3,
            color: false,
            background: '#f0f0f0',
            ignoreChars: this.account.captcha_ignore_chars,
        };

        const textOptions = {
            ...common,
            size: this.account.captcha_length,
            ...(this.account.captcha_char_preset ? { charPreset: this.account.captcha_char_preset } : {}),
        };

        const captcha = this.account.captcha_type === 'text'
            ? create(textOptions)
            : createMathExpr({
                ...common,
                mathMin: 1,
                mathMax: 9,
            });

        const challenge: CaptchaChallenge = {
            code: captcha.text,
            type: this.account.captcha_type,
            expires_at: Date.now() + CAPTCHA_TTL_MS,
        };
        return { challenge, svg: captcha.data };
    }

    verify(challenge: CaptchaChallenge | undefined, input: string | undefined): boolean {
        if (!challenge || !input) return false;
        if (Date.now() > challenge.expires_at) return false;
        const trimmed = input.trim();
        if (trimmed.length > this.account.captcha_max_length) return false;
        if (challenge.type === 'text') {
            return challenge.code.toLowerCase() === trimmed.toLowerCase();
        }
        return challenge.code === trimmed;
    }
}
