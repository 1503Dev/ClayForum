import jwt from 'jsonwebtoken';

const TOKEN_COOKIE = 'cf_token';

export interface JwtConfig {
    secret: string;
    expires_in: string | number;
}

export interface JwtPayload {
    uuid: string;
    uid: number;
    username: string;
}

export class JwtService {
    constructor(private config: JwtConfig) {}

    static get cookieName(): string {
        return TOKEN_COOKIE;
    }

    sign(payload: JwtPayload): string {
        return jwt.sign(payload, this.config.secret, {
            expiresIn: this.config.expires_in as jwt.SignOptions['expiresIn'],
        });
    }

    verify(token: string | undefined): JwtPayload | null {
        if (!token) return null;
        try {
            const decoded = jwt.verify(token, this.config.secret);
            if (typeof decoded !== 'object' || decoded === null) return null;
            const payload = decoded as Record<string, unknown>;
            if (
                typeof payload.uuid !== 'string' ||
                typeof payload.uid !== 'number' ||
                typeof payload.username !== 'string'
            ) {
                return null;
            }
            return {
                uuid: payload.uuid,
                uid: payload.uid,
                username: payload.username,
            };
        } catch {
            return null;
        }
    }

    parseCookie(cookieHeader: string | undefined): string | undefined {
        if (!cookieHeader) return undefined;
        for (const part of cookieHeader.split(';')) {
            const [name, ...rest] = part.trim().split('=');
            if (name === TOKEN_COOKIE) {
                return rest.join('=') || undefined;
            }
        }
        return undefined;
    }

    maxAgeSeconds(): number {
        const value = this.config.expires_in;
        if (typeof value === 'number') return value;
        const match = /^(\d+)([smhd])$/.exec(value);
        if (!match) return 7 * 24 * 60 * 60;
        const amount = Number(match[1]);
        switch (match[2]) {
            case 's': return amount;
            case 'm': return amount * 60;
            case 'h': return amount * 60 * 60;
            case 'd': return amount * 24 * 60 * 60;
            default: return 7 * 24 * 60 * 60;
        }
    }

    buildSetCookie(token: string): string {
        return [
            `${TOKEN_COOKIE}=${token}`,
            'Path=/',
            'HttpOnly',
            'SameSite=Lax',
            `Max-Age=${this.maxAgeSeconds()}`,
        ].join('; ');
    }

    buildClearCookie(): string {
        return `${TOKEN_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
    }
}

export function loadJwtConfig(raw: Record<string, unknown> | undefined): JwtConfig {
    const defaults: JwtConfig = {
        secret: 'change-me-in-production',
        expires_in: '7d',
    };
    if (!raw) return defaults;
    return {
        secret: typeof raw.secret === 'string' && raw.secret ? raw.secret : defaults.secret,
        expires_in: typeof raw.expires_in === 'number' || typeof raw.expires_in === 'string'
            ? raw.expires_in
            : defaults.expires_in,
    };
}
