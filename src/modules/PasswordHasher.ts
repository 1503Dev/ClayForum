import crypto from 'crypto';
import sha256 from 'sha256';

const SALT_BYTES = 16;
const DELIMITER = '$';

export class PasswordHasher {
    hash(password: string): string {
        const salt = crypto.randomBytes(SALT_BYTES).toString('hex');
        const digest = sha256(salt + password);
        return `${salt}${DELIMITER}${digest}`;
    }

    verify(password: string, stored: string): boolean {
        const sep = stored.indexOf(DELIMITER);
        if (sep <= 0) return false;
        const salt = stored.slice(0, sep);
        const expected = stored.slice(sep + 1);
        const actual = sha256(salt + password);
        if (expected.length !== actual.length) return false;
        return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(actual));
    }
}
