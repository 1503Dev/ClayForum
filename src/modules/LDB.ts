import { Level } from 'level';
import * as crypto from 'crypto';

export interface HierarchicalLevelDBOptions {
    separator?: string;
    encryptionKey?: string | null;
    [key: string]: any;
}

export interface BatchOperation<T = any> {
    type: 'put' | 'del';
    key: string | string[];
    value?: T;
}

export interface KeyValuePair<T = any> {
    key: string;
    value: T | undefined;
}

export class DecryptionError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'DecryptionError';
    }
}

export class LDB {
    private db: Level<string, Buffer>;
    private separator: string;
    private encryptionKey: Buffer | null = null;
    private readonly ALGORITHM = 'aes-256-gcm';
    private readonly IV_LENGTH = 12;
    private readonly AUTH_TAG_LENGTH = 16;

    constructor(location: string, options: HierarchicalLevelDBOptions = {}) {
        const { separator = '/', encryptionKey, ...levelOptions } = options;

        this.db = new Level<string, Buffer>(location, {
            keyEncoding: 'utf8',
            valueEncoding: 'buffer',
            ...levelOptions
        });

        this.separator = separator;

        if (encryptionKey) {
            const salt = crypto.createHash('sha256').update(location).digest();
            this.encryptionKey = crypto.scryptSync(encryptionKey, salt, 32, {
                N: 16384,
                r: 8,
                p: 1
            });
        }
    }

    static open(location: string, options: HierarchicalLevelDBOptions = {}): LDB {
        return new LDB(location, options);
    }

    private _encrypt(text: string): Buffer {
        const plainBuffer = Buffer.from(text, 'utf8');
        if (!this.encryptionKey) return plainBuffer;

        const iv = crypto.randomBytes(this.IV_LENGTH);
        const cipher = crypto.createCipheriv(this.ALGORITHM, this.encryptionKey, iv);

        const encrypted = Buffer.concat([cipher.update(plainBuffer), cipher.final()]);
        const authTag = cipher.getAuthTag();

        return Buffer.concat([iv, authTag, encrypted]);
    }

    private _decrypt(buffer: Buffer | undefined | null): string {
        if (!buffer) {
            throw new DecryptionError('Data integrity check failed: empty payload.');
        }
        if (!this.encryptionKey) return buffer.toString('utf8');

        if (buffer.length < this.IV_LENGTH + this.AUTH_TAG_LENGTH) {
            throw new DecryptionError('Data integrity check failed: payload too short.');
        }

        const iv = buffer.subarray(0, this.IV_LENGTH);
        const authTag = buffer.subarray(this.IV_LENGTH, this.IV_LENGTH + this.AUTH_TAG_LENGTH);
        const encrypted = buffer.subarray(this.IV_LENGTH + this.AUTH_TAG_LENGTH);

        try {
            const decipher = crypto.createDecipheriv(this.ALGORITHM, this.encryptionKey, iv);
            decipher.setAuthTag(authTag);

            const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
            return decrypted.toString('utf8');
        } catch (error) {
            throw new DecryptionError('Authentication failed: invalid encryption key or corrupted data.');
        }
    }

    private _buildKey(keyPath: string | string[]): string {
        if (Array.isArray(keyPath)) {
            return keyPath.join(this.separator);
        }
        return keyPath;
    }

    async put<T = any>(keyPath: string | string[], value: T): Promise<void> {
        const key = this._buildKey(keyPath);
        const jsonString = JSON.stringify(value);
        const encryptedBuffer = this._encrypt(jsonString);
        await this.db.put(key, encryptedBuffer);
    }

    async get<T = any>(keyPath: string | string[]): Promise<T | undefined> {
        const key = this._buildKey(keyPath);
        try {
            const encryptedBuffer = await this.db.get(key);
            if (encryptedBuffer === undefined || encryptedBuffer === null) {
                return undefined;
            }
            const decryptedValue = this._decrypt(encryptedBuffer);
            return JSON.parse(decryptedValue) as T;
        } catch (err: any) {
            if (err.notFound || err.code === 'LEVEL_NOT_FOUND') return undefined;
            throw err;
        }
    }

    async keys(keyPath: string | string[]): Promise<string[]> {
        const prefix = this._buildKey(keyPath);
        const separator = this.separator;

        const searchPrefix = prefix ? prefix + separator : '';
        const childKeys = new Set<string>();

        for await (const key of this.db.keys({
            gte: searchPrefix,
            lte: searchPrefix + '\xff',
            keyEncoding: 'utf8'
        })) {
            if (key === prefix) continue;

            const relativePath = key.slice(searchPrefix.length);
            const firstSeparatorIndex = relativePath.indexOf(separator);

            if (firstSeparatorIndex === -1) {
                childKeys.add(relativePath);
            } else {
                childKeys.add(relativePath.slice(0, firstSeparatorIndex));
            }
        }

        return Array.from(childKeys).sort();
    }

    async getArray<T = any>(keyPath: string | string[], recursive = false): Promise<KeyValuePair<T>[]> {
        const prefix = this._buildKey(keyPath);
        const separator = this.separator;
        const searchPrefix = prefix ? prefix + separator : '';

        const results: KeyValuePair<T>[] = [];

        if (!recursive) {
            const childKeys = await this.keys(keyPath);

            for (const childKey of childKeys) {
                const fullKey = searchPrefix + childKey;
                const value = await this.get<T>(fullKey);
                results.push({ key: childKey, value });
            }
        } else {
            for await (const [key, encryptedBuffer] of this.db.iterator({
                gte: searchPrefix,
                lte: searchPrefix + '\xff',
                keyEncoding: 'utf8',
                valueEncoding: 'buffer'
            })) {
                if (key === prefix) continue;
                const relativeKey = key.slice(searchPrefix.length);
                const decryptedValue = this._decrypt(encryptedBuffer);
                results.push({ key: relativeKey, value: JSON.parse(decryptedValue) as T });
            }
        }

        return results;
    }

    async getValues<T = any>(keyPath: string | string[], recursive = false): Promise<T[]> {
        const items = await this.getArray<T>(keyPath, recursive);
        return items.map(item => item.value).filter((v): v is T => v !== undefined);
    }

    async del(keyPath: string | string[]): Promise<void> {
        const key = this._buildKey(keyPath);
        await this.db.del(key);
    }

    async delTree(keyPath: string | string[]): Promise<void> {
        const prefix = this._buildKey(keyPath);
        if (!prefix || prefix.trim() === '' || prefix === this.separator) {
            throw new Error('Dangerous operation: removing root path or empty key is not allowed via delTree.');
        }

        const searchPrefix = prefix + this.separator;
        const keys: string[] = [];
        for await (const key of this.db.keys({
            gte: searchPrefix,
            lte: searchPrefix + '\xff'
        })) {
            keys.push(key);
        }

        if (keys.length > 0) {
            const batch = this.db.batch();
            keys.forEach(key => batch.del(key));
            await batch.write();
        }

        await this.del(prefix);
    }

    async has(keyPath: string | string[]): Promise<boolean> {
        const value = await this.get(keyPath);
        return value !== undefined;
    }

    async batch(operations: BatchOperation[]): Promise<void> {
        const batch = this.db.batch();
        for (const op of operations) {
            const key = this._buildKey(op.key);
            if (op.type === 'del') {
                batch.del(key);
            } else {
                const jsonString = JSON.stringify(op.value);
                const encryptedBuffer = this._encrypt(jsonString);
                batch.put(key, encryptedBuffer);
            }
        }
        await batch.write();
    }

    async getAllTopLevelKeys(): Promise<string[]> {
        return await this.keys('');
    }

    async export(): Promise<Record<string, any>> {
        const result: Record<string, any> = {};
        for await (const [key, encryptedBuffer] of this.db.iterator()) {
            const decryptedValue = this._decrypt(encryptedBuffer);
            result[key] = JSON.parse(decryptedValue);
        }
        return result;
    }

    async close(): Promise<void> {
        await this.db.close();
    }
}