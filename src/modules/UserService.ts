import crypto from 'crypto';
import { LDB } from './LDB';
import { AccountConfig, normalizeUsername, validateDisplayName, validatePassword, validateUsername, ValidationResult } from './AccountConfig';
import { PasswordHasher } from './PasswordHasher';
import { UserProfileService } from './UserProfileService';

export interface UserRecord {
    uuid: string;
    uid: number;
    username: string;
    password: string;
}

export interface PublicUser {
    uid: number;
    username: string;
    display_name: string;
}

export class UserService {
    private hasher = new PasswordHasher();

    constructor(
        private db: LDB,
        private profileService: UserProfileService,
        private account: AccountConfig,
    ) {}

    async register(
        username: string,
        password: string,
        displayName: string,
        confirmPassword?: string,
    ): Promise<ValidationResult & { user?: PublicUser; uuid?: string }> {
        const normalized = normalizeUsername(username);
        const usernameCheck = validateUsername(normalized, this.account);
        if (!usernameCheck.ok) return usernameCheck;

        const passwordCheck = validatePassword(password, this.account);
        if (!passwordCheck.ok) return passwordCheck;

        if (this.account.register_confirm_password) {
            if (!confirmPassword) {
                return { ok: false, message: '请确认密码' };
            }
            if (password !== confirmPassword) {
                return { ok: false, message: '两次输入的密码不一致' };
            }
        }

        const displayNameCheck = validateDisplayName(displayName, this.account);
        if (!displayNameCheck.ok) return displayNameCheck;

        const existingUid = await this.db.get<number>(['idx', 'username', normalized]);
        if (existingUid !== undefined) {
            return { ok: false, message: '用户名已被注册' };
        }

        const uid = await this.allocateUid();
        const uuid = crypto.randomUUID();
        const user: UserRecord = {
            uuid,
            uid,
            username: normalized,
            password: this.hasher.hash(password),
        };

        await this.db.batch([
            { type: 'put', key: ['user', uuid], value: user },
            { type: 'put', key: ['idx', 'uid', String(uid)], value: uuid },
            { type: 'put', key: ['idx', 'username', normalized], value: uid },
        ]);

        const profileResult = await this.profileService.create(uuid, displayName);
        if (!profileResult.ok) {
            await this.db.batch([
                { type: 'del', key: ['user', uuid] },
                { type: 'del', key: ['idx', 'uid', String(uid)] },
                { type: 'del', key: ['idx', 'username', normalized] },
            ]);
            return profileResult;
        }

        return {
            ok: true,
            uuid,
            user: {
                uid: user.uid,
                username: user.username,
                display_name: displayName,
            },
        };
    }

    async login(username: string, password: string): Promise<ValidationResult & { user?: PublicUser; uuid?: string }> {
        const normalized = normalizeUsername(username);
        const usernameCheck = validateUsername(normalized, this.account);
        if (!usernameCheck.ok) return { ok: false, message: '用户名或密码错误' };

        const uid = await this.db.get<number>(['idx', 'username', normalized]);
        if (uid === undefined) {
            return { ok: false, message: '用户名或密码错误' };
        }

        const uuid = await this.resolveUuidByUid(uid);
        if (!uuid) {
            return { ok: false, message: '用户名或密码错误' };
        }

        const user = await this.getByUuid(uuid);
        if (!user) {
            return { ok: false, message: '用户名或密码错误' };
        }

        if (!this.hasher.verify(password, user.password)) {
            return { ok: false, message: '用户名或密码错误' };
        }

        const publicUser = await this.toPublicUser(user);
        return { ok: true, user: publicUser, uuid: user.uuid };
    }

    async getByUuid(uuid: string): Promise<UserRecord | undefined> {
        return this.db.get<UserRecord>(['user', uuid]);
    }

    async getByUid(uid: number): Promise<UserRecord | undefined> {
        const uuid = await this.resolveUuidByUid(uid);
        if (!uuid) return undefined;
        return this.getByUuid(uuid);
    }

    async resolveUuidByUid(uid: number): Promise<string | undefined> {
        return this.db.get<string>(['idx', 'uid', String(uid)]);
    }

    async toPublicUser(user: UserRecord): Promise<PublicUser> {
        const profile = await this.profileService.getByUuid(user.uuid);
        return {
            uid: user.uid,
            username: user.username,
            display_name: profile?.display_name ?? user.username,
        };
    }

    getAccountConfig(): AccountConfig {
        return this.account;
    }

    private async allocateUid(): Promise<number> {
        const metaKey = ['meta', 'next_uid'];
        let nextUid = await this.db.get<number>(metaKey);
        if (nextUid === undefined) {
            nextUid = this.account.primary_userid;
        }
        const assigned = nextUid;
        await this.db.put(metaKey, nextUid + 1);
        return assigned;
    }
}
