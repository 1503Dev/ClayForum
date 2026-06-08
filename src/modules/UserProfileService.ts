import { LDB } from './LDB';
import { ValidationResult } from './AccountConfig';

export interface UserProfile {
    display_name: string;
    created_at: string;
}

export class UserProfileService {
    constructor(private db: LDB) {}

    async create(uuid: string, displayName: string): Promise<ValidationResult> {
        const profile: UserProfile = {
            display_name: displayName.trim(),
            created_at: new Date().toISOString(),
        };
        await this.db.put(['profile', uuid], profile);
        return { ok: true };
    }

    async getByUuid(uuid: string): Promise<UserProfile | undefined> {
        return this.db.get<UserProfile>(['profile', uuid]);
    }
}
