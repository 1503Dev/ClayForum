import { LDB } from './LDB';

export interface TagRecord {
    name: string;
    count: number;
    views: number;
}

export interface TagSummary {
    name: string;
    count: number;
    views: number;
}

const TAG_NAME_PATTERN = /^[\p{L}\p{N}_-]{1,32}$/u;

export function normalizeTagName(name: string): string | null {
    const trimmed = name.trim().toLowerCase();
    if (!trimmed || !TAG_NAME_PATTERN.test(trimmed)) return null;
    return trimmed;
}

export function parseTags(input: string[] | string | undefined): string[] {
    if (!input) return [];
    const raw = Array.isArray(input) ? input : String(input).split(/[,，\s]+/);
    const seen = new Set<string>();
    const result: string[] = [];
    for (const item of raw) {
        const normalized = normalizeTagName(item);
        if (normalized && !seen.has(normalized)) {
            seen.add(normalized);
            result.push(normalized);
        }
    }
    return result.slice(0, 10);
}

export class TagService {
    constructor(private db: LDB) {}

    private toSummary(tag: TagRecord): TagSummary {
        return { name: tag.name, count: tag.count, views: tag.views };
    }

    async get(name: string): Promise<TagRecord | undefined> {
        const normalized = normalizeTagName(name);
        if (!normalized) return undefined;
        return this.db.get<TagRecord>(['tag', normalized]);
    }

    async list(sortByViews = true): Promise<TagSummary[]> {
        const tags = await this.db.getValues<TagRecord>('tag');
        tags.sort((a, b) => {
            if (sortByViews) return b.views - a.views || b.count - a.count;
            return a.name.localeCompare(b.name);
        });
        return tags.map(t => this.toSummary(t));
    }

    async onPostCreated(tagNames: string[], postViews = 0): Promise<void> {
        for (const name of tagNames) {
            const existing = await this.get(name);
            if (existing) {
                existing.count += 1;
                existing.views += postViews;
                await this.db.put(['tag', name], existing);
            } else {
                const tag: TagRecord = { name, count: 1, views: postViews };
                await this.db.put(['tag', name], tag);
            }
        }
    }

    async addViews(tagNames: string[], amount: number): Promise<void> {
        for (const name of tagNames) {
            const tag = await this.get(name);
            if (!tag) continue;
            tag.views += amount;
            await this.db.put(['tag', name], tag);
        }
    }
}
