import { LDB } from './LDB';

export interface SectionRecord {
    id: number;
    name: string;
    description: string;
    views: number;
    topics_count: number;
    posts_count: number;
    created_at: number;
}

export interface SectionSummary {
    id: number;
    name: string;
    description: string;
    views: number;
    topics_count: number;
    posts_count: number;
}

const DEFAULT_SECTIONS: Array<{ name: string; description: string }> = [
    { name: '综合讨论', description: '自由交流，畅所欲言' },
    { name: '技术交流', description: '分享技术心得与问题' },
];

export class SectionService {
    constructor(private db: LDB) {}

    private toSummary(section: SectionRecord): SectionSummary {
        return {
            id: section.id,
            name: section.name,
            description: section.description,
            views: section.views,
            topics_count: section.topics_count,
            posts_count: section.posts_count,
        };
    }

    async ensureDefaults(): Promise<void> {
        const existing = await this.db.keys('section');
        if (existing.length > 0) return;

        for (const item of DEFAULT_SECTIONS) {
            await this.create(item.name, item.description);
        }
    }

    private async allocateId(): Promise<number> {
        const current = (await this.db.get<number>('meta/next_section_id')) ?? 1;
        await this.db.put('meta/next_section_id', current + 1);
        return current;
    }

    async create(name: string, description: string): Promise<SectionRecord> {
        const id = await this.allocateId();
        const now = Date.now();
        const section: SectionRecord = {
            id,
            name: name.trim(),
            description: description.trim(),
            views: 0,
            topics_count: 0,
            posts_count: 0,
            created_at: now,
        };
        await this.db.put(['section', String(id)], section);
        return section;
    }

    async getById(id: number): Promise<SectionRecord | undefined> {
        return this.db.get<SectionRecord>(['section', String(id)]);
    }

    async list(sortByViews = true): Promise<SectionSummary[]> {
        const sections = await this.db.getValues<SectionRecord>('section');
        sections.sort((a, b) => {
            if (sortByViews) return b.views - a.views || b.posts_count - a.posts_count;
            return a.id - b.id;
        });
        return sections.map(s => this.toSummary(s));
    }

    async incrementViews(id: number, amount = 1): Promise<void> {
        const section = await this.getById(id);
        if (!section) return;
        section.views += amount;
        await this.db.put(['section', String(id)], section);
    }

    async onPostCreated(sectionId: number): Promise<void> {
        const section = await this.getById(sectionId);
        if (!section) return;
        section.topics_count += 1;
        section.posts_count += 1;
        await this.db.put(['section', String(sectionId)], section);
    }

    async addPostViews(sectionId: number, amount: number): Promise<void> {
        const section = await this.getById(sectionId);
        if (!section) return;
        section.views += amount;
        await this.db.put(['section', String(sectionId)], section);
    }
}
