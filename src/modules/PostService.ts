import crypto from 'crypto';
import { LDB } from './LDB';
import { renderMarkdown } from './MarkdownService';
import { parseTags } from './TagService';
import { SectionService } from './SectionService';
import { TagService } from './TagService';

export interface PostRecord {
    id: number;
    uuid: string;
    title: string;
    content_md: string;
    author_uuid: string;
    author_uid: number;
    author_name: string;
    section_id: number;
    tags: string[];
    views: number;
    created_at: number;
    updated_at: number;
}

export interface PostSummary {
    id: number;
    title: string;
    author_uid: number;
    author_name: string;
    section_id: number;
    tags: string[];
    views: number;
    created_at: number;
}

export interface PostDetail extends PostSummary {
    content_html: string;
    updated_at: number;
}

export interface CreatePostInput {
    title: string;
    content: string;
    section_id: number;
    tags?: string[] | string;
    author_uuid: string;
    author_uid: number;
    author_name: string;
}

export interface ValidationResult {
    ok: boolean;
    message?: string;
}

const MAX_TITLE_LENGTH = 128;
const MAX_CONTENT_LENGTH = 100_000;

export class PostService {
    constructor(
        private db: LDB,
        private sectionService: SectionService,
        private tagService: TagService,
    ) {}

    private toSummary(post: PostRecord): PostSummary {
        return {
            id: post.id,
            title: post.title,
            author_uid: post.author_uid,
            author_name: post.author_name,
            section_id: post.section_id,
            tags: post.tags,
            views: post.views,
            created_at: post.created_at,
        };
    }

    private validateInput(input: CreatePostInput): ValidationResult {
        const title = String(input.title ?? '').trim();
        if (!title) return { ok: false, message: '标题不能为空' };
        if (title.length > MAX_TITLE_LENGTH) {
            return { ok: false, message: `标题不能超过 ${MAX_TITLE_LENGTH} 个字符` };
        }
        const content = String(input.content ?? '');
        if (!content.trim()) return { ok: false, message: '内容不能为空' };
        if (content.length > MAX_CONTENT_LENGTH) {
            return { ok: false, message: `内容不能超过 ${MAX_CONTENT_LENGTH} 个字符` };
        }
        if (!Number.isInteger(input.section_id) || input.section_id <= 0) {
            return { ok: false, message: '请选择板块' };
        }
        return { ok: true };
    }

    private async allocateId(): Promise<number> {
        const current = (await this.db.get<number>('meta/next_post_id')) ?? 1;
        await this.db.put('meta/next_post_id', current + 1);
        return current;
    }

    async create(input: CreatePostInput): Promise<ValidationResult & { post?: PostDetail }> {
        const validation = this.validateInput(input);
        if (!validation.ok) return validation;

        const section = await this.sectionService.getById(input.section_id);
        if (!section) return { ok: false, message: '板块不存在' };

        const title = input.title.trim();
        const content_md = input.content;
        const tags = parseTags(input.tags);
        const now = Date.now();
        const id = await this.allocateId();
        const uuid = crypto.randomUUID();

        const post: PostRecord = {
            id,
            uuid,
            title,
            content_md,
            author_uuid: input.author_uuid,
            author_uid: input.author_uid,
            author_name: input.author_name,
            section_id: input.section_id,
            tags,
            views: 0,
            created_at: now,
            updated_at: now,
        };

        const batch = [
            { type: 'put' as const, key: ['post', String(id)], value: post },
            { type: 'put' as const, key: ['idx', 'section', String(input.section_id), 'post', String(id)], value: now },
            { type: 'put' as const, key: ['idx', 'author', input.author_uuid, 'post', String(id)], value: now },
        ];
        for (const tag of tags) {
            batch.push({
                type: 'put',
                key: ['idx', 'tag', tag, 'post', String(id)],
                value: now,
            });
        }
        await this.db.batch(batch);

        await this.sectionService.onPostCreated(input.section_id);
        await this.tagService.onPostCreated(tags, 0);

        return { ok: true, post: this.toDetail(post) };
    }

    toDetail(post: PostRecord): PostDetail {
        return {
            ...this.toSummary(post),
            content_html: renderMarkdown(post.content_md),
            updated_at: post.updated_at,
        };
    }

    preview(content: string): { html: string } {
        return { html: renderMarkdown(content) };
    }

    async getById(id: number): Promise<PostRecord | undefined> {
        return this.db.get<PostRecord>(['post', String(id)]);
    }

    async getDetail(id: number): Promise<PostDetail | undefined> {
        const post = await this.getById(id);
        if (!post) return undefined;
        return this.toDetail(post);
    }

    async incrementViews(id: number): Promise<PostDetail | undefined> {
        const post = await this.getById(id);
        if (!post) return undefined;
        post.views += 1;
        await this.db.put(['post', String(id)], post);
        await this.sectionService.addPostViews(post.section_id, 1);
        await this.tagService.addViews(post.tags, 1);
        return this.toDetail(post);
    }

    private async listFromIndex(
        indexPath: string[],
        limit: number,
        offset: number,
    ): Promise<PostSummary[]> {
        const postIds = await this.db.keys(indexPath);
        postIds.sort((a, b) => Number(b) - Number(a));

        const posts: PostRecord[] = [];
        for (const postId of postIds) {
            const post = await this.getById(Number(postId));
            if (post) posts.push(post);
        }

        posts.sort((a, b) => b.views - a.views || b.created_at - a.created_at);
        return posts.slice(offset, offset + limit).map(p => this.toSummary(p));
    }

    async listAll(limit = 20, offset = 0): Promise<PostSummary[]> {
        const postIds = await this.db.keys('post');
        const posts: PostRecord[] = [];
        for (const postId of postIds) {
            const post = await this.getById(Number(postId));
            if (post) posts.push(post);
        }
        posts.sort((a, b) => b.views - a.views || b.created_at - a.created_at);
        return posts.slice(offset, offset + limit).map(p => this.toSummary(p));
    }

    async listBySection(sectionId: number, limit = 20, offset = 0): Promise<PostSummary[]> {
        return this.listFromIndex(['idx', 'section', String(sectionId), 'post'], limit, offset);
    }

    async listByTag(tagName: string, limit = 20, offset = 0): Promise<PostSummary[]> {
        const normalized = parseTags([tagName])[0];
        if (!normalized) return [];
        return this.listFromIndex(['idx', 'tag', normalized, 'post'], limit, offset);
    }
}
