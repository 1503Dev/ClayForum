import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { UploadConfig } from './UploadConfig';

const ALLOWED_MIME_TYPES: Record<string, string> = {
    'image/jpeg': 'jpg',
    'image/png': 'png',
    'image/gif': 'gif',
    'image/webp': 'webp',
};

export interface ImageUploadResult {
    ok: true;
    url: string;
    sha1: string;
    size: number;
}

export interface ImageUploadError {
    ok: false;
    message: string;
}

export class ImageUploadService {
    private uploadDir: string;

    constructor(
        private config: UploadConfig,
        baseDir: string = process.cwd(),
    ) {
        this.uploadDir = path.join(baseDir, 'uploads', 'images');
        fs.mkdirSync(this.uploadDir, { recursive: true });
    }

    get maxBytes(): number {
        return this.config.max_image_size * 1024;
    }

    validate(buffer: Buffer, mimeType: string): ImageUploadError | null {
        if (!buffer || buffer.length === 0) {
            return { ok: false, message: '文件为空' };
        }
        if (buffer.length > this.maxBytes) {
            return {
                ok: false,
                message: `图片大小不能超过 ${this.config.max_image_size} KB`,
            };
        }
        if (!ALLOWED_MIME_TYPES[mimeType]) {
            return { ok: false, message: '仅支持 JPEG、PNG、GIF、WebP 格式图片' };
        }
        return null;
    }

    async save(buffer: Buffer, mimeType: string): Promise<ImageUploadResult | ImageUploadError> {
        const validation = this.validate(buffer, mimeType);
        if (validation) return validation;

        const sha1 = crypto.createHash('sha1').update(buffer).digest('hex');
        const ext = ALLOWED_MIME_TYPES[mimeType];
        const filename = `${sha1}.${ext}`;
        const filePath = path.join(this.uploadDir, filename);

        if (!fs.existsSync(filePath)) {
            await fs.promises.writeFile(filePath, buffer);
        }

        return {
            ok: true,
            url: `../uploads/images/${filename}`,
            sha1,
            size: buffer.length,
        };
    }

    getPublicPath(filename: string): string | null {
        const base = path.basename(filename);
        if (!/^[a-f0-9]{40}\.[a-z0-9]+$/i.test(base)) return null;
        const filePath = path.join(this.uploadDir, base);
        if (!fs.existsSync(filePath)) return null;
        return filePath;
    }
}
