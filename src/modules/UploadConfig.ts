export interface UploadConfig {
    max_image_size: number;
}

const DEFAULT_MAX_IMAGE_SIZE_KB = 2048;

export function loadUploadConfig(raw: Record<string, unknown> | undefined): UploadConfig {
    const upload = (raw ?? {}) as Record<string, unknown>;
    let maxImageSize = Number(upload.max_image_size);
    if (!Number.isFinite(maxImageSize) || maxImageSize <= 0) {
        maxImageSize = DEFAULT_MAX_IMAGE_SIZE_KB;
    }
    return { max_image_size: Math.floor(maxImageSize) };
}
