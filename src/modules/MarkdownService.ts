import { marked, Renderer } from 'marked';
import sanitizeHtml from 'sanitize-html';

const ALLOWED_TAGS = [
    'p', 'br', 'strong', 'b', 'em', 'i', 'u', 'del', 's', 'sup', 'sub', 'hr',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li', 'blockquote', 'code', 'pre',
    'table', 'thead', 'tbody', 'tr', 'th', 'td',
    'a', 'img',
];

function escapeHtml(text: string): string {
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function escapeAttr(text: string): string {
    return escapeHtml(text);
}

/** Reject any URL with a scheme (http:, https:, javascript:, data:, etc.) */
export function isSafeInternalUrl(url: string | undefined | null): boolean {
    if (!url || typeof url !== 'string') return false;
    const trimmed = url.trim();
    if (!trimmed) return false;
    if (/^[\w+.-]+:/i.test(trimmed)) return false;
    if (trimmed.startsWith('//')) return false;
    return trimmed.startsWith('/') || trimmed.startsWith('#');
}

/** Only allow images served from the local uploads directory */
export function isSafeImageUrl(url: string | undefined | null): boolean {
    if (!isSafeInternalUrl(url)) return false;
    const trimmed = url!.trim();
    return /^\/uploads\/images\/[a-f0-9]{40}\.[a-z0-9]+$/i.test(trimmed);
}

function buildRenderer(): Renderer {
    const renderer = new Renderer();

    renderer.link = ({ href, title, tokens }) => {
        const text = marked.parser(tokens);
        if (!isSafeInternalUrl(href)) {
            return escapeHtml(text.replace(/<[^>]*>/g, ''));
        }
        const titleAttr = title ? ` title="${escapeAttr(title)}"` : '';
        return `<a href="${escapeAttr(href!)}"${titleAttr} rel="noopener noreferrer">${text}</a>`;
    };

    renderer.image = ({ href, title, text }) => {
        if (!isSafeImageUrl(href)) {
            return escapeHtml(text || title || '');
        }
        const alt = escapeAttr(text || title || '');
        const titleAttr = title ? ` title="${escapeAttr(title)}"` : '';
        return `<img src="${escapeAttr(href!)}" alt="${alt}"${titleAttr}>`;
    };

    return renderer;
}

marked.use({
    renderer: buildRenderer(),
    gfm: true,
    breaks: true,
});

function sanitizeRenderedHtml(html: string): string {
    return sanitizeHtml(html, {
        allowedTags: ALLOWED_TAGS,
        allowedAttributes: {
            a: ['href', 'title', 'rel'],
            img: ['src', 'alt', 'title'],
            th: ['colspan', 'rowspan'],
            td: ['colspan', 'rowspan'],
        },
        allowedSchemes: [],
        allowedSchemesByTag: {},
        allowedSchemesAppliedToAttributes: ['href', 'src', 'cite'],
        disallowedTagsMode: 'discard',
        transformTags: {
            a: (tagName, attribs) => {
                if (!isSafeInternalUrl(attribs.href)) {
                    return { tagName: 'span', attribs: {}, text: '' };
                }
                return {
                    tagName: 'a',
                    attribs: {
                        href: attribs.href,
                        ...(attribs.title ? { title: attribs.title } : {}),
                        rel: 'noopener noreferrer',
                    },
                };
            },
            img: (tagName, attribs) => {
                if (!isSafeImageUrl(attribs.src)) {
                    return { tagName: 'span', attribs: {}, text: attribs.alt || '' };
                }
                return {
                    tagName: 'img',
                    attribs: {
                        src: attribs.src,
                        alt: attribs.alt || '',
                        ...(attribs.title ? { title: attribs.title } : {}),
                    },
                };
            },
        },
    });
}

export function renderMarkdown(markdown: string): string {
    const source = String(markdown ?? '');
    const rawHtml = marked.parse(source, { async: false }) as string;
    return sanitizeRenderedHtml(rawHtml);
}
