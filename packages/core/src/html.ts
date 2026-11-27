export interface StructuredWebDocument {
  url: string;
  title: string;
  description: string | null;
  headings: Array<{ level: number; text: string }>;
  jsonLd: unknown[];
  markdown: string;
  links: Array<{ text: string; href: string }>;
  estimatedTokenSavingsPct: number;
}

function decodeHtmlEntities(input: string): string {
  return input
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&#(\d+);/g, (_m, code) => String.fromCharCode(Number(code)));
}

function stripTags(html: string): string {
  return decodeHtmlEntities(html.replace(/<[^>]+>/g, ' '))
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Zero-dependency HTML-to-Structured JSON & Markdown extractor for paying AI agents.
 * Strips scripts, styles, nav/footer boilerplate, extracts JSON-LD & meta tags,
 * and converts semantic content into compact Markdown + structured metadata.
 */
export function extractStructuredDocument(rawHtml: string, pageUrl = '/'): StructuredWebDocument {
  const originalLen = Math.max(rawHtml.length, 1);

  // 1. Extract <script type="application/ld+json"> before stripping scripts
  const jsonLd: unknown[] = [];
  const ldRegex = /<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let ldMatch: RegExpExecArray | null;
  while ((ldMatch = ldRegex.exec(rawHtml)) !== null) {
    try {
      jsonLd.push(JSON.parse(ldMatch[1]!.trim()));
    } catch {
      // ignore malformed JSON-LD
    }
  }

  // 2. Extract title & meta description
  const titleMatch = rawHtml.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const ogTitleMatch = rawHtml.match(/<meta[^>]*property=["']og:title["'][^>]*content=["']([^"']*)["']/i);
  const descMatch =
    rawHtml.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']*)["']/i) ??
    rawHtml.match(/<meta[^>]*property=["']og:description["'][^>]*content=["']([^"']*)["']/i);

  const title = stripTags(titleMatch?.[1] ?? ogTitleMatch?.[1] ?? 'Untitled Document');
  const description = descMatch?.[1] ? decodeHtmlEntities(descMatch[1].trim()) : null;

  // 3. Remove non-content blocks (<script>, <style>, <noscript>, <svg>, <nav>, <footer>)
  let cleaned = rawHtml
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<(script|style|noscript|svg|iframe)[^>]*>[\s\S]*?<\/\1>/gi, '')
    .replace(/<(nav|footer|aside)[^>]*>[\s\S]*?<\/\1>/gi, '');

  // Prefer <main> or <article> when available
  const mainMatch =
    cleaned.match(/<article[^>]*>([\s\S]*?)<\/article>/i) ??
    cleaned.match(/<main[^>]*>([\s\S]*?)<\/main>/i);
  if (mainMatch?.[1]) {
    cleaned = mainMatch[1];
  }

  // 4. Extract headings & links
  const headings: Array<{ level: number; text: string }> = [];
  const hRegex = /<h([1-6])[^>]*>([\s\S]*?)<\/h\1>/gi;
  let hMatch: RegExpExecArray | null;
  while ((hMatch = hRegex.exec(cleaned)) !== null) {
    const text = stripTags(hMatch[2]!);
    if (text) headings.push({ level: Number(hMatch[1]), text });
  }

  const links: Array<{ text: string; href: string }> = [];
  const aRegex = /<a[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let aMatch: RegExpExecArray | null;
  while ((aMatch = aRegex.exec(cleaned)) !== null) {
    const href = aMatch[1]!.trim();
    const text = stripTags(aMatch[2]!);
    if (href && !href.startsWith('javascript:') && text) {
      links.push({ text, href });
    }
  }

  // 5. Convert semantic blocks into clean Markdown
  let md = cleaned
    .replace(/<h1[^>]*>([\s\S]*?)<\/h1>/gi, (_m, c) => `\n# ${stripTags(c)}\n`)
    .replace(/<h2[^>]*>([\s\S]*?)<\/h2>/gi, (_m, c) => `\n## ${stripTags(c)}\n`)
    .replace(/<h3[^>]*>([\s\S]*?)<\/h3>/gi, (_m, c) => `\n### ${stripTags(c)}\n`)
    .replace(/<h([4-6])[^>]*>([\s\S]*?)<\/h\1>/gi, (_m, l, c) => `\n${'#'.repeat(Number(l))} ${stripTags(c)}\n`)
    .replace(/<li[^>]*>([\s\S]*?)<\/li>/gi, (_m, c) => `\n- ${stripTags(c)}`)
    .replace(/<a[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi, (_m, href, txt) => {
      const cleanTxt = stripTags(txt);
      return cleanTxt ? `[${cleanTxt}](${href})` : '';
    })
    .replace(/<(strong|b)[^>]*>([\s\S]*?)<\/\1>/gi, (_m, _t, c) => `**${stripTags(c)}**`)
    .replace(/<(em|i)[^>]*>([\s\S]*?)<\/\1>/gi, (_m, _t, c) => `*${stripTags(c)}*`)
    .replace(/<(p|div|section|br|tr)[^>]*>/gi, '\n')
    .replace(/<[^>]+>/g, '');

  md = decodeHtmlEntities(md)
    .split('\n')
    .map((line) => line.trim())
    .filter((line, idx, arr) => !(line === '' && arr[idx - 1] === ''))
    .join('\n')
    .trim();

  const savings = Math.max(0, Math.min(99, Math.round((1 - md.length / originalLen) * 100)));

  return {
    url: pageUrl,
    title,
    description,
    headings,
    jsonLd,
    markdown: md,
    links: links.slice(0, 50),
    estimatedTokenSavingsPct: savings,
  };
}
