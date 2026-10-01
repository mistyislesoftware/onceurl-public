import { readFile } from "node:fs/promises";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { App, routeForPathname } from "./App";

const LOCATOR = `loc1_${"a".repeat(48)}`;
const PUBLIC_BEARER = "pub1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const OWNER_BEARER = "own1_AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

describe("functional secret UI", () => {
  it("renders an accessible creator form with UTF-8 limits, policy, and no automatic copy", () => {
    const html = renderToStaticMarkup(<App pathname="/" />);
    expect(html).toContain('for="secret-text"');
    expect(html).toContain('id="secret-text"');
    expect(html).toContain('for="expiry"');
    expect(html).toContain('for="access-code"');
    expect(html).toContain('id="access-code"');
    expect(html).toContain("65,536 UTF-8 bytes");
    expect(html).toContain('type="submit"');
    expect(html).toContain("Encryption happens here with Web Crypto");
    expect(html).toContain("lost response or failed local decryption cannot safely reopen it");
    expect(html).not.toContain("Turnstile");
    expect(html).toContain("Ten incorrect attempts place the capability in a protective lock");
  });

  it("routes exact recipient and owner paths to separate keyboard-operable documents", () => {
    const recipientPath = `/s/${LOCATOR}/${PUBLIC_BEARER}`;
    const ownerPath = `/m/${LOCATOR}/${OWNER_BEARER}`;
    expect(routeForPathname(recipientPath)).toBe("recipient");
    expect(routeForPathname(ownerPath)).toBe("owner");
    expect(routeForPathname(`/s/${LOCATOR}/${OWNER_BEARER}`)).toBe("creator");
    const recipientHtml = renderToStaticMarkup(<App pathname={recipientPath} />);
    expect(recipientHtml).toContain("Reveal secret once");
    expect(recipientHtml).toContain('id="reveal-risk"');
    expect(recipientHtml).toContain('aria-describedby="reveal-risk"');
    expect(recipientHtml).toContain(
      "before delivery to this browser is confirmed. Keep this page open while it completes"
    );
    const ownerHtml = renderToStaticMarkup(<App pathname={ownerPath} />);
    expect(ownerHtml).toContain("Anonymous secret status");
    expect(ownerHtml).not.toContain("Reveal secret once");
  });

  it("uses no persistent browser storage, automatic clipboard write, telemetry, or service worker", async () => {
    const sources = await Promise.all(
      [
        "App.tsx",
        "access-code.ts",
        "secret-api.ts",
        "turnstile-challenge.ts",
        "zero-knowledge.ts",
        "main.tsx"
      ].map((file) => readFile(new URL(file, import.meta.url), "utf8"))
    );
    const source = sources.join("\n");
    for (const forbidden of [
      "localStorage",
      "sessionStorage",
      "indexedDB",
      "caches.open",
      "serviceWorker.register",
      "sendBeacon",
      "document.cookie"
    ]) {
      expect(source).not.toContain(forbidden);
    }
    expect(source.match(/clipboard\.writeText/gu)).toHaveLength(1);
    expect(source).toContain("onCopy={() => void copyUrl");
    expect(source).toContain('target="_blank"');
    expect(source).toContain('rel="noopener noreferrer"');
  });

  it("keeps lifecycle invalidation guards around asynchronous sensitive-state continuations", async () => {
    const source = await readFile(new URL("App.tsx", import.meta.url), "utf8");
    expect(source.match(/addEventListener\("pagehide"/gu)).toHaveLength(2);
    expect(source.match(/addEventListener\("pageshow"/gu)).toHaveLength(2);
    expect(source.match(/event\.persisted/gu)).toHaveLength(2);
    expect(source.match(/pageHiddenRef\.current/gu)?.length).toBeGreaterThanOrEqual(12);
    expect(source).toContain("clearPendingSecret(pendingRef.current)");
    expect(source).toContain("keyRef.current?.fill(0)");
    expect(source).toContain('window.history.replaceState(null, "", window.location.pathname)');
    expect(source).toContain("pending.recoveryDeadlineMonotonicMs - performance.now()");
    expect(source).not.toContain("Date.now()");
    expect(source).toContain("flushSync(() =>");
  });
});
