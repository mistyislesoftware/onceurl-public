import { useEffect, useRef, useState, type FormEvent } from "react";
import { flushSync } from "react-dom";
import {
  clearPendingSecret,
  CreationRequestError,
  isCompletionRecoveryExpired,
  SECRET_EXPIRY_OPTIONS,
  prepareEncryptedSecret,
  submitEncryptedSecret,
  type CompletedSecretCreation,
  type PendingSecretCreation,
  type SecretExpirySeconds
} from "./secret-api";
import {
  MAX_PLAINTEXT_BYTES,
  SecretDecryptionError,
  countUtf8Bytes,
  decryptSecret,
  encodeBase64url,
  parseFragmentKey
} from "./zero-knowledge";
import { ACCESS_CODE_MAX_BYTES } from "./access-code";
import {
  accessCodeChallengeFromDetails,
  challengeIsVerified,
  challengeUrl,
  requestChallenge,
  type ChallengeTicket
} from "./turnstile-challenge";

type AppRoute = "creator" | "recipient" | "owner";

interface CapabilityMetadata {
  readonly kind: "secret";
  readonly state: string;
  readonly created_at: string;
  readonly expires_at: string | null;
  readonly is_available: boolean;
  readonly policy: { readonly max_consumptions: 1 };
  readonly access_code_required: boolean;
  readonly events?: readonly { readonly type: string; readonly occurred_at: string }[];
}

export function routeForPathname(pathname: string): AppRoute {
  if (/^\/s\/loc1_[0-9a-f]{48}\/pub1_[A-Za-z0-9_-]{43}$/u.test(pathname)) {
    return "recipient";
  }
  if (/^\/m\/loc1_[0-9a-f]{48}\/own1_[A-Za-z0-9_-]{43}$/u.test(pathname)) {
    return "owner";
  }
  return "creator";
}

export function App({ pathname }: { readonly pathname?: string }) {
  const currentPathname =
    pathname ?? (typeof window === "undefined" ? "/" : window.location.pathname);
  switch (routeForPathname(currentPathname)) {
    case "recipient":
      return <RecipientPage />;
    case "owner":
      return <OwnerPage />;
    case "creator":
      return <CreatorPage />;
  }
}

function CreatorPage() {
  const [secret, setSecret] = useState("");
  const [accessCode, setAccessCode] = useState("");
  const [expiry, setExpiry] = useState<SecretExpirySeconds>(86_400);
  const [phase, setPhase] = useState<
    "idle" | "challenging" | "encrypting" | "submitting" | "uncertain" | "retrying" | "closed"
  >("idle");
  const [error, setError] = useState<string | null>(null);
  const [completed, setCompleted] = useState<CompletedSecretCreation | null>(null);
  const [copied, setCopied] = useState<"recipient" | "owner" | null>(null);
  const [recoveryWindowExpired, setRecoveryWindowExpired] = useState(false);
  const pendingRef = useRef<PendingSecretCreation | null>(null);
  const creatorInputRef = useRef<{
    readonly secret: string;
    readonly expiry: SecretExpirySeconds;
    readonly accessCode?: string;
  } | null>(null);
  const [challengeTicket, setChallengeTicket] = useState<ChallengeTicket | null>(null);
  const pageHiddenRef = useRef(false);
  const byteCount = countUtf8Bytes(secret);
  const accessCodeByteCount = countUtf8Bytes(accessCode);
  const validPlaintext =
    byteCount >= 1 &&
    byteCount <= MAX_PLAINTEXT_BYTES &&
    accessCodeByteCount <= ACCESS_CODE_MAX_BYTES;

  useEffect(() => {
    const pageHide = () => {
      pageHiddenRef.current = true;
      clearPendingSecret(pendingRef.current);
      pendingRef.current = null;
      creatorInputRef.current = null;
      flushSync(() => {
        setSecret("");
        setAccessCode("");
        setChallengeTicket(null);
        setCompleted(null);
        setCopied(null);
        setError(null);
        setPhase("closed");
      });
    };
    const pageShow = (event: PageTransitionEvent) => {
      if (event.persisted) {
        window.location.reload();
      }
    };
    window.addEventListener("pagehide", pageHide);
    window.addEventListener("pageshow", pageShow);
    return () => {
      window.removeEventListener("pagehide", pageHide);
      window.removeEventListener("pageshow", pageShow);
      clearPendingSecret(pendingRef.current);
      pendingRef.current = null;
      creatorInputRef.current = null;
    };
  }, []);

  useEffect(() => {
    const pending = pendingRef.current;
    if (phase !== "uncertain" || pending === null) {
      return;
    }
    if (isCompletionRecoveryExpired(pending)) {
      setRecoveryWindowExpired(true);
      return;
    }
    setRecoveryWindowExpired(false);
    const delay = pending.recoveryDeadlineMonotonicMs - performance.now() + 1;
    const timeout = window.setTimeout(() => setRecoveryWindowExpired(true), delay);
    return () => window.clearTimeout(timeout);
  }, [phase]);

  useEffect(() => {
    if (phase !== "challenging" || challengeTicket === null) return;
    let active = true;
    let timeout: number | undefined;
    const poll = async () => {
      try {
        if (await challengeIsVerified(challengeTicket)) {
          const input = creatorInputRef.current;
          if (!active || pageHiddenRef.current || input === null) return;
          setChallengeTicket(null);
          setPhase("encrypting");
          const pending = await prepareEncryptedSecret(input.secret, input.expiry, {
            challengeId: challengeTicket.id,
            ...(input.accessCode === undefined ? {} : { accessCode: input.accessCode })
          });
          creatorInputRef.current = null;
          if (pageHiddenRef.current) {
            clearPendingSecret(pending);
            return;
          }
          pendingRef.current = pending;
          setRecoveryWindowExpired(false);
          setSecret("");
          setAccessCode("");
          await submitPending(pending);
          return;
        }
        if (active) timeout = window.setTimeout(() => void poll(), 1_000);
      } catch (cause) {
        if (!active || pageHiddenRef.current) return;
        creatorInputRef.current = null;
        setChallengeTicket(null);
        setError(cause instanceof Error ? cause.message : "The security check is unavailable.");
        setPhase("idle");
      }
    };
    void poll();
    return () => {
      active = false;
      if (timeout !== undefined) window.clearTimeout(timeout);
    };
  }, [challengeTicket, phase]);

  async function submitPending(
    pending: PendingSecretCreation,
    uncertaintyAlreadyKnown = false
  ): Promise<void> {
    if (pageHiddenRef.current) {
      clearPendingSecret(pending);
      return;
    }
    setPhase(uncertaintyAlreadyKnown ? "retrying" : "submitting");
    try {
      const result = await submitEncryptedSecret(pending, window.location.origin, {
        uncertaintyAlreadyKnown
      });
      pendingRef.current = null;
      if (pageHiddenRef.current) {
        return;
      }
      setCompleted(result);
      setError(null);
      setPhase("idle");
    } catch (cause) {
      const latestError =
        cause instanceof CreationRequestError ? cause : new CreationRequestError(true);
      const requestError =
        uncertaintyAlreadyKnown && !latestError.ambiguous
          ? new CreationRequestError(true)
          : latestError;
      if (!requestError.ambiguous || pageHiddenRef.current) {
        clearPendingSecret(pending);
        pendingRef.current = null;
      }
      if (pageHiddenRef.current) {
        return;
      }
      setPhase(requestError.ambiguous ? "uncertain" : "idle");
      setError(requestError.message);
    }
  }

  async function createSecret(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!validPlaintext || phase !== "idle") {
      return;
    }
    setError(null);
    setCompleted(null);
    setPhase("challenging");
    try {
      creatorInputRef.current = {
        secret,
        expiry,
        ...(accessCode === "" ? {} : { accessCode })
      };
      const ticket = await requestChallenge("onceurl_prepare");
      if (pageHiddenRef.current) return;
      setChallengeTicket(ticket);
    } catch (cause) {
      if (pageHiddenRef.current) {
        return;
      }
      const message = cause instanceof Error ? cause.message : "The secret could not be created.";
      creatorInputRef.current = null;
      setError(message);
      setPhase("idle");
    }
  }

  if (phase === "closed") {
    return (
      <PageShell eyebrow="Sensitive values cleared" title="This creation page is closed">
        <p role="status">
          Plaintext, pending key material, and completed URLs were cleared when this page was left.
          Reload to start again.
        </p>
      </PageShell>
    );
  }

  if ((phase === "uncertain" || phase === "retrying") && pendingRef.current !== null) {
    const recoveryExpired =
      recoveryWindowExpired || isCompletionRecoveryExpired(pendingRef.current);
    return (
      <PageShell eyebrow="Encrypted request retained" title="Creation outcome unknown">
        <div className="notice notice-warning" role="alert">
          <p>
            A completion attempt may already have committed, but this browser did not receive a
            validated success response. A later error cannot prove that the capability was not
            created.
          </p>
          {phase === "retrying" ? (
            <p role="status">Retrying the exact same encrypted request…</p>
          ) : recoveryExpired ? (
            <>
              <p>
                The authenticated completion recovery interval has ended. The original outcome
                remains unknown, and another completion retry is no longer offered.
              </p>
              <p>
                Do not create a replacement unless you deliberately accept that an orphaned
                duplicate capability may already exist. Leaving or reloading clears the retained
                browser key without resolving the outcome.
              </p>
            </>
          ) : (
            <>
              <p>{error}</p>
              <p>Keep this tab open and do not create a replacement.</p>
              <button
                className="button button-secondary"
                type="button"
                onClick={() => {
                  const pending = pendingRef.current;
                  if (pending !== null) {
                    void submitPending(pending, true);
                  }
                }}
              >
                Retry the same encrypted request
              </button>
            </>
          )}
        </div>
      </PageShell>
    );
  }

  async function copyUrl(kind: "recipient" | "owner", value: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(value);
      if (pageHiddenRef.current) {
        return;
      }
      setCopied(kind);
      setError(null);
    } catch {
      if (pageHiddenRef.current) {
        return;
      }
      setError("Copy was blocked by the browser. Select the URL and copy it manually.");
    }
  }

  if (completed !== null) {
    return (
      <PageShell eyebrow="Secret created" title="Save both URLs before you leave">
        <div className="notice notice-success" role="status">
          The plaintext was encrypted in this browser. OnceURL received only ciphertext.
        </div>
        <UrlCard
          heading="Recipient URL"
          description="Share this complete URL. Its fragment contains the browser-only decryption key. Without the full URL, the secret cannot be recovered."
          value={completed.recipientUrl}
          copied={copied === "recipient"}
          onCopy={() => void copyUrl("recipient", completed.recipientUrl)}
        />
        <UrlCard
          heading="Owner management URL"
          description="Keep this separate. It can inspect status, but it cannot reveal or decrypt the secret."
          value={completed.ownerUrl}
          copied={copied === "owner"}
          onCopy={() => void copyUrl("owner", completed.ownerUrl)}
        />
        {error !== null ? (
          <p className="field-error" role="alert">
            {error}
          </p>
        ) : null}
        <p className="fine-print">
          Expires {formatDate(completed.expiresAt)}. URLs are shown once and were not copied
          automatically.
        </p>
        <button
          className="button button-secondary"
          type="button"
          onClick={() => {
            setCompleted(null);
            setCopied(null);
          }}
        >
          Clear these URLs
        </button>
      </PageShell>
    );
  }

  return (
    <PageShell eyebrow="Zero-knowledge secret" title="Share text for one explicit reveal">
      <p className="lede">
        Encryption happens here with Web Crypto. The server never receives the plaintext or AES key,
        and a passive page visit never consumes the secret.
      </p>
      <form className="panel form-stack" onSubmit={(event) => void createSecret(event)}>
        <label htmlFor="secret-text">Secret text</label>
        <textarea
          id="secret-text"
          name="secret"
          rows={9}
          value={secret}
          onChange={(event) => setSecret(event.target.value)}
          aria-describedby="secret-count secret-help"
          aria-invalid={byteCount > MAX_PLAINTEXT_BYTES}
          autoComplete="off"
          spellCheck={false}
        />
        <div
          id="secret-count"
          className={byteCount > MAX_PLAINTEXT_BYTES ? "field-error" : "counter"}
        >
          {byteCount.toLocaleString()} / {MAX_PLAINTEXT_BYTES.toLocaleString()} UTF-8 bytes
        </div>
        <p id="secret-help" className="fine-print">
          Text is not normalized. It is kept only in this tab until local encryption finishes.
        </p>
        <label htmlFor="access-code">Access code (optional)</label>
        <input
          id="access-code"
          name="access-code"
          type="password"
          value={accessCode}
          onChange={(event) => setAccessCode(event.target.value)}
          aria-describedby="access-code-help"
          aria-invalid={accessCodeByteCount > ACCESS_CODE_MAX_BYTES}
          autoComplete="new-password"
        />
        <p
          id="access-code-help"
          className={accessCodeByteCount > ACCESS_CODE_MAX_BYTES ? "field-error" : "fine-print"}
        >
          Optional, up to {ACCESS_CODE_MAX_BYTES} UTF-8 bytes. Only a browser-derived verifier is
          sent. Ten incorrect attempts place the capability in a protective lock; an unresolved lock
          may be deleted after 72 hours or at expiry and does not prove abuse.
        </p>
        <label htmlFor="expiry">Expiry</label>
        <select
          id="expiry"
          value={expiry}
          onChange={(event) => setExpiry(Number(event.target.value) as SecretExpirySeconds)}
        >
          {SECRET_EXPIRY_OPTIONS.map((seconds) => (
            <option key={seconds} value={seconds}>
              {expiryLabel(seconds)}
            </option>
          ))}
        </select>
        <div className="notice">
          One explicit claim permanently consumes the ciphertext. A lost response or failed local
          decryption cannot safely reopen it.
        </div>
        {phase === "challenging" && challengeTicket !== null ? (
          <div className="notice" role="status">
            <p>Complete the security check in its isolated page, then return here.</p>
            <a
              className="button button-secondary"
              href={challengeUrl(challengeTicket)}
              target="_blank"
              rel="noopener noreferrer"
            >
              Open security check
            </a>
          </div>
        ) : null}
        <button className="button" type="submit" disabled={!validPlaintext || phase !== "idle"}>
          {phase === "challenging"
            ? "Waiting for security check…"
            : phase === "encrypting"
              ? "Encrypting in this browser…"
              : phase === "submitting"
                ? "Storing ciphertext…"
                : "Create one-time secret"}
        </button>
      </form>
      {error !== null ? (
        <p className="field-error" role="alert">
          {error}
        </p>
      ) : null}
    </PageShell>
  );
}

function RecipientPage() {
  const [metadata, setMetadata] = useState<CapabilityMetadata | null>(null);
  const [metadataError, setMetadataError] = useState(false);
  const [phase, setPhase] = useState<
    "ready" | "claiming" | "challenging" | "revealed" | "failed" | "closed"
  >("ready");
  const [plaintext, setPlaintext] = useState("");
  const [accessCode, setAccessCode] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [challengeTicket, setChallengeTicket] = useState<ChallengeTicket | null>(null);
  const [fragmentReady, setFragmentReady] = useState(
    () => typeof window !== "undefined" && isValidFragment(window.location.hash)
  );
  const claimStarted = useRef(false);
  const keyRef = useRef<Uint8Array | null>(null);
  const resultRef = useRef<HTMLElement | null>(null);
  const pageHiddenRef = useRef(false);
  const accessCodeByteCount = countUtf8Bytes(accessCode);

  useEffect(() => {
    let active = true;
    void loadCapabilityMetadata(window.location.pathname).then(
      (value) => active && !pageHiddenRef.current && setMetadata(value),
      () => active && !pageHiddenRef.current && setMetadataError(true)
    );
    return () => {
      active = false;
      keyRef.current?.fill(0);
      keyRef.current = null;
    };
  }, []);

  useEffect(() => {
    const pageHide = () => {
      pageHiddenRef.current = true;
      claimStarted.current = true;
      keyRef.current?.fill(0);
      keyRef.current = null;
      if (window.location.hash !== "") {
        window.history.replaceState(null, "", window.location.pathname);
      }
      flushSync(() => {
        setMetadata(null);
        setMetadataError(false);
        setPlaintext("");
        setAccessCode("");
        setMessage(null);
        setChallengeTicket(null);
        setFragmentReady(false);
        setPhase("closed");
      });
    };
    const pageShow = (event: PageTransitionEvent) => {
      if (event.persisted) {
        window.location.reload();
      }
    };
    window.addEventListener("pagehide", pageHide);
    window.addEventListener("pageshow", pageShow);
    return () => {
      window.removeEventListener("pagehide", pageHide);
      window.removeEventListener("pageshow", pageShow);
    };
  }, []);

  useEffect(() => {
    if (phase === "revealed") {
      resultRef.current?.focus();
    }
  }, [phase]);

  useEffect(() => {
    if (phase !== "challenging" || challengeTicket === null) return;
    let active = true;
    let timeout: number | undefined;
    const poll = async () => {
      try {
        if (await challengeIsVerified(challengeTicket)) {
          if (!active || pageHiddenRef.current) return;
          claimStarted.current = false;
          setAccessCode("");
          setMessage("Security check complete. Re-enter the access code and reveal again.");
          setPhase("ready");
          return;
        }
        if (active) timeout = window.setTimeout(() => void poll(), 1_000);
      } catch (cause) {
        if (!active || pageHiddenRef.current) return;
        claimStarted.current = false;
        setChallengeTicket(null);
        setMessage(cause instanceof Error ? cause.message : "The security check is unavailable.");
        setPhase("ready");
      }
    };
    void poll();
    return () => {
      active = false;
      if (timeout !== undefined) window.clearTimeout(timeout);
    };
  }, [challengeTicket, phase]);

  async function reveal(): Promise<void> {
    if (
      claimStarted.current ||
      !fragmentReady ||
      metadata?.is_available !== true ||
      (metadata.access_code_required &&
        (accessCodeByteCount < 1 || accessCodeByteCount > ACCESS_CODE_MAX_BYTES))
    ) {
      return;
    }
    claimStarted.current = true;
    setMessage(null);
    setPhase("claiming");
    try {
      if (keyRef.current === null) {
        keyRef.current = parseFragmentKey(window.location.hash);
        window.history.replaceState(null, "", window.location.pathname);
      }
      const response = await fetch(`${window.location.pathname}/claim`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          operation_id: randomOperationValue("reveal"),
          nonce: randomOperationValue("nonce"),
          ...(metadata.access_code_required ? { access_code: accessCode } : {}),
          ...(challengeTicket === null ? {} : { challenge_id: challengeTicket.id })
        })
      });
      if (!response.ok) {
        const failure = await readApiFailure(response);
        if (failure.code === "verification_required") {
          const ticket = accessCodeChallengeFromDetails(failure.details);
          setAccessCode("");
          if (ticket === null) {
            setChallengeTicket(null);
            setMessage("The security check is unavailable.");
            setPhase("ready");
          } else {
            setChallengeTicket(ticket);
            setMessage("Complete the separate security check before another code attempt.");
            setPhase("challenging");
          }
          claimStarted.current = false;
          return;
        }
        if (failure.code === "verification_failed") {
          claimStarted.current = false;
          setChallengeTicket(null);
          setAccessCode("");
          setMessage("The access code or security check was not accepted. Try again.");
          setPhase("ready");
          return;
        }
        if (failure.code === "rate_limited") {
          claimStarted.current = false;
          setChallengeTicket(null);
          setMessage(
            `Too many attempts. Wait ${failure.retryAfter ?? 1} seconds before trying again.`
          );
          setPhase("ready");
          return;
        }
        if (failure.code === "capability_unavailable") {
          throw new CapabilityUnavailableError();
        }
        throw new SecretDecryptionError();
      }
      const body: unknown = await response.json();
      if (!isRecord(body) || body.outcome !== "released" || !("ciphertext_envelope" in body)) {
        throw new SecretDecryptionError();
      }
      const revealed = await decryptSecret(body.ciphertext_envelope, keyRef.current);
      keyRef.current.fill(0);
      keyRef.current = null;
      if (pageHiddenRef.current) {
        return;
      }
      setPlaintext(revealed);
      setAccessCode("");
      setChallengeTicket(null);
      setFragmentReady(false);
      setPhase("revealed");
    } catch (cause) {
      keyRef.current?.fill(0);
      keyRef.current = null;
      if (pageHiddenRef.current) {
        return;
      }
      setAccessCode("");
      setChallengeTicket(null);
      setFragmentReady(false);
      setMessage(
        cause instanceof CapabilityUnavailableError
          ? "This capability is unavailable. No retry was sent."
          : "The claim result is uncertain or decryption failed; retrying could not safely reopen it."
      );
      setPhase("failed");
    }
  }

  function closeSecret(): void {
    keyRef.current?.fill(0);
    keyRef.current = null;
    setPlaintext("");
    setAccessCode("");
    setMessage(null);
    setChallengeTicket(null);
    setFragmentReady(false);
    setPhase("closed");
  }

  return (
    <PageShell eyebrow="One-time secret" title="Reveal is a final action">
      <p className="lede">
        Opening this page did not consume the secret. Reveal only when you are ready to read and
        securely handle it.
      </p>
      {metadataError ? (
        <UnavailableNotice />
      ) : metadata === null ? (
        <p role="status">Checking availability…</p>
      ) : null}
      {metadata !== null && !metadata.is_available ? <UnavailableNotice /> : null}
      {phase === "ready" && !fragmentReady ? (
        <div className="notice notice-warning" role="alert">
          The browser-only decryption key is missing or invalid. Reveal is disabled, and no claim
          was sent.
        </div>
      ) : null}
      {metadata?.access_code_required && (phase === "ready" || phase === "claiming") ? (
        <>
          <label htmlFor="recipient-access-code">Access code</label>
          <input
            id="recipient-access-code"
            type="password"
            value={accessCode}
            onChange={(event) => setAccessCode(event.target.value)}
            autoComplete="current-password"
            aria-describedby="recipient-access-code-help"
            aria-invalid={accessCodeByteCount > ACCESS_CODE_MAX_BYTES}
          />
          <p id="recipient-access-code-help" className="fine-print">
            Enter the code shared separately by the creator. Incorrect attempts trigger increasing
            delays and, after three failures, a separate security check.
          </p>
        </>
      ) : null}
      {phase === "challenging" && challengeTicket !== null ? (
        <div className="notice" role="status">
          <p>{message}</p>
          <a
            className="button button-secondary"
            href={challengeUrl(challengeTicket)}
            target="_blank"
            rel="noopener noreferrer"
          >
            Open security check
          </a>
        </div>
      ) : null}
      {phase === "ready" && message !== null ? (
        <p className="notice notice-warning" role="status">
          {message}
        </p>
      ) : null}
      {phase === "ready" || phase === "claiming" ? (
        <>
          <p id="reveal-risk" className="notice notice-warning">
            Revealing permanently consumes this secret on the server before delivery to this browser
            is confirmed. Keep this page open while it completes. If the connection is interrupted,
            or you reload or leave during reveal, the secret may become permanently unavailable.
          </p>
          <button
            className="button"
            type="button"
            aria-describedby="reveal-risk"
            disabled={
              !fragmentReady ||
              metadata?.is_available !== true ||
              phase === "claiming" ||
              (metadata?.access_code_required === true &&
                (accessCodeByteCount < 1 || accessCodeByteCount > ACCESS_CODE_MAX_BYTES))
            }
            onClick={() => void reveal()}
          >
            {phase === "claiming" ? "Claiming and decrypting…" : "Reveal secret once"}
          </button>
        </>
      ) : null}
      {phase === "revealed" ? (
        <section
          ref={resultRef}
          className="panel secret-result"
          aria-labelledby="revealed-heading"
          tabIndex={-1}
        >
          <h2 id="revealed-heading">Revealed secret</h2>
          <pre>{plaintext}</pre>
          <button className="button button-secondary" type="button" onClick={closeSecret}>
            Clear and close
          </button>
        </section>
      ) : null}
      {phase === "failed" ? (
        <div className="notice notice-warning" role="alert">
          {message}
        </div>
      ) : null}
      {phase === "closed" ? (
        <p role="status">The displayed plaintext and in-memory key reference were cleared.</p>
      ) : null}
    </PageShell>
  );
}

function OwnerPage() {
  const [metadata, setMetadata] = useState<CapabilityMetadata | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let active = true;
    void loadCapabilityMetadata(window.location.pathname).then(
      (value) => active && setMetadata(value),
      () => active && setFailed(true)
    );
    return () => {
      active = false;
    };
  }, []);

  return (
    <PageShell eyebrow="Owner authority" title="Anonymous secret status">
      <p className="lede">
        This URL can inspect coarse lifecycle information. It cannot reveal or decrypt the
        recipient's secret.
      </p>
      {failed ? (
        <UnavailableNotice />
      ) : metadata === null ? (
        <p role="status">Loading owner status…</p>
      ) : (
        <>
          <dl className="panel status-grid">
            <div>
              <dt>Kind</dt>
              <dd>Zero-knowledge text secret</dd>
            </div>
            <div>
              <dt>Lifecycle</dt>
              <dd>{metadata.state}</dd>
            </div>
            <div>
              <dt>Available</dt>
              <dd>{metadata.is_available ? "Yes" : "No"}</dd>
            </div>
            <div>
              <dt>Created</dt>
              <dd>{formatDate(metadata.created_at)}</dd>
            </div>
            <div>
              <dt>Expires</dt>
              <dd>{formatDate(metadata.expires_at)}</dd>
            </div>
            <div>
              <dt>Policy</dt>
              <dd>At most {metadata.policy.max_consumptions} explicit reveal</dd>
            </div>
          </dl>
          <section className="panel" aria-labelledby="events-heading">
            <h2 id="events-heading">Coarse events</h2>
            <ol className="event-list">
              {(metadata.events ?? []).map((event) => (
                <li key={`${event.type}-${event.occurred_at}`}>
                  <span>{eventLabel(event.type)}</span>
                  <time dateTime={event.occurred_at}>{formatDate(event.occurred_at)}</time>
                </li>
              ))}
            </ol>
          </section>
          <p className="fine-print">
            No recipient identity, IP address, user agent, device fingerprint, operation ID, nonce,
            ciphertext, plaintext, or key is shown.
          </p>
        </>
      )}
    </PageShell>
  );
}

function PageShell({
  eyebrow,
  title,
  children
}: {
  readonly eyebrow: string;
  readonly title: string;
  readonly children: React.ReactNode;
}) {
  return (
    <main className="app-shell">
      <section className="content-shell">
        <div className="brand" aria-label="OnceURL">
          OnceURL
        </div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        {children}
      </section>
    </main>
  );
}

function UrlCard({
  heading,
  description,
  value,
  copied,
  onCopy
}: {
  readonly heading: string;
  readonly description: string;
  readonly value: string;
  readonly copied: boolean;
  readonly onCopy: () => void;
}) {
  const id = heading.startsWith("Recipient") ? "recipient-url" : "owner-url";
  return (
    <section className="panel url-card" aria-labelledby={`${id}-heading`}>
      <h2 id={`${id}-heading`}>{heading}</h2>
      <p>{description}</p>
      <label htmlFor={id}>Complete {heading.toLowerCase()}</label>
      <textarea id={id} value={value} readOnly rows={3} />
      <button className="button button-secondary" type="button" onClick={onCopy}>
        {copied ? "Copied" : `Copy ${heading.toLowerCase()}`}
      </button>
    </section>
  );
}

function UnavailableNotice() {
  return (
    <div className="notice notice-warning" role="alert">
      This capability is unavailable or the authority URL is not valid.
    </div>
  );
}

async function loadCapabilityMetadata(pathname: string): Promise<CapabilityMetadata> {
  const response = await fetch(pathname, {
    headers: { accept: "application/json" },
    cache: "no-store"
  });
  if (!response.ok) {
    throw new Error("unavailable");
  }
  const body: unknown = await response.json();
  if (!isRecord(body) || !isRecord(body.capability)) {
    throw new Error("unavailable");
  }
  const capability = body.capability;
  const owner = pathname.startsWith("/m/");
  const expectedKeys = [
    "kind",
    "state",
    "created_at",
    "expires_at",
    "is_available",
    "policy",
    "access_code_required",
    ...(owner ? ["events"] : [])
  ];
  if (
    !hasExactKeys(capability, expectedKeys) ||
    capability.kind !== "secret" ||
    typeof capability.state !== "string" ||
    typeof capability.created_at !== "string" ||
    (capability.expires_at !== null && typeof capability.expires_at !== "string") ||
    typeof capability.is_available !== "boolean" ||
    typeof capability.access_code_required !== "boolean" ||
    !isRecord(capability.policy) ||
    !hasExactKeys(capability.policy, ["max_consumptions"]) ||
    capability.policy.max_consumptions !== 1 ||
    (owner &&
      (!Array.isArray(capability.events) ||
        capability.events.length > 64 ||
        capability.events.some(
          (event) =>
            !isRecord(event) ||
            !hasExactKeys(event, ["type", "occurred_at"]) ||
            typeof event.type !== "string" ||
            typeof event.occurred_at !== "string"
        )))
  ) {
    throw new Error("unavailable");
  }
  return capability as unknown as CapabilityMetadata;
}

class CapabilityUnavailableError extends Error {}

async function readApiFailure(response: Response): Promise<{
  readonly code: string;
  readonly retryAfter: number | null;
  readonly details: unknown;
}> {
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  const code =
    isRecord(body) && isRecord(body.error) && typeof body.error.code === "string"
      ? body.error.code
      : "unknown";
  const details = isRecord(body) && isRecord(body.error) ? body.error.details : null;
  const retryHeader = response.headers.get("Retry-After");
  const retryAfter =
    retryHeader !== null && /^[1-9]\d*$/u.test(retryHeader) ? Number(retryHeader) : null;
  return {
    code,
    details,
    retryAfter:
      retryAfter !== null && Number.isSafeInteger(retryAfter) && retryAfter > 0 ? retryAfter : null
  };
}

function randomOperationValue(prefix: string): string {
  const bytes = new Uint8Array(18);
  crypto.getRandomValues(bytes);
  const encoded = encodeBase64url(bytes);
  bytes.fill(0);
  return `${prefix}_${encoded}`;
}

function isValidFragment(fragment: string): boolean {
  try {
    const key = parseFragmentKey(fragment);
    key.fill(0);
    return true;
  } catch {
    return false;
  }
}

function expiryLabel(seconds: SecretExpirySeconds): string {
  return seconds === 3_600
    ? "1 hour"
    : seconds === 86_400
      ? "24 hours"
      : seconds === 604_800
        ? "7 days"
        : "30 days";
}

function eventLabel(type: string): string {
  return type === "created"
    ? "Secret created"
    : type === "consumed"
      ? "Secret consumed"
      : "Lifecycle changed";
}

function formatDate(value: string | null): string {
  if (value === null) {
    return "No expiry";
  }
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(
    new Date(value)
  );
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const candidateKeys = Object.keys(value);
  return candidateKeys.length === keys.length && keys.every((key) => candidateKeys.includes(key));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
