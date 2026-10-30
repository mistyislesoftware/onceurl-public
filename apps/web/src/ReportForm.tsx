import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  challengeIsVerified,
  challengeUrl,
  requestChallenge,
  type ChallengeTicket
} from "./turnstile-challenge";

export function ReportForm() {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("other");
  const [note, setNote] = useState("");
  const [nonce, setNonce] = useState<string | null>(null);
  const [ticket, setTicket] = useState<ChallengeTicket | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const pageHidden = useRef(false);
  const bytes = new TextEncoder().encode(note).byteLength;
  useEffect(() => {
    const clear = () => {
      pageHidden.current = true;
      setNote("");
      setNonce(null);
      setTicket(null);
      setOpen(false);
      setMessage(null);
    };
    window.addEventListener("pagehide", clear);
    const show = () => {
      pageHidden.current = false;
    };
    window.addEventListener("pageshow", show);
    return () => {
      pageHidden.current = true;
      window.removeEventListener("pagehide", clear);
      window.removeEventListener("pageshow", show);
    };
  }, []);
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy || bytes > 1024) return;
    setBusy(true);
    setMessage(null);
    try {
      if (ticket === null || nonce === null) {
        const match = /^\/s\/(loc1_[0-9a-f]{48})\/(pub1_[A-Za-z0-9_-]{43})$/u.exec(
          window.location.pathname
        );
        if (match === null) throw new Error();
        const response = await fetch("/api/v1/reports/nonce", {
          method: "POST",
          cache: "no-store",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ locator: match[1], public_bearer: match[2] })
        });
        const result: unknown = await response.json();
        if (pageHidden.current) return;
        if (
          !response.ok ||
          typeof result !== "object" ||
          result === null ||
          !("nonce" in result) ||
          typeof result.nonce !== "string" ||
          !/^rpt1_[A-Za-z0-9_-]{43}$/u.test(result.nonce)
        )
          throw new Error();
        const challenge = await requestChallenge("onceurl_report_submit");
        if (pageHidden.current) return;
        setNonce(result.nonce);
        setTicket(challenge);
        setMessage("Complete the separate security check, then send this report.");
      } else {
        const verified = await challengeIsVerified(ticket);
        if (pageHidden.current) return;
        if (!verified) {
          setMessage("Complete the security check first.");
          return;
        }
        const response = await fetch("/api/v1/reports", {
          method: "POST",
          cache: "no-store",
          headers: { "content-type": "application/json", "X-OnceURL-Challenge": ticket.id },
          body: JSON.stringify({ nonce, reason, ...(note === "" ? {} : { note }) })
        });
        const result: unknown = await response.json();
        if (pageHidden.current) return;
        if (
          !response.ok ||
          typeof result !== "object" ||
          result === null ||
          !("acknowledged" in result) ||
          result.acknowledged !== true
        )
          throw new Error();
        setMessage(
          "Thank you. The report has been acknowledged. Reports do not automatically change a link."
        );
        setNote("");
        setNonce(null);
        setTicket(null);
        setOpen(false);
      }
    } catch {
      if (pageHidden.current) return;
      setNonce(null);
      setTicket(null);
      setMessage(
        "The report is unavailable or its outcome is unknown. You may begin a new security check."
      );
    } finally {
      setBusy(false);
    }
  }
  return (
    <section aria-label="Report abuse">
      {!open ? (
        <button type="button" className="button button-secondary" onClick={() => setOpen(true)}>
          Report abuse
        </button>
      ) : (
        <form onSubmit={(event) => void submit(event)}>
          <h2>Report abuse</h2>
          <p>
            Do not include the secret, access code, link or personal information. Notes are removed
            within 30 days.
          </p>
          <label htmlFor="report-reason">Reason</label>
          <select
            id="report-reason"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            disabled={busy}
          >
            <option value="phishing">Phishing</option>
            <option value="malware">Malware</option>
            <option value="harassment">Harassment</option>
            <option value="spam">Spam</option>
            <option value="other">Other</option>
          </select>
          <label htmlFor="report-note">Optional note</label>
          <textarea
            id="report-note"
            value={note}
            onChange={(event) => setNote(event.target.value)}
            maxLength={1024}
            aria-describedby="report-note-count"
            aria-invalid={bytes > 1024}
            disabled={busy}
          />
          <p id="report-note-count">{bytes}/1024 UTF-8 bytes</p>
          {ticket !== null ? (
            <a href={challengeUrl(ticket)} target="_blank" rel="noopener noreferrer">
              Open report security check
            </a>
          ) : null}
          <button type="submit" className="button" disabled={busy || bytes > 1024}>
            {ticket === null ? "Begin report security check" : "Send report"}
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => {
              setOpen(false);
              setNote("");
              setNonce(null);
              setTicket(null);
            }}
          >
            Cancel report
          </button>
        </form>
      )}
      {message !== null ? <p role="status">{message}</p> : null}
    </section>
  );
}
