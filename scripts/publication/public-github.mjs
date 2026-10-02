import { assert, SHA, safePath } from "./contract.mjs";

export const PUBLIC = "mistyislesoftware/onceurl-public";
export const ACTIONS_APP_ID = 15368;
export function githubClient(token, transport = fetch) {
  return async (method, path, body) => {
    assert(path.startsWith("/") && !path.includes(".."), "Unsafe GitHub API path");
    let response;
    try {
      response = await transport(`https://api.github.com${path}`, {
        method,
        redirect: "error",
        signal: globalThis.AbortSignal.timeout(30_000),
        headers: {
          "Content-Type": "application/json",
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2026-03-10",
          ...(token ? { Authorization: `Bearer ${token}` } : {})
        },
        body: body === undefined ? undefined : JSON.stringify(body)
      });
    } catch {
      throw new Error("GitHub transport failed (credentials and response suppressed)");
    }
    assert(response.ok, `GitHub API prerequisite failed (HTTP ${response.status})`);
    // Never include provider bodies or authentication headers in exceptions/logs.
    try {
      return await response.json();
    } catch {
      throw new Error("Invalid GitHub JSON response");
    }
  };
}
export async function pages(api, path, field) {
  const result = [];
  for (let page = 1; page <= 100; page++) {
    const response = await api(
      "GET",
      `${path}${path.includes("?") ? "&" : "?"}per_page=100&page=${page}`
    );
    const items = field ? response[field] : response;
    assert(Array.isArray(items), "Invalid GitHub collection");
    result.push(...items);
    if (items.length < 100) {
      if (field && response.total_count !== undefined)
        assert(result.length === response.total_count, "Incomplete/changing GitHub pagination");
      return result;
    }
  }
  throw new Error("GitHub pagination limit exceeded");
}
export function verifyRepository(repo, fullName, id, ownerId, privateRepository) {
  assert(
    repo.id === id &&
      repo.full_name === fullName &&
      repo.owner?.login === "mistyislesoftware" &&
      repo.owner.id === ownerId &&
      repo.private === privateRepository &&
      repo.default_branch === "main" &&
      !repo.fork &&
      !repo.archived &&
      !repo.disabled,
    "Wrong repository identity or state"
  );
}
export async function currentMain(api, repository, sha) {
  SHA.parse(sha);
  const branch = await api("GET", `/repos/${repository}/branches/main`);
  assert(
    branch.name === "main" && branch.commit?.sha === sha,
    "Stale canonical source or unexpected public main"
  );
}
export async function verifyCi(
  api,
  repository,
  repositoryId,
  sha,
  workflowPath,
  jobName,
  prNumber
) {
  const runs = await pages(
    api,
    `/repos/${repository}/actions/runs?head_sha=${SHA.parse(sha)}`,
    "workflow_runs"
  );
  const eligible = runs
    .filter(
      (r) =>
        r.path === workflowPath &&
        (prNumber === undefined
          ? r.event === "push" && r.head_branch === "main"
          : r.event === "pull_request" &&
            r.pull_requests?.length === 1 &&
            r.pull_requests[0].number === prNumber &&
            r.pull_requests[0].head?.sha === sha &&
            r.pull_requests[0].head?.repo?.id === repositoryId)
    )
    .sort((a, b) => b.id - a.id);
  const run = eligible[0];
  assert(
    run &&
      run.repository?.id === repositoryId &&
      run.head_sha === sha &&
      run.status === "completed" &&
      run.conclusion === "success",
    "Missing/failing latest required CI"
  );
  const jobs = await pages(
    api,
    `/repos/${repository}/actions/runs/${run.id}/jobs?filter=latest`,
    "jobs"
  );
  assert(
    jobs.length === 1 &&
      jobs[0].name === jobName &&
      jobs[0].head_sha === sha &&
      jobs[0].run_attempt === run.run_attempt &&
      jobs[0].status === "completed" &&
      jobs[0].conclusion === "success",
    "Ambiguous/failing required CI job"
  );
  const job = jobs[0];
  const match = new RegExp(
    `^https://api\\.github\\.com/repos/${repository}/check-runs/([0-9]+)$`,
    "u"
  ).exec(job.check_run_url);
  assert(match, "Wrong CI check repository");
  const check = await api("GET", `/repos/${repository}/check-runs/${match[1]}`);
  assert(
    check.app?.id === ACTIONS_APP_ID &&
      check.name === jobName &&
      check.head_sha === sha &&
      check.status === "completed" &&
      check.conclusion === "success" &&
      check.check_suite?.id === run.check_suite_id,
    "Wrong CI issuer/commit/suite"
  );
  return { runId: run.id, attempt: run.run_attempt, checkId: check.id, jobId: job.id };
}
export async function readPublicCommit(api, sha) {
  SHA.parse(sha);
  const commit = await api("GET", `/repos/${PUBLIC}/git/commits/${sha}`);
  assert(commit.sha === sha && Array.isArray(commit.parents), "Wrong public commit");
  const listing = await api(
    "GET",
    `/repos/${PUBLIC}/git/trees/${SHA.parse(commit.tree?.sha)}?recursive=1`
  );
  assert(
    listing.sha === commit.tree.sha && listing.truncated === false && Array.isArray(listing.tree),
    "Incomplete public Git tree"
  );
  const tree = new Map();
  for (const item of listing.tree) {
    safePath(item.path);
    if (item.type === "tree") {
      assert(item.mode === "040000", "Invalid directory mode");
      continue;
    }
    assert(
      item.type === "blob" && ["100644", "100755"].includes(item.mode) && !tree.has(item.path),
      "Unsafe public Git object/mode"
    );
    const blob = await api("GET", `/repos/${PUBLIC}/git/blobs/${SHA.parse(item.sha)}`);
    assert(
      blob.sha === item.sha &&
        blob.encoding === "base64" &&
        Number.isSafeInteger(blob.size) &&
        blob.size <= 10_000_000,
      "Invalid public blob"
    );
    const encoded = blob.content.replace(/\n/gu, "");
    const bytes = Buffer.from(encoded, "base64");
    assert(
      bytes.toString("base64") === encoded && bytes.length === blob.size && blob.size === item.size,
      "Invalid public blob encoding/size"
    );
    tree.set(item.path, { mode: item.mode, bytes });
  }
  assert(
    new Set([...tree.keys()].map((p) => p.toLowerCase())).size === tree.size,
    "Case collision in public tree"
  );
  return { tree, commit };
}
