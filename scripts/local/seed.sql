BEGIN TRANSACTION;

DELETE FROM capabilities
WHERE id IN ('local-synthetic-alpha', 'local-synthetic-beta');

INSERT INTO capabilities (
  id,
  workspace_id,
  created_by_user_id,
  kind,
  state,
  routing_locator,
  public_alias,
  policy_json,
  expires_at,
  consumed_at,
  disabled_at,
  deleted_at,
  created_at,
  updated_at,
  version
) VALUES
  (
    'local-synthetic-alpha',
    NULL,
    NULL,
    'secret',
    'ACTIVE',
    'loc1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    NULL,
    '{"label":"Synthetic alpha","synthetic":true}',
    1893456000000,
    NULL,
    NULL,
    NULL,
    1704067200000,
    1704067200000,
    1
  ),
  (
    'local-synthetic-beta',
    NULL,
    NULL,
    'secret',
    'EXPIRED',
    'loc1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    NULL,
    '{"label":"Synthetic beta","synthetic":true}',
    1704153600000,
    NULL,
    NULL,
    NULL,
    1704067200000,
    1704153600000,
    1
  );

INSERT INTO capability_counters (
  capability_id,
  view_count,
  consumption_count,
  download_count,
  upload_count,
  click_count,
  updated_at
) VALUES
  ('local-synthetic-alpha', 2, 0, 0, 0, 0, 1704067200000),
  ('local-synthetic-beta', 1, 0, 0, 0, 0, 1704153600000);

COMMIT;
