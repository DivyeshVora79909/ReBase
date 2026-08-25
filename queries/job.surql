CREATE file_storage_config:b2_prod SET
  owned_by = groups:root,
  bucket = 'myapp-dev-2026-xyz123',
  endpoint = 'https://s3.us-east-005.backblazeb2.com',
  region = 'us-east-005',
  access_key_id = '005cde60571247f0000000001',
  secret_access_key = 'K0XXXXXXXXXXXXXXXXX',
  default_expiry_seconds = 3600;

CREATE file_access_grant SET owned_by = groups:root, storage_config = file_storage_config:b2_prod, object_key = 'test.txt', expires_in = 3600;
SELECT 
  id, 
  access_url, 
  expires_at 
  FROM file_access_grant 
  ORDER BY id DESC 
  LIMIT 1;

CREATE email_brevo_config:prod SET
  owned_by = groups:root,
  label = 'Brevo Production',
  from_email = 'divy.r.vora14@gmail.com',
  from_name = 'Divyesh Vora',
  api_key = 'xkeysib-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
  provider_account_id = 'primary';

CREATE send_brevo_email SET owned_by = groups:root, config = email_brevo_config:prod, to = ['divyeshvora.21.ce@iite.indusuni.ac.in'], subject = 'Live Test', text = 'Hello from ReBase!';
SELECT 
  id, 
  to, 
  rebase_status, 
  rebase_outcome, 
  provider_reference 
  FROM send_brevo_email 
  ORDER BY id DESC 
  LIMIT 1;

CREATE send_brevo_email SET 
  owned_by = groups:root, 
  config = email_brevo_config:prod, 
  to = ['divyeshvora.21.ce@iite.indusuni.ac.in'], 
  subject = 'Cron Test: Automated Email', 
  text = 'This email was triggered automatically by the ReBase cron scheduler.',
  schedule = {
    cron: '* * * * *',      -- Standard 5-field UTC cron (every minute)
    repeat: 2,              -- Run exactly 2 times then finish
    misfire: 'coalesce'     -- If server was down, execute once on recovery
  };

SELECT 
  id, 
  subject, 
  schedule, 
  rebase_schedule_index, 
  rebase_schedule_next_at, 
  rebase_schedule_finished_at, 
  rebase_outcome 
FROM send_brevo_email 
WHERE schedule != NONE;

SELECT 
  id, 
  to, 
  rebase_status, 
  rebase_outcome, 
  provider_reference, 
  created_at 
FROM send_brevo_email 
WHERE schedule = NONE AND subject = 'Cron Test: Automated Email' 
ORDER BY created_at DESC;

-- Force the scheduler to consider the job immediately due
UPDATE send_brevo_email 
SET rebase_schedule_next_at = time::now() - 1s 
WHERE schedule != NONE AND rebase_schedule_finished_at = NONE;