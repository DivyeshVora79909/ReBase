-- REBASE_STORAGE_BUCKET supplies the shared physical bucket for every context.
CREATE file_storage_config:b2_prod SET
  owned_by = groups:root,
  endpoint = 'https://s3.example.invalid',
  region = 'YOUR_REGION',
  access_key_id = 'YOUR_ACCESS_KEY_ID',
  secret_access_key = 'YOUR_SECRET_ACCESS_KEY',
  default_expiry_seconds = 3600;

-- The file entity owns one deterministic object key and its current access grant.
LET $file = CREATE ONLY test_attachment SET
  owned_by = groups:root,
  storage_config = file_storage_config:b2_prod,
  attached_to = test_primitive:attachment_target,
  file_name = 'empty.txt',
  media_type = 'text/plain',
  byte_length_limit = 0,
  access_duration = 3600;

-- Razorpay credentials are strict tenant configuration, never runtime environment fallbacks.
-- Replace the placeholders below with the values held by the tenant's authorized config workflow.
CREATE razorpay_config:primary SET
  owned_by = groups:root,
  label = 'Razorpay Test',
  key_id = 'rzp_test_example',
  key_secret = 'example-secret',
  webhook_secret = 'example-webhook-secret';

CREATE razorpay_order SET
  owned_by = groups:root,
  config = razorpay_config:primary,
  amount_paise = 100,
  currency = 'INR';
SELECT 
  id, 
  access_url, 
  access_expires_at
FROM test_attachment
ORDER BY id DESC
LIMIT 1;

CREATE email_brevo_config:prod SET
  owned_by = groups:root,
  label = 'Brevo Production',
  from_email = 'sender@example.com',
  from_name = 'Example Sender',
  api_key = 'YOUR_BREVO_API_KEY';

CREATE send_brevo_email SET owned_by = groups:root, config = email_brevo_config:prod, to = ['recipient@example.com'], subject = 'Live Test', text = 'Hello from ReBase!';
SELECT 
  id, 
  to, 
  rebase_status, 
  rebase_outcome, 
  provider_reference 
  FROM send_brevo_email 
  ORDER BY id DESC 
  LIMIT 1;

-- UTC cron schedule: every minute, repeat twice, coalesce misfires
CREATE send_brevo_email SET 
  owned_by = groups:root, 
  config = email_brevo_config:prod, 
  to = ['recipient@example.com'],
  subject = 'Cron Test: Automated Email', 
  text = 'This email was triggered automatically by the ReBase cron scheduler.',
  schedule = {
    cron: '* * * * *',
    repeat: 2,
    misfire: 'coalesce'
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
