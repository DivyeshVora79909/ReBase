# Twilio Trial SMS Findings

Status: measured provider compatibility finding; trial-only constraints remain
Last verified: 2026-09-02
Provider: Twilio REST API (`2010-04-01`) and the Messaging trial flow
Confidence: high for the configured account and recipient; medium for
account-wide geographic policy because Twilio exposes that setting in Console

This document records observed behavior for the ReBase development account. It
contains no account authentication secret, API key secret, or unmasked
personal phone number. The only content names shown are Twilio's public trial
template identifier and a deliberately generic probe label. Re-run the probes
after an account upgrade, sender change, or Twilio API behavior change.

## Result

The documented request is valid for this account when `Body` is the exact
Twilio trial template name `sms_appointment_reminders`. A request with an
arbitrary body failed before delivery with Twilio error `572006`:

```text
Invalid template name. Trial accounts can only use predefined SMS templates.
```

This is a trial content restriction, not the observed failure of the sender,
credentials, or India route. The exact template request returned a message SID;
the initial message state was `queued`, and a subsequent account message-list
read showed `delivered`. The listed message sender and recipient matched the
configured trial sender and the configured recipient.

## Account and credential probes

Only prefixes/suffixes are recorded here. The current `.env` values were read
without printing their contents.

| Probe | Observation |
| --- | --- |
| Account SID + Auth Token | `GET /Accounts/{account}/Messages.json?PageSize=1` returned HTTP 200. The account is active and `Trial`. |
| API key SID + API key secret | The same read-only Messages request returned HTTP 200. `TWILIO_CLIENT_SID` is an API-key SID (`SK...`), not a provider OAuth client ID. |
| Configured trial sender | E.164-shaped `+173...8034`; accepted as `From` for the successful template message. |
| Configured recipient | E.164-shaped `+91...0580`; the successful message was delivered to it. |
| Account inventory | `GET /IncomingPhoneNumbers.json` returned an empty list, including when filtered by the configured trial sender. |
| Message list | Returned the successful message and its `delivered` state. |
| Individual message read | `GET /Messages/{sid}.json` returned HTTP 403 for the trial message in this account, while the list endpoint remained readable. Treat this as an unresolved trial/API quirk and prefer list reads or status callbacks for probes. |

An empty `IncomingPhoneNumbers` list does not prove that the trial sender is
invalid. Twilio's current trial documentation says product trial numbers are
provided by Twilio, can vary by product and recipient, and are not numbers the
user purchases during the trial flow. The Try out SMS page is therefore the
source of truth for the active product trial sender.

## Reproduction evidence

The following probes were run against the configured account with secrets held
only in the process:

1. A POST to `Messages.json` with an arbitrary body (`ReBase Twilio API probe`)
   returned HTTP 400 and error `572006`. No message SID was created.
2. The same POST shape with `Body=sms_appointment_reminders` and the configured
   `To`/`From` returned success and a message SID. The message appeared as
   `delivered` in `Messages.json` shortly afterward.
3. Both the Account SID/Auth Token pair and the `SK...` API-key pair authorized
   read-only access to the Messages list.

Redacted reproduction shape:

```bash
curl -X POST \
  "https://api.twilio.com/2010-04-01/Accounts/$TWILIO_ACCOUNT_SID/Messages.json" \
  -u "$TWILIO_ACCOUNT_SID:$TWILIO_AUTH_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "To=<verified-recipient-in-E.164>" \
  --data-urlencode "From=<trial-sender-shown-by-Twilio>" \
  --data-urlencode "Body=sms_appointment_reminders"
```

Do not put real credentials in a command copied into documentation or shell
history. The ReBase adapter probe should inject a fetch transport instead of
sending a live message.

The credentials used for this check were supplied from the local development
profile and were never written to this file. Any live credential pasted into a
chat, issue, log, or shell transcript should be rotated before production use;
create a new API key and Auth Token, update the secret store, and revoke the
old values.

## Trial policy (documented)

Twilio's trial documentation currently states:

- trial accounts may message only verified recipients (up to five per
  account); the signup number is verified automatically;
- trial SMS/Voice traffic is geographically restricted, generally to the
  signup country; the Try out SMS page currently describes verified US
  recipients specifically;
- trial requests must use Twilio-provided body templates rather than custom
  message text;
- phone numbers must use E.164 format;
- product trial numbers are supplied by Twilio and can differ between products
  or recipients;
- the Account SID/Auth Token are the same credential types used after upgrade;
  a trial does not have a separate credential set.

The Try out SMS API reference lists these allowed trial body values:

```text
sms_2fa
sms_appointment_reminders
sms_order_confirmation
sms_delivery_updates
sms_customer_support
sms_marketing_promotions
sms_event_notifications
sms_account_alerts
sms_feedback_surveys
sms_internal_alerts
```

The general trial page and the product Try out page describe geographic scope
slightly differently. The measured account delivered to the configured `+91`
recipient, so this account's verified-recipient and route settings currently
permit that request. Do not generalize that result to another account or
recipient; verify the recipient in Console and inspect the provider error code
when a later request fails.

Sources (retrieved 2026-09-02):

- [Twilio free-trial restrictions](https://www.twilio.com/docs/usage/tutorials/how-to-use-your-free-trial-account.md)
- [Twilio Try out SMS](https://www.twilio.com/docs/usage/trials/try-out-sms.md)
- [Twilio Message resource](https://www.twilio.com/docs/messaging/api/message-resource.md)

## Why Console delivery worked

The Console Try out flow automatically selects the product's active trial
number, a verified recipient, and one of the permitted template identifiers.
The API request copied from that page succeeds because it preserves those
constraints. A hand-written API request can use the same sender and recipient
and still fail if its body is not an allowed template, if the recipient is no
longer verified, or if the account's geographic policy changes.

Dashboard success therefore does not imply that arbitrary OTP text, an
unverified number, or a different country is permitted during trial.

## ReBase implications

1. Keep Twilio as an explicit named adapter. Preserve provider code `572006`
   and its message in the effect result; do not relabel it as a generic geo
   or network error.
2. Model trial content as a provider test mode or a declared template input.
   Do not silently replace application text with a template. A trial account
   cannot be used to validate dynamic SMS OTP text; use an upgraded Messaging
   account or the appropriate Twilio verification product for that workflow.
3. Validate E.164 shape in the Surreal schema where useful, but leave trial
   recipient verification, sender eligibility, geographic permissions, and
   carrier delivery to Twilio. Those facts cannot be proven by local schema
   validation.
4. Keep live SMS checks opt-in and outside ordinary contract tests. Adapter
   tests should assert URL-encoded form mapping, authorization selection,
   response normalization, retry classification, and redaction using an
   injected transport.
5. For inbound SMS, configure the webhook on the active Twilio product trial
   resource and send from the verified handset. The repository has not
   performed an inbound handset test, and an empty IncomingPhoneNumbers list
   means the standard purchased-number webhook path should not be assumed for
   the trial virtual number.

## Open checks

- Send one inbound message manually from the verified phone to the number
  shown on the Try out SMS page, then record whether the product trial exposes
  a webhook callback and which `From`/`To` values it uses.
- Confirm the recipient's verification and India geographic permission in the
  Twilio Console for this account; the public REST probes above do not expose a
  reliable trial geo-permission read endpoint.
- Re-test the individual Message resource after upgrading or changing API
  credentials; the observed HTTP 403 may be trial-specific or an account
  permission change.
- When wiring ReBase configuration, prefer descriptive platform names such as
  `REBASE_PLATFORM_SMS_TWILIO_ACCOUNT_SID`,
  `REBASE_PLATFORM_SMS_TWILIO_API_KEY_SID`,
  `REBASE_PLATFORM_SMS_TWILIO_API_KEY_SECRET`, and
  `REBASE_PLATFORM_SMS_TWILIO_FROM`. The current `TWILIO_*` names are recorded
  as the development profile only; no rename was performed by this research
  update.

## Maintenance rule

This file is a measured finding, not a promise that all Twilio accounts behave
the same way. Keep the observed date, account type, provider error codes, and
source links together. Re-run the redacted probes after changing the Twilio
plan, sender, recipient verification, API credentials, or Messaging product.
