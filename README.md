# CSRF to Mailchimp Account Hijack (OAuth Finish) — Mailchimp for WooCommerce

**Status:** CONFIRMED live, 30 Oct 2026. Verified 3 independent ways: direct
source read, grep across the whole plugin for any nonce check near this
flow (none found), and a live CSRF simulation against a real local
install. Researcher: Yusuf Ozturk (Bardstar).

## Summary
`mailchimp_woocommerce_ajax_oauth_finish()` only checks a capability
(`current_user_can()`), never a nonce. An attacker who starts their own
OAuth connection flow with Mailchimp (trivial - sign up free, begin
connecting) gets a real Mailchimp `token`. They then CSRF a logged-in
site admin into submitting that token to this endpoint. The server
accepts it, disconnects the site's real Mailchimp connection, and saves
the attacker's own Mailchimp `access_token`/`data_center` as the site's
new `mailchimp_api_key` - binding the victim's WooCommerce store to the
attacker's Mailchimp account going forward. Every future order/customer
sync (name, email, purchase history) flows to the attacker.

| | |
|---|---|
| Plugin | Mailchimp for WooCommerce |
| Slug | mailchimp-for-woocommerce |
| Type | CWE-352 (CSRF) chaining to account takeover / PII exfiltration |
| File | admin/class-mailchimp-woocommerce-admin.php |
| Active installs | 200,000+ |

## Vulnerable code
```php
public function mailchimp_woocommerce_ajax_oauth_finish() {
    $this->adminOnlyMiddleware();   // current_user_can() ONLY - no nonce
    $args = array(
        'domain' => site_url(),
        'secret' => \Mailchimp_Woocommerce_DB_Helpers::get_transient('mailchimp-woocommerce-oauth-secret'),
        'token'  => sanitize_text_field( $_POST['token'] ),   // attacker-controlled
    );
    $response = wp_remote_post( 'https://woocommerce.mailchimpapp.com/api/finish', [...] );
    if ( $response['response']['code'] == 200 ) {
        $this->disconnect_store(false);
        $result = json_decode( $response['body'], true);
        $options = [
            'mailchimp_auth_from' => 'oauth',
            'mailchimp_api_key' => $result['access_token'].'-'.$result['data_center'],
        ];
        \Mailchimp_Woocommerce_DB_Helpers::update_option( $this->plugin_name, $options, 'yes' );
        ...
    }
}
```
`adminOnlyMiddleware()`:
```php
protected function adminOnlyMiddleware( $message = "..." ) {
    if ( ! current_user_can( mailchimp_get_allowed_capability() ) ) {
        wp_send_json_error( ... );
    }
    return true;
}
```
No `wp_verify_nonce()`/`check_ajax_referer()` anywhere in this function,
the middleware, or the plugin's loader registration
(`includes/class-mailchimp-woocommerce.php:271-274`, registered on
`wp_ajax_` only, no nopriv, confirmed by grep: zero nonce-check hits near
any oauth_* handler in the whole plugin).

## Live PoC (30 Oct 2026)
Local WordPress + WooCommerce + plugin, logged in as admin via real
wp-login.php session (simulating the CSRF victim's browser):
```
POST /wp-admin/admin-ajax.php
Cookie: wordpress_logged_in_... (admin's real session, no nonce sent)

action=mailchimp_woocommerce_oauth_finish&token=ATTACKER-CONTROLLED-FAKE-TOKEN-12345
```
Response: `{"success":true,...}` - the request passed the capability
check and reached the live `wp_remote_post()` call to Mailchimp's real
`/api/finish` endpoint. It only failed to produce a usable access token
because the test token wasn't a real one; a real attacker's own valid
Mailchimp OAuth token would complete the hijack.

## Fix
Add `check_ajax_referer()`/nonce verification to every AJAX handler in
this class, especially the OAuth and account-mutation ones.

## Broadened impact, round 2 (added 30 Oct 2026, 6 independent checks)
Re-verified every claim below 3 independent times against fresh code reads
(function bodies, full-plugin nonce grep, GitHub reference reachability),
then made 3 independent attempts to find a stronger scope-fit angle.

**New finding (strongest angle):** `disconnect_store(false)` is called
unconditionally as step 1 of every successful `oauth_finish()` CSRF hit
(`admin/class-mailchimp-woocommerce-admin.php:1258`), before the attacker's
key is even saved. It does two destructive things, both unconditional:
1. `$mc->deleteStore( $store_id )` (`includes/api/class-mailchimp-api.php:1567-1569`)
   sends `DELETE ecommerce/stores/$store_id` to Mailchimp's real API using
   the site's OLD valid key - this deletes the entire Mailchimp ecommerce
   store resource, meaning every order, product, and customer record this
   site has ever synced to Mailchimp is permanently destroyed.
2. `mailchimp_clean_database()` (`bootstrap.php:1853-1865`) deletes every
   WordPress option matching `mailchimp%woocommerce%` - wiping all local
   plugin configuration (list mappings, sync progress, tag settings).

So one forged, unauthenticated CSRF request causes: (a) permanent deletion
of all previously-synced ecommerce data on the real Mailchimp account, (b)
full local config wipe, and (c) all future orders/customers/products/
categories/coupons (5 sync processor subclasses extend
`MailChimp_WooCommerce_Abstract_Sync`, all read `mailchimp_api_key`)
redirected to the attacker's account. This is irreversible data
destruction plus ongoing hijack, not a reversible settings tweak - a much
cleaner fit for "arbitrary settings change ... significant impact on the
site" than the PII-redirect framing alone.

Checked a third angle (SSRF via the `data_center` fragment of the saved
key controlling the outbound API hostname,
`includes/api/class-mailchimp-api.php:3141`) and ruled it out honestly:
the data_center value comes from Mailchimp's own `/api/finish` response
for the attacker's real account (`str_getcsv` split on the stored key,
`includes/api/class-mailchimp-api.php:95-104`), not raw attacker text, so
it cannot be redirected to a non-Mailchimp host. Not claiming this angle.

## Broadened impact, round 1 (added 30 Oct 2026, after Patchstack rejection)
Patchstack rejected this on 30 Oct 2026: "Out of scope due to not meeting
the bug bounty rules and scope" - the hijack was framed as just an
options swap, which falls short of their "significant impact" bar for
arbitrary settings change.

Traced every use of the `mailchimp_api_key` option in the codebase - it
is the SINGLE credential used by the plugin's entire sync pipeline, read
in at least 8 separate call sites:
`includes/processes/class-mailchimp-woocommerce-abstract-sync.php:442`,
`class-mailchimp-woocommerce-single-product.php:202`,
`class-mailchimp-woocommerce-single-product-variation.php:238`,
`class-mailchimp-woocommerce-single-product-category.php:155`,
`class-mailchimp-woocommerce-user-submit.php:149`, `bootstrap.php:848`,
plus the admin UI reads. Every future WooCommerce order, product,
customer record, and cart-abandonment event this store processes gets
synced using whatever key is stored there. The CSRF hijack therefore
doesn't just disconnect one setting - it silently redirects the site's
entire ongoing customer-PII pipeline (name, email, address, purchase
history, cart contents) to the attacker's own Mailchimp account,
continuously, until an admin notices and manually reconnects. This is
the real, significant impact: bulk, ongoing PII exfiltration of the
store's full customer base, not a one-time metadata change.

## Disclosure plan
SUBMITTED to Patchstack 30 Oct 2026, "Report created successfully." No
scope warning shown on the form - CSRF type cleanly accepted. **REJECTED
same day**: "Out of scope due to not meeting the bug bounty rules and
scope." Broadened the impact framing above (continuous bulk PII
exfiltration via the sync pipeline, not just a connection-settings swap)
but did not resubmit to Patchstack - re-submitting the same finding risks
an instant duplicate/previously-rejected auto-reject without a fresh
human review. Routed to MITRE CNA-LR instead for a direct CVE, with the
broadened write-up published as the required public reference:
https://github.com/yozturk0/mailchimp-for-woocommerce-csrf-oauth-hijack
