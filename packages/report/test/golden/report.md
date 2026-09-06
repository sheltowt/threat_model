# Threat model: Payment Service

Card-present checkout API for the storefront, plus its settlement batch.

| Field | Value |
| --- | --- |
| Business criticality | critical |
| Owner | platform-security |
| Author | B. Shelton |
| Model date | 2026-09-06 |
| Model version | 3 |
| Generated | 2026-09-06T12:00:00Z |
| Rules run | 53 (0 skipped) |
| Scope | 7 of 8 elements, 7 flows, 4 trust boundaries, 5 data assets |

## Management summary

The payment service accepts card data from the storefront, tokenises it through the processor, and stores only tokens. The open questions are whether the settlement batch needs the full pan and who owns key rotation.

The analysis found **31 risks** across 8 elements and 7 flows, of which **31 remain open**, the worst at **high** severity. 0 have been dealt with and 0 are suppressed by a recorded assumption.

11 of these are low-confidence findings, meaning the rule could not settle its condition because the model does not record the control it asks about. They are model gaps first and risks second — see [Low-confidence findings](#low-confidence-findings).

## Severity summary

| Severity | Total | Open | Resolved | Suppressed | Low confidence |
| --- | --- | --- | --- | --- | --- |
| 🟥 critical | 0 | 0 | 0 | 0 | 0 |
| 🟧 high | 5 | 5 | 0 | 0 | 2 |
| 🟨 elevated | 20 | 20 | 0 | 0 | 8 |
| 🟦 medium | 6 | 6 | 0 | 0 | 1 |
| ⬜ low | 0 | 0 | 0 | 0 | 0 |
| **Total** | 31 | 31 | 0 | 0 | 11 |

## Attention first

5 open risks at critical or high severity. Deal with these before anything else in this report.

### Storefront web app aggregates several categories of personal data

`excessive-pii-collection@storefront` · **high** · Storefront web app (element) · information-disclosure · CWE-359 · confidence high

One processing asset holds several distinct categories of personal data at once, at least one of them in volume. The categories are more dangerous together than apart: joining them is what turns records into people.

**Do this.** Reduce this asset to the personal data fields it actually needs, and tokenise the rest.

**Confirm it worked.** List every personal data field the asset can read, and for each one name the feature that requires it.

### Settlement batch retains card data in temporary files

`manual@T-001` · **high** · Nightly settlement batch (element) · information-disclosure · CWE-459 · confidence high

The batch writes intermediate CSV files to local disk. Nobody has confirmed those files are shredded after a run.

**Do this.** Write intermediates to a tmpfs and delete on completion.

### Operations console signs in to Payment API with a single factor

`missing-authentication-second-factor@ops_to_api` · **high** · Operator access (flow) · spoofing · CWE-308 · confidence low

A person signs in to something valuable with one factor, so every credential-stuffing list, phishing kit and shoulder-surf is a complete authentication bypass.

**Do this.** Enforce MFA on this login path and record it on the flow.

**Confirm it worked.** Attempt the login with a valid password alone and confirm it is refused.

### Shopper signs in to Storefront web app with a single factor

`missing-authentication-second-factor@shopper_to_storefront` · **high** · Checkout (flow) · spoofing · CWE-308 · confidence low

A person signs in to something valuable with one factor, so every credential-stuffing list, phishing kit and shoulder-surf is a complete authentication bypass.

**Do this.** Enforce MFA on this login path and record it on the flow.

**Confirm it worked.** Attempt the login with a valid password alone and confirm it is refused.

### Storefront web app is published to the internet with no edge component in front

`unguarded-access-from-internet@storefront` · **high** · Storefront web app (element) · elevation-of-privilege · CWE-1327 · confidence high

A general-purpose asset is published directly to the internet. Everything it exposes — every endpoint, every parser, every version banner — is a first-line surface, with nothing in front to normalise, filter or absorb traffic.

**Do this.** Move the asset behind an edge component and make its own listener private.

**Confirm it worked.** Resolve the asset's own hostname from outside and confirm it does not answer.

## Risks by severity

### 🟧 high (5)

| ID | Title | Subject | STRIDE | CWE | Status | Confidence |
| --- | --- | --- | --- | --- | --- | --- |
| `excessive-pii-collection@storefront` | Storefront web app aggregates several categories of personal data | Storefront web app (element) | information-disclosure | CWE-359 | unchecked | high |
| `manual@T-001` | Settlement batch retains card data in temporary files | Nightly settlement batch (element) | information-disclosure | CWE-459 | unchecked | high |
| `missing-authentication-second-factor@ops_to_api` | Operations console signs in to Payment API with a single factor | Operator access (flow) | spoofing | CWE-308 | unchecked | low |
| `missing-authentication-second-factor@shopper_to_storefront` | Shopper signs in to Storefront web app with a single factor | Checkout (flow) | spoofing | CWE-308 | unchecked | low |
| `unguarded-access-from-internet@storefront` | Storefront web app is published to the internet with no edge component in front | Storefront web app (element) | elevation-of-privilege | CWE-1327 | unchecked | high |

<details><summary><code>excessive-pii-collection@storefront</code> — Storefront web app aggregates several categories of personal data</summary>

One processing asset holds several distinct categories of personal data at once, at least one of them in volume. The categories are more dangerous together than apart: joining them is what turns records into people.

**Why it fired.** An in-scope element that is not itself a datastore, which processes or stores two or more data assets flagged as personal data, at least one of them with a quantity of many or more. Datastores are excluded because a system of record is supposed to hold the whole picture; the finding is about processing tiers and edge services that have accumulated one.

**Mitigation.** Split the categories across assets that do not share a compromise, replace direct identifiers with tokens resolvable only by the asset that must resolve them, and narrow each service's read scope to the fields it uses rather than the record it sits on.

**Action.** Reduce this asset to the personal data fields it actually needs, and tokenise the rest.

**Check.** List every personal data field the asset can read, and for each one name the feature that requires it.

**When this is wrong.** Assets that hold the categories only in transit, never together in one record, and services whose access to several categories is real but strictly segregated per request. If the aggregation is genuinely necessary, the finding is still the right place to write down why.

**References.** CWE-359 · CAPEC-118 · ASVS V8.3 · https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html

**Rating.** likelihood very-likely × impact high = high; data breach probable via storefront

</details>

<details><summary><code>manual@T-001</code> — Settlement batch retains card data in temporary files</summary>

The batch writes intermediate CSV files to local disk. Nobody has confirmed those files are shredded after a run.

**Why it fired.** Recorded by hand in the model file.

**Mitigation.** Write intermediates to a tmpfs and delete on completion.

**When this is wrong.** Reviewed by a person, so judge it on its own terms.

**References.** CWE-459

**Rating.** likelihood likely × impact medium = high; data breach improbable via settlement_batch

</details>

<details><summary><code>missing-authentication-second-factor@ops_to_api</code> — Operations console signs in to Payment API with a single factor</summary>

A person signs in to something valuable with one factor, so every credential-stuffing list, phishing kit and shoulder-surf is a complete authentication bypass.

**Why it fired.** A flow whose source is a human, arriving at a technology the catalogue marks a high-value target or carrying devops usage, where the recorded authentication is something weaker than two-factor and the link does not record uses_mfa. Flows with no authentication at all are left to missing-authentication, which says something stronger. Where uses_mfa is simply unrecorded the finding is raised at low confidence and names that field, because "nobody wrote it down" is not the same as "there is no second factor".

**Mitigation.** Require a phishing-resistant second factor — a passkey or a hardware authenticator — for administrative access without exception, and step it up on sensitive actions for everyone else.

**Action.** Enforce MFA on this login path and record it on the flow.

**Check.** Attempt the login with a valid password alone and confirm it is refused.

**When this is wrong.** Consumer flows where a second factor is a deliberate, documented business trade-off, and sessions established behind an SSO portal that already enforced MFA upstream — in the latter case the second factor exists, it is just on a hop the model does not draw. Record uses_mfa on the link to settle it either way.

**References.** CWE-308 · CAPEC-560, CAPEC-600 · ASVS V2.8 · https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html

**Rating.** likelihood very-likely × impact high = high; data breach possible via ops_console, payment_api

</details>

<details><summary><code>missing-authentication-second-factor@shopper_to_storefront</code> — Shopper signs in to Storefront web app with a single factor</summary>

A person signs in to something valuable with one factor, so every credential-stuffing list, phishing kit and shoulder-surf is a complete authentication bypass.

**Why it fired.** A flow whose source is a human, arriving at a technology the catalogue marks a high-value target or carrying devops usage, where the recorded authentication is something weaker than two-factor and the link does not record uses_mfa. Flows with no authentication at all are left to missing-authentication, which says something stronger. Where uses_mfa is simply unrecorded the finding is raised at low confidence and names that field, because "nobody wrote it down" is not the same as "there is no second factor".

**Mitigation.** Require a phishing-resistant second factor — a passkey or a hardware authenticator — for administrative access without exception, and step it up on sensitive actions for everyone else.

**Action.** Enforce MFA on this login path and record it on the flow.

**Check.** Attempt the login with a valid password alone and confirm it is refused.

**When this is wrong.** Consumer flows where a second factor is a deliberate, documented business trade-off, and sessions established behind an SSO portal that already enforced MFA upstream — in the latter case the second factor exists, it is just on a hop the model does not draw. Record uses_mfa on the link to settle it either way.

**References.** CWE-308 · CAPEC-560, CAPEC-600 · ASVS V2.8 · https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html

**Rating.** likelihood very-likely × impact high = high; data breach possible via shopper, storefront

</details>

<details><summary><code>unguarded-access-from-internet@storefront</code> — Storefront web app is published to the internet with no edge component in front</summary>

A general-purpose asset is published directly to the internet. Everything it exposes — every endpoint, every parser, every version banner — is a first-line surface, with nothing in front to normalise, filter or absorb traffic.

**Why it fired.** An in-scope element marked internet-facing whose technology is not one of the roles built to sit at the edge: gateway, reverse proxy, load balancer or WAF. Clients and humans are excluded, since an internet-facing browser or operator is a description of where the user is, not an exposure you own.

**Mitigation.** Put a gateway or reverse proxy in front, terminate TLS there, and publish only the routes that need to be public. Keep the asset itself on a private address so the guard cannot be bypassed by anyone who learns the origin.

**Action.** Move the asset behind an edge component and make its own listener private.

**Check.** Resolve the asset's own hostname from outside and confirm it does not answer.

**When this is wrong.** Assets that are internet-facing by design and hardened for it — a public CDN origin serving only static files, or a service whose edge is a managed platform the model does not draw as an element. Where a provider's edge is doing the guarding, model it: an unnamed layer nobody can point at tends not to be configured either.

**References.** CWE-1327 · CAPEC-1 · ASVS V1.1.4 · https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html

**Rating.** likelihood very-likely × impact high = high; data breach possible via storefront

</details>

### 🟨 elevated (20)

| ID | Title | Subject | STRIDE | CWE | Status | Confidence |
| --- | --- | --- | --- | --- | --- | --- |
| `clickjacking@storefront` | Storefront web app can be framed by another origin | Storefront web app (element) | tampering | CWE-1021 | unchecked | high |
| `container-baseimage-backdooring@payment_api` | Payment API runs a container image with no recorded provenance check | Payment API (element) | tampering | CWE-1357 | unchecked | low |
| `container-baseimage-backdooring@storefront` | Storefront web app runs a container image with no recorded provenance check | Storefront web app (element) | tampering | CWE-1357 | unchecked | low |
| `dos-risky-access-across-trust-boundary@ops_to_api` | Payment API accepts unthrottled traffic over ops_to_api | Operator access (flow) | denial-of-service | CWE-770 | unchecked | low |
| `dos-risky-access-across-trust-boundary@storefront_to_api` | Payment API accepts unthrottled traffic over storefront_to_api | Tokenise (flow) | denial-of-service | CWE-770 | unchecked | low |
| `excessive-pii-collection@payment_api` | Payment API aggregates several categories of personal data | Payment API (element) | information-disclosure | CWE-359 | unchecked | high |
| `missing-cloud-hardening@vpc` | Production VPC has no recorded cloud hardening baseline | Production VPC (boundary) | elevation-of-privilege | CWE-1188 | unchecked | low |
| `missing-consent-record@card_data` | Personal data card_data has no recorded origin | card_data (data) | repudiation | CWE-359 | unchecked | high |
| `missing-consent-record@customer_profile` | Personal data customer_profile has no recorded origin | customer_profile (data) | repudiation | CWE-359 | unchecked | high |
| `missing-content-security-policy@storefront` | Storefront web app serves pages without a content security policy | Storefront web app (element) | tampering | CWE-1021 | unchecked | high |
| `missing-hardening@payment_api` | Payment API is an attractive target with no recorded hardening | Payment API (element) | elevation-of-privilege | CWE-1188 | unchecked | low |
| `missing-hardening@token_store` | Token store is an attractive target with no recorded hardening | Token store (element) | elevation-of-privilege | CWE-1188 | unchecked | low |
| `missing-pii-encryption-at-rest@token_store` | Token store stores personal data with transparent encryption only | Token store (element) | information-disclosure | CWE-311 | unchecked | high |
| `missing-waf@storefront` | Storefront web app faces the internet with no web application firewall in front | Storefront web app (element) | tampering | CWE-693 | unchecked | high |
| `pii-crossing-untrusted-boundary@api_to_processor` | api_to_processor carries personal data to Card processor outside the estate | Processor tokenisation (flow) | information-disclosure | CWE-359 | unchecked | high |
| `pii-retention-unbounded@customer_profile` | Personal data customer_profile is stored in volume with no owner | customer_profile (data) | information-disclosure | CWE-359 | unchecked | high |
| `sql-nosql-injection@batch_to_token_store` | Nightly settlement batch may build injectable queries against Token store | Nightly read (flow) | tampering | CWE-89 | unchecked | low |
| `unencrypted-communication@api_to_token_store` | Unencrypted sql-access-protocol link from Payment API to Token store | Token persistence (flow) | information-disclosure | CWE-319 | unchecked | high |
| `unencrypted-communication@batch_to_token_store` | Unencrypted sql-access-protocol link from Nightly settlement batch to Token store | Nightly read (flow) | information-disclosure | CWE-319 | unchecked | high |
| `unguarded-direct-datastore-access@api_to_token_store` | Payment API reaches Token store directly across a network boundary | Token persistence (flow) | elevation-of-privilege | CWE-1220 | unchecked | high |

<details><summary><code>clickjacking@storefront</code> — Storefront web app can be framed by another origin</summary>

Nothing stops another site from loading this application in a frame, so a user can be induced to click a control they cannot see, in a session they are already authenticated for.

**Why it fired.** An internet-facing web application that does not record uses_content_security_policy, which is where frame-ancestors would be declared. This shares a control with missing-content-security-policy and is reported separately because the fix and the consequence are different: frame-ancestors is a one-line directive, and its absence is exploitable on its own rather than only in combination with another flaw.

**Mitigation.** Set frame-ancestors in the content security policy to the exact origins allowed to embed the page, using 'none' when that is nobody, and require re-authentication or a typed confirmation for the actions worth stealing a click for.

**Action.** Add a frame-ancestors directive to the application's policy.

**Check.** Load the application inside an iframe on a foreign origin and confirm the browser blocks it.

**When this is wrong.** Applications with no clickable state-changing controls, applications that are deliberately embeddable — a payment widget, an embedded map — and those whose proxy sets frame-ancestors on the way out. Embeddable by design is the common case; record the control as true and add a note.

**References.** CWE-1021 · CAPEC-103, CAPEC-181 · ASVS V14.4.7 · https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html

**Rating.** likelihood likely × impact high = elevated; data breach improbable via storefront

</details>

<details><summary><code>container-baseimage-backdooring@payment_api</code> — Payment API runs a container image with no recorded provenance check</summary>

The asset runs as a container and nothing records that the image it runs was signed or that its contents were verified. A base image is code you did not write, pulled by a tag that can be moved under you.

**Why it fired.** An in-scope element whose machine is recorded as container, which records neither uses_code_signing nor verifies_dependencies. An unrecorded machine is treated as not a container rather than as unknown, because that is a deployment fact the author either wrote down or did not, unlike a security control.

**Mitigation.** Pin base images by digest rather than by tag, sign images at build time and verify the signature at admission, rebuild on base image updates rather than on a schedule, and scan the final image rather than only the manifest.

**Action.** Pin base images by digest and require a valid signature at admission.

**Check.** Attempt to deploy an unsigned image and confirm the cluster refuses it.

**When this is wrong.** Estates where an admission controller enforces signatures cluster-wide, so the control is true for every workload and written on none of them, and images built entirely from source in your own pipeline. Record uses_code_signing on the workloads, or add the admission controller as an element.

**References.** CWE-1357 · CAPEC-444 · ASVS V14.2.1 · https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

**Rating.** likelihood likely × impact high = elevated; data breach possible via payment_api

</details>

<details><summary><code>container-baseimage-backdooring@storefront</code> — Storefront web app runs a container image with no recorded provenance check</summary>

The asset runs as a container and nothing records that the image it runs was signed or that its contents were verified. A base image is code you did not write, pulled by a tag that can be moved under you.

**Why it fired.** An in-scope element whose machine is recorded as container, which records neither uses_code_signing nor verifies_dependencies. An unrecorded machine is treated as not a container rather than as unknown, because that is a deployment fact the author either wrote down or did not, unlike a security control.

**Mitigation.** Pin base images by digest rather than by tag, sign images at build time and verify the signature at admission, rebuild on base image updates rather than on a schedule, and scan the final image rather than only the manifest.

**Action.** Pin base images by digest and require a valid signature at admission.

**Check.** Attempt to deploy an unsigned image and confirm the cluster refuses it.

**When this is wrong.** Estates where an admission controller enforces signatures cluster-wide, so the control is true for every workload and written on none of them, and images built entirely from source in your own pipeline. Record uses_code_signing on the workloads, or add the admission controller as an element.

**References.** CWE-1357 · CAPEC-444 · ASVS V14.2.1 · https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

**Rating.** likelihood likely × impact high = elevated; data breach possible via storefront

</details>

<details><summary><code>dos-risky-access-across-trust-boundary@ops_to_api</code> — Payment API accepts unthrottled traffic over ops_to_api</summary>

Traffic crosses a network boundary into an asset the business needs available, and nothing on either the link or the target records a limit on how much of it there can be.

**Why it fired.** A non-response flow crossing a network trust boundary into an in-scope asset rated critical or better for availability, where the caller either comes from an untrusted network or is reachable from an internet-facing element, and neither the link nor the target records rate_limited. When neither has been recorded the finding is raised at low confidence and names the missing fields.

**Mitigation.** Rate limit per caller identity rather than per address, set concurrency and payload size caps, and shed load at the edge so the pressure never reaches the asset you care about. Load shedding that returns quickly beats a queue that grows.

**Action.** Apply a per-identity rate limit and a concurrency cap on this path.

**Check.** Drive the endpoint past the intended limit and confirm it returns a throttling response rather than degrading.

**When this is wrong.** Links whose volume is bounded by construction — a scheduled batch, a queue consumer pulling at its own pace — and paths already throttled by a platform layer the model does not draw, such as a mesh or an ingress controller. Record rate_limited on the flow in that case.

**References.** CWE-770 · CAPEC-125, CAPEC-227 · ASVS V11.1.4 · https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html

**Rating.** likelihood likely × impact medium = elevated; data breach improbable via ops_console, payment_api

</details>

<details><summary><code>dos-risky-access-across-trust-boundary@storefront_to_api</code> — Payment API accepts unthrottled traffic over storefront_to_api</summary>

Traffic crosses a network boundary into an asset the business needs available, and nothing on either the link or the target records a limit on how much of it there can be.

**Why it fired.** A non-response flow crossing a network trust boundary into an in-scope asset rated critical or better for availability, where the caller either comes from an untrusted network or is reachable from an internet-facing element, and neither the link nor the target records rate_limited. When neither has been recorded the finding is raised at low confidence and names the missing fields.

**Mitigation.** Rate limit per caller identity rather than per address, set concurrency and payload size caps, and shed load at the edge so the pressure never reaches the asset you care about. Load shedding that returns quickly beats a queue that grows.

**Action.** Apply a per-identity rate limit and a concurrency cap on this path.

**Check.** Drive the endpoint past the intended limit and confirm it returns a throttling response rather than degrading.

**When this is wrong.** Links whose volume is bounded by construction — a scheduled batch, a queue consumer pulling at its own pace — and paths already throttled by a platform layer the model does not draw, such as a mesh or an ingress controller. Record rate_limited on the flow in that case.

**References.** CWE-770 · CAPEC-125, CAPEC-227 · ASVS V11.1.4 · https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html

**Rating.** likelihood likely × impact medium = elevated; data breach improbable via storefront, payment_api

</details>

<details><summary><code>excessive-pii-collection@payment_api</code> — Payment API aggregates several categories of personal data</summary>

One processing asset holds several distinct categories of personal data at once, at least one of them in volume. The categories are more dangerous together than apart: joining them is what turns records into people.

**Why it fired.** An in-scope element that is not itself a datastore, which processes or stores two or more data assets flagged as personal data, at least one of them with a quantity of many or more. Datastores are excluded because a system of record is supposed to hold the whole picture; the finding is about processing tiers and edge services that have accumulated one.

**Mitigation.** Split the categories across assets that do not share a compromise, replace direct identifiers with tokens resolvable only by the asset that must resolve them, and narrow each service's read scope to the fields it uses rather than the record it sits on.

**Action.** Reduce this asset to the personal data fields it actually needs, and tokenise the rest.

**Check.** List every personal data field the asset can read, and for each one name the feature that requires it.

**When this is wrong.** Assets that hold the categories only in transit, never together in one record, and services whose access to several categories is real but strictly segregated per request. If the aggregation is genuinely necessary, the finding is still the right place to write down why.

**References.** CWE-359 · CAPEC-118 · ASVS V8.3 · https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html

**Rating.** likelihood likely × impact high = elevated; data breach probable via payment_api

</details>

<details><summary><code>missing-cloud-hardening@vpc</code> — Production VPC has no recorded cloud hardening baseline</summary>

A cloud-provider trust boundary holds assets, and nothing inside it records that it has been hardened. In a cloud account the defaults that matter are the account's — public storage, permissive security groups, over-scoped roles, no logging — and they are set once and inherited by everything.

**Why it fired.** A trust boundary typed as a cloud provider network containing at least one in-scope member that does not record the hardened control. The boundary is the subject rather than any one asset, because cloud misconfiguration is an account-level property that no single element owns.

**Mitigation.** Apply the provider's benchmark at the account level, enforce it with policy-as-code in the deployment pipeline rather than by review, turn on the audit trail before anything else, and scope roles to the actions they actually use.

**Action.** Adopt a cloud benchmark and enforce it in the pipeline that creates these resources.

**Check.** Run a posture assessment against the account and confirm no high findings remain open.

**When this is wrong.** Accounts governed by policy-as-code with a passing posture report, where the control is true for the whole boundary and simply not written on each element. Record hardened on the members, or add an assumption naming the posture tool and its last run.

**References.** CWE-1188 · CAPEC-1 · ASVS V14.1.3 · https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html

**Rating.** likelihood likely × impact high = elevated; data breach possible via settlement_batch, storefront, payment_api, token_store, audit_store

</details>

<details><summary><code>missing-consent-record@card_data</code> — Personal data card_data has no recorded origin</summary>

The model holds personal data and does not say where it came from. Without that, nobody can answer the two questions every privacy review starts with: on what basis do we hold this, and were the people it describes told.

**Why it fired.** A data asset flagged as personal data whose origin field is not set. Origin stands in for provenance and lawful basis together — collected from the subject, derived from behaviour, purchased from a broker, inferred by a model — because those four have very different consent stories and the difference is invisible once the data is in a table.

**Mitigation.** Record the origin and the lawful basis on the data asset, then check that the basis actually covers every use the model shows — a basis for collection is not a basis for every downstream transfer this diagram contains.

**Action.** Set origin on the data asset and name the lawful basis for holding it.

**Check.** Pick one record and trace it back to the collection point and the notice shown there.

**When this is wrong.** Data whose provenance is recorded thoroughly in a separate register that the model simply references elsewhere, and derived assets whose origin is obvious from the pipeline that produces them. Writing one line in origin is cheaper than explaining either.

**References.** CWE-359 · CAPEC-118 · ASVS V8.3 · https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html

**Rating.** likelihood likely × impact medium = elevated; data breach improbable via storefront, payment_api, processor

</details>

<details><summary><code>missing-consent-record@customer_profile</code> — Personal data customer_profile has no recorded origin</summary>

The model holds personal data and does not say where it came from. Without that, nobody can answer the two questions every privacy review starts with: on what basis do we hold this, and were the people it describes told.

**Why it fired.** A data asset flagged as personal data whose origin field is not set. Origin stands in for provenance and lawful basis together — collected from the subject, derived from behaviour, purchased from a broker, inferred by a model — because those four have very different consent stories and the difference is invisible once the data is in a table.

**Mitigation.** Record the origin and the lawful basis on the data asset, then check that the basis actually covers every use the model shows — a basis for collection is not a basis for every downstream transfer this diagram contains.

**Action.** Set origin on the data asset and name the lawful basis for holding it.

**Check.** Pick one record and trace it back to the collection point and the notice shown there.

**When this is wrong.** Data whose provenance is recorded thoroughly in a separate register that the model simply references elsewhere, and derived assets whose origin is obvious from the pipeline that produces them. Writing one line in origin is cheaper than explaining either.

**References.** CWE-359 · CAPEC-118 · ASVS V8.3 · https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html

**Rating.** likelihood likely × impact medium = elevated; data breach improbable via token_store, storefront, payment_api

</details>

<details><summary><code>missing-content-security-policy@storefront</code> — Storefront web app serves pages without a content security policy</summary>

The application ships no policy telling the browser where script may come from, so a single injection flaw anywhere in the page turns straight into code execution in the user's session.

**Why it fired.** An in-scope web application that does not record uses_content_security_policy. This is a defence-in-depth control, so it fires independently of whether output encoding is in place; the two mitigate the same class of bug at different layers and both are worth having.

**Mitigation.** Serve a policy with a nonce-based script-src and no unsafe-inline, then tighten frame-ancestors, base-uri and form-action. Start in report-only mode against real traffic rather than guessing at the directive set.

**Action.** Add a Content-Security-Policy header with a nonce-based script-src.

**Check.** Load the application and confirm the header is present, then check the report endpoint for violations from normal use.

**When this is wrong.** APIs that never return HTML, single-purpose endpoints with no browser surface, and applications where the policy is set by a reverse proxy the model does not draw. The first two are better modelled as a web service than as a web application.

**References.** CWE-1021 · CAPEC-63 · ASVS V14.4.3 · https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html

**Rating.** likelihood likely × impact medium = elevated; data breach improbable via storefront

</details>

<details><summary><code>missing-hardening@payment_api</code> — Payment API is an attractive target with no recorded hardening</summary>

One of the most attractive assets in the model does not record that it has been hardened, so it is probably running whatever its base image, package manager and framework defaults gave it.

**Why it fired.** An in-scope, non-human, non-client element that does not record the hardened control, is among the most attractive assets in the model, and is independently worth hardening: it either holds data classified confidential or above, is rated critical for integrity, or is reachable from the internet. The second test is what stops this rule scaling with the model rather than with the risk. Attractiveness is normalised across the model, so some asset always scores 100 and a bare rank threshold would select roughly the same fraction of every model it ever runs on, however benign. Pairing rank with an absolute property means a system of uniformly low-value assets produces no finding at all.

**Mitigation.** Apply a published benchmark — CIS, the vendor's, your own written one — remove packages and listeners the asset does not need, run as a non-root user with a read-only root filesystem, and re-check the configuration on every deploy rather than once at build time.

**Action.** Apply and record a hardening baseline for this asset.

**Check.** Run the benchmark's scoring tool against a running instance and keep the report.

**When this is wrong.** Assets built from an image that is hardened centrally, where the control is true and simply unrecorded, and managed services where the provider owns the configuration. Record hardened: true with a pointer to the benchmark, which is more useful to the next reader than a suppression.

**References.** CWE-1188 · CAPEC-1 · ASVS V14.1.3 · https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html

**Rating.** likelihood likely × impact high = elevated; data breach possible via payment_api

</details>

<details><summary><code>missing-hardening@token_store</code> — Token store is an attractive target with no recorded hardening</summary>

One of the most attractive assets in the model does not record that it has been hardened, so it is probably running whatever its base image, package manager and framework defaults gave it.

**Why it fired.** An in-scope, non-human, non-client element that does not record the hardened control, is among the most attractive assets in the model, and is independently worth hardening: it either holds data classified confidential or above, is rated critical for integrity, or is reachable from the internet. The second test is what stops this rule scaling with the model rather than with the risk. Attractiveness is normalised across the model, so some asset always scores 100 and a bare rank threshold would select roughly the same fraction of every model it ever runs on, however benign. Pairing rank with an absolute property means a system of uniformly low-value assets produces no finding at all.

**Mitigation.** Apply a published benchmark — CIS, the vendor's, your own written one — remove packages and listeners the asset does not need, run as a non-root user with a read-only root filesystem, and re-check the configuration on every deploy rather than once at build time.

**Action.** Apply and record a hardening baseline for this asset.

**Check.** Run the benchmark's scoring tool against a running instance and keep the report.

**When this is wrong.** Assets built from an image that is hardened centrally, where the control is true and simply unrecorded, and managed services where the provider owns the configuration. Record hardened: true with a pointer to the benchmark, which is more useful to the next reader than a suppression.

**References.** CWE-1188 · CAPEC-1 · ASVS V14.1.3 · https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html

**Rating.** likelihood likely × impact high = elevated; data breach possible via token_store

</details>

<details><summary><code>missing-pii-encryption-at-rest@token_store</code> — Token store stores personal data with transparent encryption only</summary>

A datastore holds personal data protected by nothing stronger than transparent encryption. Transparent encryption defends against a stolen disk and against nothing else: any process holding a valid connection reads plaintext, which is the case in every application compromise.

**Why it fired.** A datastore storing at least one data asset flagged as personal data, whose recorded encryption is none or transparent, on a technology that does not declare unencrypted storage tolerated. The threshold is deliberately above transparent, unlike unencrypted-asset which fires only on none, because a regulator asking whether personal data was encrypted is not asking about the disk.

**Mitigation.** Encrypt the identifying fields in the application with keys the datastore's own credentials cannot reach, and prefer tokenisation where the value only needs to be compared rather than read. Then decide who can decrypt, which is the question the disk-level answer never asks.

**Action.** Apply field-level encryption or tokenisation to the identifying columns.

**Check.** Read the identifying columns directly with the datastore's own client and confirm they are unreadable.

**When this is wrong.** Stores where field-level encryption is applied by the application and not recorded on the element, and datasets already pseudonymised such that the stored values do not identify anyone. In the second case model the stored asset as the pseudonymised one rather than the original.

**References.** CWE-311 · CAPEC-37 · ASVS V6.2 · https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html

**Rating.** likelihood likely × impact high = elevated; data breach probable via token_store

</details>

<details><summary><code>missing-waf@storefront</code> — Storefront web app faces the internet with no web application firewall in front</summary>

A publicly reachable application takes web traffic with nothing in front to filter it, so a newly published exploit reaches the code the day it is released and stays reachable until the code ships.

**Why it fired.** An internet-facing element that is a web application or web service, is not itself a WAF, and has no incoming flow originating from one. A WAF is compensating rather than primary, so this rule is deliberately independent of whether the application's own input handling is recorded.

**Mitigation.** Put a WAF or schema-validating gateway in front, run it in blocking mode against known signatures, and treat the rules as a place to apply a virtual patch quickly rather than as a permanent substitute for fixing the code.

**Action.** Deploy a WAF or gateway in front of the application and record it in the model.

**Check.** Send a request that the rule set should block and confirm it never reaches the application log.

**When this is wrong.** Applications behind a managed edge — a CDN with rules enabled, a cloud load balancer with a policy attached — that the model does not draw as an element, and APIs where a schema-validating gateway does the same job under a different name. Add the edge as an element with the waf or gateway technology and the finding retires.

**References.** CWE-693 · CAPEC-1 · ASVS V1.14.6 · https://cheatsheetseries.owasp.org/cheatsheets/Virtual_Patching_Cheat_Sheet.html

**Rating.** likelihood likely × impact medium = elevated; data breach improbable via storefront

</details>

<details><summary><code>pii-crossing-untrusted-boundary@api_to_processor</code> — api_to_processor carries personal data to Card processor outside the estate</summary>

Personal data leaves the estate for an asset on an untrusted network. Once it lands there, what happens to it is governed by someone else's retention policy, someone else's access control and someone else's breach notification.

**Why it fired.** A non-response flow carrying at least one data asset flagged as personal data, whose destination is internet-facing or sits in a boundary typed network-untrusted, where the source is not itself internet-facing. Excluding internet-facing sources keeps the ordinary case — a user's own browser sending their own data in — out of the results.

**Mitigation.** Send the least you can: a token or a hashed identifier rather than the record, fields the recipient actually uses rather than the object you happen to have. Encrypt in transit, pin the recipient, and record the lawful basis, the retention period and the deletion path before the first transfer rather than after the first question.

**Action.** Minimise and tokenise the payload, and record the basis for this transfer.

**Check.** Capture one real request and confirm every personal data field in it is needed by the recipient.

**When this is wrong.** Transfers to a processor under a contract that already covers them, and destinations modelled as untrusted only because the model has one boundary for everything external. In the first case the finding is still the right anchor for recording the contract and the lawful basis.

**References.** CWE-359 · CAPEC-117 · ASVS V8.3 · https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html

**Rating.** likelihood likely × impact high = elevated; data breach probable via payment_api, processor

</details>

<details><summary><code>pii-retention-unbounded@customer_profile</code> — Personal data customer_profile is stored in volume with no owner</summary>

A large body of personal data is held durably and no owner is recorded. Retention periods do not enforce themselves; they are enforced by someone whose job it is, and the model does not say who that is.

**Why it fired.** A data asset flagged as personal data, stored by at least one in-scope element, with a quantity of many or more and no owner recorded. Durable storage is what makes retention a question at all — data that only passes through has no retention period to exceed — and volume is what makes the accumulated liability material.

**Mitigation.** Name an owner, set a retention period in the store rather than in a document, and implement deletion as a scheduled job that proves it ran. Confirm that a deletion request reaches replicas, exports, caches, analytics copies and backups, since those are where the data survives the policy.

**Action.** Assign an owner and enforce a retention period in the storage layer.

**Check.** Confirm records older than the intended period are absent from the store and from its backups.

**When this is wrong.** Assets governed by a retention policy held outside the model, and stores where deletion is automatic at the platform level — a TTL on the table, a lifecycle rule on the bucket. Naming an owner on the data asset costs one line and makes the next reviewer's job possible.

**References.** CWE-359 · CAPEC-118 · ASVS V8.3 · https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html

**Rating.** likelihood likely × impact high = elevated; data breach probable via token_store, storefront, payment_api

</details>

<details><summary><code>sql-nosql-injection@batch_to_token_store</code> — Nightly settlement batch may build injectable queries against Token store</summary>

Custom code builds a query for a datastore from data it received, so a caller who controls that data controls the query.

**Why it fired.** A flow to a datastore over a query protocol, where the calling asset contains custom-developed code and does not record that it uses parameterised queries. The rule fires as a confirmed finding when the control is recorded absent, and as a low-confidence finding when nobody has recorded it either way.

**Mitigation.** Use parameterised statements or an ORM binding for every query, and never build one by string concatenation.

**Action.** Replace concatenated query construction in the calling service.

**Check.** Search the caller for string-built queries and confirm each uses bound parameters.

**When this is wrong.** Callers that only ever issue static queries with no interpolated values, and callers whose data layer is a mature ORM used without raw query escapes. Record uses_parameterized_queries on the caller to settle it.

**References.** CWE-89 · CAPEC-66, CAPEC-7 · ASVS V5.3.4 · https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

**Rating.** likelihood likely × impact very-high = elevated; data breach probable via settlement_batch, token_store

</details>

<details><summary><code>unencrypted-communication@api_to_token_store</code> — Unencrypted sql-access-protocol link from Payment API to Token store</summary>

Sensitive data crosses a network on a protocol that offers no confidentiality, so anyone positioned on the path can read it and, absent integrity protection, change it.

**Why it fired.** A flow whose protocol is not encrypted, is not confined to one process or host, and carries either credentials or data classified confidential or above. Flows into a technology that tolerates plaintext by design, such as an IoT sensor feed, are skipped, as are flows already inside a VPN.

**Mitigation.** Use the encrypted variant of the protocol with TLS 1.2 or better, and prefer mutual authentication where both ends are services you operate.

**Action.** Terminate TLS at the receiving asset rather than at a proxy in front of it.

**Check.** Capture traffic on the link and confirm the handshake and cipher suite.

**When this is wrong.** Links inside a single host, over a dedicated hardware channel, or already wrapped by a service mesh that terminates mutual TLS transparently. If a mesh handles it, record the protocol as its encrypted variant rather than suppressing the rule.

**References.** CWE-319 · CAPEC-117, CAPEC-157 · ASVS V9.1 · https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html

**Rating.** likelihood likely × impact medium = elevated; data breach probable via payment_api, token_store

</details>

<details><summary><code>unencrypted-communication@batch_to_token_store</code> — Unencrypted sql-access-protocol link from Nightly settlement batch to Token store</summary>

Sensitive data crosses a network on a protocol that offers no confidentiality, so anyone positioned on the path can read it and, absent integrity protection, change it.

**Why it fired.** A flow whose protocol is not encrypted, is not confined to one process or host, and carries either credentials or data classified confidential or above. Flows into a technology that tolerates plaintext by design, such as an IoT sensor feed, are skipped, as are flows already inside a VPN.

**Mitigation.** Use the encrypted variant of the protocol with TLS 1.2 or better, and prefer mutual authentication where both ends are services you operate.

**Action.** Terminate TLS at the receiving asset rather than at a proxy in front of it.

**Check.** Capture traffic on the link and confirm the handshake and cipher suite.

**When this is wrong.** Links inside a single host, over a dedicated hardware channel, or already wrapped by a service mesh that terminates mutual TLS transparently. If a mesh handles it, record the protocol as its encrypted variant rather than suppressing the rule.

**References.** CWE-319 · CAPEC-117, CAPEC-157 · ASVS V9.1 · https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html

**Rating.** likelihood likely × impact medium = elevated; data breach probable via settlement_batch, token_store

</details>

<details><summary><code>unguarded-direct-datastore-access@api_to_token_store</code> — Payment API reaches Token store directly across a network boundary</summary>

An asset an attacker can reach from the internet talks straight to a sensitive datastore across a network boundary, so one application compromise becomes a database session with the application's full grants.

**Why it fired.** A non-response flow into a datastore holding confidential or better data, where the caller is reachable from an internet-facing element, is not itself a datastore or a gateway, and the link crosses a network trust boundary. Reachability rather than direct exposure is the test, because the interesting case is the second hop: a web tier that is not itself public but sits one call away from something that is.

**Mitigation.** Give the caller a database role limited to the exact tables and operations it uses, restrict the datastore's listener to the caller's addresses or identities, and put reads that do not need to be live behind a cache or a view.

**Action.** Scope the caller's database grants to least privilege and restrict the listener.

**Check.** With the caller's credential, attempt a read outside its normal tables and confirm it is denied.

**When this is wrong.** Architectures where the caller is the datastore's intended and only client and the boundary crossing is an artefact of coarse modelling — a service and its own database drawn in separate subnets. The finding still asks a fair question there: whether the caller's grants are scoped to the rows it actually needs.

**References.** CWE-1220 · CAPEC-116 · ASVS V1.2.2 · https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html

**Rating.** likelihood likely × impact medium = elevated; data breach probable via payment_api, token_store

</details>

### 🟦 medium (6)

| ID | Title | Subject | STRIDE | CWE | Status | Confidence |
| --- | --- | --- | --- | --- | --- | --- |
| `dos-risky-access-across-trust-boundary@api_to_token_store` | Token store accepts unthrottled traffic over api_to_token_store | Token persistence (flow) | denial-of-service | CWE-770 | unchecked | low |
| `incomplete-model@settlement_batch` | Nightly settlement batch records no security controls at all | Nightly settlement batch (element) | repudiation | CWE-1059 | unchecked | high |
| `missing-build-infrastructure@model` | Payment Service builds custom code with no build pipeline modelled | Payment Service (model) | tampering | CWE-1357 | unchecked | high |
| `missing-identity-store@model` | Payment Service authenticates callers but models no identity store | Payment Service (model) | spoofing | CWE-1059 | unchecked | high |
| `weak-authentication@api_to_token_store` | Payment API authenticates to Token store with a static credential | Token persistence (flow) | spoofing | CWE-287 | unchecked | high |
| `weak-authentication@batch_to_token_store` | Nightly settlement batch authenticates to Token store with a static credential | Nightly read (flow) | spoofing | CWE-287 | unchecked | high |

<details><summary><code>dos-risky-access-across-trust-boundary@api_to_token_store</code> — Token store accepts unthrottled traffic over api_to_token_store</summary>

Traffic crosses a network boundary into an asset the business needs available, and nothing on either the link or the target records a limit on how much of it there can be.

**Why it fired.** A non-response flow crossing a network trust boundary into an in-scope asset rated critical or better for availability, where the caller either comes from an untrusted network or is reachable from an internet-facing element, and neither the link nor the target records rate_limited. When neither has been recorded the finding is raised at low confidence and names the missing fields.

**Mitigation.** Rate limit per caller identity rather than per address, set concurrency and payload size caps, and shed load at the edge so the pressure never reaches the asset you care about. Load shedding that returns quickly beats a queue that grows.

**Action.** Apply a per-identity rate limit and a concurrency cap on this path.

**Check.** Drive the endpoint past the intended limit and confirm it returns a throttling response rather than degrading.

**When this is wrong.** Links whose volume is bounded by construction — a scheduled batch, a queue consumer pulling at its own pace — and paths already throttled by a platform layer the model does not draw, such as a mesh or an ingress controller. Record rate_limited on the flow in that case.

**References.** CWE-770 · CAPEC-125, CAPEC-227 · ASVS V11.1.4 · https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html

**Rating.** likelihood unlikely × impact medium = medium; data breach improbable via payment_api, token_store

</details>

<details><summary><code>incomplete-model@settlement_batch</code> — Nightly settlement batch records no security controls at all</summary>

Nothing is recorded about this element's security controls. Not that they are absent — that nobody has said either way, so every rule that asks about them can only shrug, and the element passes the analysis by being undescribed rather than by being safe.

**Why it fired.** An in-scope, non-human, non-client element for which none of six baseline controls is recorded: validates_input, has_access_control, logs_security_events, hardened, monitored and uses_secure_defaults. The test is known(), not the control's value, so recording any one of them as false — an honest answer — retires the finding, while silence does not. The threshold is all six rather than some, so this fires only on elements nobody has assessed at all.

**Mitigation.** Answer the six questions for this element, with false where the answer is false. A recorded false produces a confident finding that someone can act on, which is far more useful than a blank that produces nothing.

**Action.** Fill in the element's controls block, recording false where a control is genuinely absent.

**Check.** Read the finished controls block back to whoever operates the asset and confirm they agree.

**When this is wrong.** Elements deliberately kept coarse because they are somebody else's responsibility, which is better expressed by marking them out of scope with a justification, and trivial components — a static file mount, an embedded library — where the six questions genuinely do not apply.

**References.** CWE-1059 · CAPEC-116 · ASVS V1.1.2 · https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html

**Rating.** likelihood likely × impact low = medium; data breach improbable via settlement_batch

</details>

<details><summary><code>missing-build-infrastructure@model</code> — Payment Service builds custom code with no build pipeline modelled</summary>

The model contains code this team writes and nothing that builds it. Whatever turns that source into what runs in production is outside the review, which means so are its credentials, its dependencies and whoever can trigger it.

**Why it fired.** A model-level check: at least one in-scope element is marked as containing custom code, and no element in the model carries the build pipeline role. Build systems are routinely omitted from threat models because they are not part of the running system, which is exactly why they make good targets.

**Mitigation.** Model the build system, then treat it as production infrastructure: authenticated and authorised triggers, isolated runners per trust level, signed artefacts, and no standing credentials that a pull request can reach.

**Action.** Add the build pipeline to the model, in scope or explicitly out of it.

**Check.** Trace one deployed artefact back to the job that produced it and name every identity that could have triggered that job.

**When this is wrong.** Models scoped deliberately to the runtime, and estates where the build is a shared platform reviewed under its own threat model. Both are reasonable; add the pipeline as an out-of-scope element with a justification so the omission is a decision on the record rather than an oversight.

**References.** CWE-1357 · CAPEC-444 · ASVS V14.2.1 · https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html

**Rating.** likelihood unlikely × impact high = medium; data breach possible

</details>

<details><summary><code>missing-identity-store@model</code> — Payment Service authenticates callers but models no identity store</summary>

Links in this model authenticate their callers, but nothing in it is an identity provider or identity store. Something is deciding who these callers are, and the model does not say what, so nobody is reviewing how it does it.

**Why it fired.** A model-level check: at least one flow authenticates with credentials, a session id or a token, and no element carries the identity provider or identity store role. This is a completeness finding rather than a vulnerability — the component almost certainly exists, and the risk is that it exists outside the boundary of anything anyone reviews.

**Mitigation.** Add the component that verifies these credentials to the model — even as an external, out-of-scope element — so the rules about isolation, storage and second factors have something to attach to.

**Action.** Model the identity provider or store that backs these authenticated links.

**Check.** For one authenticated flow, name the system that holds the credential it verifies, and confirm that system appears in the model.

**When this is wrong.** Models that scope out authentication on purpose, systems where every credential is verified by a third party covered elsewhere, and mutual-TLS estates where the certificate authority is the identity store and has not been drawn. Model the authority, or scope the omission out explicitly, rather than ignoring it.

**References.** CWE-1059 · CAPEC-593 · ASVS V2.1 · https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

**Rating.** likelihood unlikely × impact medium = medium; data breach improbable

</details>

<details><summary><code>weak-authentication@api_to_token_store</code> — Payment API authenticates to Token store with a static credential</summary>

A caller proves itself to a crown-jewel asset with a static username and password. That secret is replayable, it lives in configuration, and it does not expire when the caller does.

**Why it fired.** A non-local, non-response flow authenticating with credentials into a technology the catalogue marks a high-value target, where the link carries data classified confidential or above and the target is reachable from an internet-facing asset. The combination matters: a password is acceptable on a low-value internal link and is not acceptable on the path to the asset an attacker actually wants.

**Mitigation.** Replace the static secret with a workload identity: mutual TLS between services, or a short-lived token minted per connection. Where the datastore cannot do that, at least sink the password into a vault and rotate it on a schedule the team can prove.

**Action.** Move this link to certificate or token authentication.

**Check.** Rotate the credential and confirm the caller keeps working without a redeploy; that is only true when it fetches the secret at runtime.

**When this is wrong.** Links where "credentials" stands in for a short-lived, automatically rotated secret issued by the platform — a cloud IAM database password rotated every hour is closer to a token than to a password. Record those as token, or as client-certificate where mutual TLS is in play.

**References.** CWE-287 · CAPEC-560, CAPEC-49 · ASVS V2.2 · https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

**Rating.** likelihood unlikely × impact medium = medium; data breach possible via payment_api, token_store

</details>

<details><summary><code>weak-authentication@batch_to_token_store</code> — Nightly settlement batch authenticates to Token store with a static credential</summary>

A caller proves itself to a crown-jewel asset with a static username and password. That secret is replayable, it lives in configuration, and it does not expire when the caller does.

**Why it fired.** A non-local, non-response flow authenticating with credentials into a technology the catalogue marks a high-value target, where the link carries data classified confidential or above and the target is reachable from an internet-facing asset. The combination matters: a password is acceptable on a low-value internal link and is not acceptable on the path to the asset an attacker actually wants.

**Mitigation.** Replace the static secret with a workload identity: mutual TLS between services, or a short-lived token minted per connection. Where the datastore cannot do that, at least sink the password into a vault and rotate it on a schedule the team can prove.

**Action.** Move this link to certificate or token authentication.

**Check.** Rotate the credential and confirm the caller keeps working without a redeploy; that is only true when it fetches the secret at runtime.

**When this is wrong.** Links where "credentials" stands in for a short-lived, automatically rotated secret issued by the platform — a cloud IAM database password rotated every hour is closer to a token than to a password. Record those as token, or as client-certificate where mutual TLS is in play.

**References.** CWE-287 · CAPEC-560, CAPEC-49 · ASVS V2.2 · https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

**Rating.** likelihood unlikely × impact medium = medium; data breach possible via settlement_batch, token_store

</details>

## Low-confidence findings

A low-confidence finding is not a weaker risk. It is a rule that could not settle its
condition because the model does not record the control it asks about, so tmac reports
the possibility rather than inventing a `false`. Filling in the fields below either
removes the finding or promotes it to a confirmed one; leaving them blank keeps the
question open forever.

**Unrecorded fields, most consequential first.**

| Field | Findings it would settle |
| --- | --- |
| `flow.controls.rate_limited` | 3 |
| `el.controls.hardened` | 2 |
| `el.controls.uses_code_signing` | 2 |
| `el.controls.verifies_dependencies` | 2 |
| `flow.controls.uses_mfa` | 2 |
| `flow.from.controls.uses_parameterized_queries` | 1 |
| `flow.to.controls.rate_limited` | 1 |
| `m.controls.hardened` | 1 |

**The findings themselves.**

| ID | Title | Severity | Unrecorded |
| --- | --- | --- | --- |
| `missing-authentication-second-factor@ops_to_api` | Operations console signs in to Payment API with a single factor | high | `flow.controls.uses_mfa` |
| `missing-authentication-second-factor@shopper_to_storefront` | Shopper signs in to Storefront web app with a single factor | high | `flow.controls.uses_mfa` |
| `container-baseimage-backdooring@payment_api` | Payment API runs a container image with no recorded provenance check | elevated | `el.controls.uses_code_signing`, `el.controls.verifies_dependencies` |
| `container-baseimage-backdooring@storefront` | Storefront web app runs a container image with no recorded provenance check | elevated | `el.controls.uses_code_signing`, `el.controls.verifies_dependencies` |
| `dos-risky-access-across-trust-boundary@ops_to_api` | Payment API accepts unthrottled traffic over ops_to_api | elevated | `flow.controls.rate_limited` |
| `dos-risky-access-across-trust-boundary@storefront_to_api` | Payment API accepts unthrottled traffic over storefront_to_api | elevated | `flow.controls.rate_limited` |
| `missing-cloud-hardening@vpc` | Production VPC has no recorded cloud hardening baseline | elevated | `m.controls.hardened` |
| `missing-hardening@payment_api` | Payment API is an attractive target with no recorded hardening | elevated | `el.controls.hardened` |
| `missing-hardening@token_store` | Token store is an attractive target with no recorded hardening | elevated | `el.controls.hardened` |
| `sql-nosql-injection@batch_to_token_store` | Nightly settlement batch may build injectable queries against Token store | elevated | `flow.from.controls.uses_parameterized_queries` |
| `dos-risky-access-across-trust-boundary@api_to_token_store` | Token store accepts unthrottled traffic over api_to_token_store | medium | `flow.controls.rate_limited`, `flow.to.controls.rate_limited` |

## Risk tracking

Nothing in this model has been triaged yet: all 31 risks are unchecked. Record a decision in `risk_tracking` as each one is dealt with.

## Data asset matrix

| Asset | Classification | Integrity | Availability | Quantity | Flags | Processed by | Stored by | In transit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **card_data** | strictly-confidential | critical | important | many | PII, pci-dss | Storefront web app, Payment API, Card processor | — | Checkout, Tokenise, Processor tokenisation |
| **payment_token** | confidential | critical | critical | very-many | — | Payment API, Nightly settlement batch, Card processor | Token store | Token persistence, Checkout, Tokenise, Processor tokenisation, Nightly read |
| **customer_profile** | restricted | important | important | many | PII, gdpr | Storefront web app, Payment API | Token store | Checkout, Token persistence, Operator access |
| **processor_credentials** | strictly-confidential | mission-critical | critical | very-few | credentials | Payment API | — | Processor tokenisation |
| **audit_log** | internal | critical | important | very-many | — | Nightly settlement batch | Audit log store | Audit write |

## Assumptions

Every finding below rests on these. If one turns out to be false, re-run the analysis.

- **A1.** The processor terminates TLS with a pinned certificate and is covered by its own attestation, so we do not raise transport findings on that hop.

## Open questions

| Question | Answer |
| --- | --- |
| Does the settlement batch require the full pan, or will a token do? | **Unanswered** |
| Who rotates the processor API credentials, and how often? | Platform team, quarterly. |

1 of 2 still unanswered.

## Abuse cases

| Case | Description |
| --- | --- |
| Carding | An attacker uses the checkout endpoint to test stolen card numbers in bulk. |
| Insider export | An operator with database access exports the token vault. |

## Security requirements

| Requirement | Statement |
| --- | --- |
| PCI DSS 3.4 | Primary account numbers are never written to durable storage. |
| Least privilege | Every service account holds only the grants its job needs. |

## Elements

RAA is Relative Attacker Attractiveness: where an attacker would spend a foothold if
they had one. It is normalised across this model, so the numbers rank elements against
each other and mean nothing against another model.

| Element | Kind | Technology | RAA | Confidentiality | Integrity | Availability | Trust boundary | Internet | Risks |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Payment API** | process | web-service-rest | 100 | strictly-confidential | mission-critical | critical | Web tier namespace | reachable | 6 |
| **Token store** | datastore | database | 99 | confidential | critical | critical | Data tier subnet | reachable | 9 |
| **Nightly settlement batch** | process | batch-processing | 75 | confidential | critical | critical | Production VPC | no | 2 |
| **Storefront web app** | process | web-application | 73 | strictly-confidential | critical | important | Web tier namespace | facing | 7 |
| **Audit log store** | datastore | database | 47 | internal | critical | important | Data tier subnet | reachable | 0 |
| **Operations console** | external | devops-client | 34 | public | archive | archive | Public internet | no | 0 |
| Card processor _(out of scope)_ | external | web-service-rest | 24 | strictly-confidential | critical | critical | Public internet | reachable | 1 |
| **Shopper** | actor | browser | 21 | public | archive | archive | Public internet | facing | 0 |

## Shared runtimes

Elements sharing a runtime share its blast radius: a compromise of one is a foothold
in all of them.

| Runtime | Runs |
| --- | --- |
| Payments Kubernetes cluster | Storefront web app, Payment API, Nightly settlement batch |

---

Generated by tmac from `the model` at 2026-09-06T12:00:00Z. Risk ids are derived from the rule and the model ids it concerns, so they survive a regeneration and can be tracked in `risk_tracking`.
