# Fifth-pass tests — bounded reverse seeding and mixed path forms

- Reverse the previous cache-poisoning direction: seed public variant B and
  request distinct query variant A. Record body, ETag and (OutputCaching) CSP.
- On the victim A URL, revalidate using **the ETag previously received on that
  URL**, showing whether the first incorrect representation persists through
  a 304. A 304 alone is not diagnostic without verifying the variant identity.
- Expand the #8 corpus to 23 fixed paths (case variants, mixed escaped dots /
  separators, nested segments, malformed-looking but bounded forms) on two
  real HAProxy listeners: normalized+decoded ACL vs an additional encoded
  separator deny. A HTTP 200 means a synthetic proxy-rule counterexample, not
  bypass of ASP.NET authorization.
- The test reports unexpected HTTP 200 outcomes even when they were not
  predeclared as assertions, so a new case is not hidden by pass/fail logic.

No real credentials, private records, external target or internet callbacks.
The corpus and mitigation checks are not claimed to be exhaustive.
