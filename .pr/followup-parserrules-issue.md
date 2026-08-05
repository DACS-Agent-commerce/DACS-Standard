TITLE: DACS-2 §7.6/§7.5.2 step 6 assumes all methods parse an HTTP body; make parser application conditional on method kind

## Problem

`Recipe.parserRules: ParserSpec` is a REQUIRED field (DACS-2 §7.4.1) and
`ParserSpec` is a closed union of four HTTP-body formats — `json` / `html` /
`xml` / `raw` — each with a mandatory match predicate (§7.4.1). The
attestation-resolution algorithm §7.5.2 step 6 ("parsing the response by
applying `recipe.parserRules` to extract structured data into
`VerifyResult.data`") is likewise written as though every verification method
fetches and parses an authority HTTP response body.

That assumption is already false for methods in the registry:

- `domain-tls-control` (§7.3.8) validates an ACME challenge/response transcript;
  its procedure never applies a `ParserSpec`.
- `self-signed` (§7.3.9) validates a signature over a claim assertion; its
  procedure never applies a `ParserSpec`.
- `demos-gcr-domain` (§7.3.10, added for issue #275) consumes a consensus-
  recorded Demos GCR `web2.domain` result; its procedure explicitly does not
  consume `recipe.parserRules`.

So a required, HTTP-parse-only field is imposed on at least three methods that
never apply it, and §7.5.2 step 6 describes a step those methods skip. Nothing
in the spec says what `parserRules` a non-parser recipe should carry (an inert
`raw` matcher that is never evaluated? an omitted field the schema does not
permit?), and no in-repo Recipe artifact exists to set a precedent.

## Not introduced here

This is a pre-existing inconsistency. `domain-tls-control` and `self-signed`
predate it; the #275 `demos-gcr-domain` method is only the third instance and
surfaces the wart without resolving it (resolving it was out of scope for a
domain-scheme change, and doing it there would have widened the blast radius to
every method's recipe).

## Requested change

Make `parserRules` (and the §7.5.2 step-6 parse step) conditional on method
kind. Options for the working group:

1. Make `parserRules` OPTIONAL on `Recipe`, required only for methods whose
   procedure applies a `ParserSpec` (the HTTP-fetch methods: `consensus-backed-
   proxy`, `evm-rpc`, and the body-consuming part of `verifiable-credential`);
   omitted/ignored for `domain-tls-control`, `self-signed`, `demos-gcr-domain`.
2. Add an explicit `"none"` / no-parse `ParserSpec` variant that a non-parser
   recipe carries as a declared sentinel, and gate §7.5.2 step 6 on it.
3. Split the method registry into "body-parsing" vs "self-attesting" classes and
   scope `parserRules` + §7.5.2 step 6 to the former normatively.

Whichever is chosen, §7.5.2 step 6 should say that the parse step applies only
to methods whose procedure declares it, and the §7.4.1 `Recipe` schema should
stop requiring a field that three methods never read.

## Acceptance criteria

- `parserRules` is no longer required of a method that does not apply a
  `ParserSpec`.
- §7.5.2 step 6 is explicitly conditional on method kind.
- `domain-tls-control`, `self-signed`, and `demos-gcr-domain` recipes are
  conformant without carrying an inert parser spec.
- A conformance vector covers a non-parser recipe's parser-field handling.

Refs: DACS-2 §7.3.8, §7.3.9, §7.3.10, §7.4.1, §7.5.2; issue #275.
