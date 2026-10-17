# Mutation Testing Report - Specialization B

## Executive Summary

I used mutation testing to check whether my tests detect small changes to the
whitespace watermark code. The final run generated 137 mutations: 85 were
killed, 43 survived, and 9 had no tests. I added tests for non-text secrets
and keys after identifying gaps in those checks. No application-code bug was
confirmed or fixed during this focused work.

## 1. Mutation Testing Tool Configuration

- **Tool:** mutmut 3.8.0
- **Python:** 3.12
- **Test framework:** pytest
- **Configuration file:** `server/pyproject.toml`
- **Code tested:** `src/whitespace_watermark.py`
- **Tests run:** `test/test_whitespace_watermark.py`

The configuration limited mutations to the whitespace watermark and selected
its focused test file. Other watermark methods were not included.

## 2. Results & Progress

| Result | Count |
| --- | ---: |
| Total mutations | 137 |
| Killed by tests | 85 |
| Survived | 43 |
| No tests reached the mutation | 9 |

The mutation score was **62.0%** (85 of 137). Excluding the 9 mutations with
no tests, the score was **66.4%** (85 of 128). All 5 focused tests passed.

## 3. Collection of Interesting Mutants

- **Secret validation:** A mutant changed the condition from `or` to `and`.
  It survived before I added a test for a non-text secret. The new test then
  caused this kind of invalid-input change to be caught.
- **Key validation:** A similar `or` to `and` change showed that a non-text
  key was not covered. I added a test for this case.
- **Error message:** A mutant changed the secret error message by adding
  `XX`. It survived because the test checks for the expected text within the
  message. This changed only the wording and was not treated as an
  application-code bug.

## 4. Collection of Bugs Discovered

- **Test-suite gaps:** Before the new tests, the suite did not check rejection
  of non-text secrets or keys.
- **Application-code bugs:** None were confirmed by this focused run.

## 5. Collection of Fixes

- Added a test that checks a non-text secret is rejected.
- Added a test that checks a non-text key is rejected.
- No application-code changes were made as a result of these findings.

## Key Findings

### What Mutation Testing Revealed

The existing tests covered successful recovery, a wrong key, and a missing
watermark, but initially did not check invalid secret and key types. The added
tests cover those cases. Some mutations to error-message text still survive.

### Impact

The additional tests improve checks for invalid inputs in the whitespace
watermark. The results apply only to this method and its focused tests; they
do not establish that the other watermark methods are fully tested.

## Conclusion

Mutation testing helped me identify and address two gaps in the whitespace
watermark tests. The focused test file passed all 5 tests after the additions.
