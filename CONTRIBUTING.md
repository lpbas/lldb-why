# Contributing

Thanks for helping `why` recognize more crashes. The most useful contribution
is a new crash signature with a fixture that proves it.

## Ground rules

* `why/core` must not import `lldb`. Everything it needs comes in through
  `CrashContext`. If a rule needs new data, add a field to `CrashContext`
  (`why/core/model.py`) and gather it in `why/lldb_adapter/gather.py`.
* Stay compatible with the Python that ships with Xcode's lldb (3.9): no
  `match`, no `X | Y` type unions, no third-party packages.
* Verify lldb behavior before relying on it, and write it down in
  `docs/FINDINGS.md`. Several obvious assumptions turned out to be wrong.
* Output is plain text first. Keep verdicts to one line, and keep each next
  step one actionable sentence.

## Adding a rule

1. **Reproduce the crash under lldb** and capture it:

   ```
   (lldb) command script import /path/to/lldb-why/why
   (lldb) run
   ... crash ...
   (lldb) why dump-context --expect --anonymize -o tests/unit/fixtures/my_case.json
   ```

   Keep fixtures small: avoid deep recursion (tens of thousands of frames), or
   build the context in a unit test with the helpers in `tests/unit/builders.py`.

2. **Add a `Rule` to `RULES`** in `why/core/rules.py`, above any more general
   rule that would otherwise match first:

   ```python
   Rule(
       id="my-signature",            # stable, kebab-case
       category="trap",              # bad_access | trap | abort | arithmetic | resource | other | not-a-crash | any
       when=lambda f: f.top_match(6, [r"^some_runtime_function"]),
       verdict="Plain-English verdict mentioning {user_name}",
       confidence="high",            # or a callable(facts) -> "high" | "medium" | "low"
       evidence=["Extra evidence lines"],
       notes=["Why this happens and what usually causes it"],
       next_steps=[Steps.ASAN, "Run `frame select 2` ..."],
   )
   ```

   * `when` receives a `Facts` object (`why/core/engine.py`) with helpers such
     as `top_match(n, patterns)`, `find_frame(patterns)`, `fault`,
     `null_offset()`, `fault_below_stack()`, `stack` (the stack report) and
     `ctx` (the raw `CrashContext`).
   * Templates use `{name}` placeholders from `Facts.variables()`, for example
     `{fault}`, `{user}`, `{user_name}`, `{queue}`, `{frame0_name}` and
     `{message}`, plus anything the rule's `vars` callable returns. Other
     braces, such as Swift code in a next step, are left alone. Unknown names
     raise an error, so typos fail the tests.
   * Any template can be a callable `(facts, variables) -> str`. Returning
     `None` or `""` drops the line.
   * Swift runtime messages and libdispatch misuse are sub-tables
     (`SWIFT_MESSAGES`, `CLIENT_BUGS`); a new message is usually one line there.

3. **Edit the fixture's `expect` block** (`rule_id`, `confidence`,
   `verdict_contains`, `user_frame`, `output_contains`). `tests/unit/test_fixtures.py`
   picks it up automatically.

4. **If you can reproduce it in Swift**, add a scenario to
   `demo/Sources/why-demo/main.swift` and to `EXPECTED` in
   `tests/integration/test_demo.py`.

5. Run the tests:

   ```bash
   python3 -m unittest discover -s tests/unit
   python3 -m unittest discover -s tests/integration -v
   ```

## Reporting a wrong verdict

Open an issue with the output of `why` and, if you can, the file from
`why dump-context --anonymize -o case.json`. Check it first: it contains
symbol names and file paths from your app.
