# Background-output drain timing

Investigated 2026-11-18 after the macOS/Python 3.10 job for candidate `3497286`
failed `test_background_job_writing_after_the_command_returned` with Bash and
`(sleep 6; cat s.txt) & echo started`. The measured 6.232 seconds exceeded the
test's 5.5-second bound; exit status, readiness output and no-raw-value assertions
passed. That run remains failed evidence, not a successful retry.

## Measurement and controls

The old timer started before `hooked.run()`, which first runs a separate
PreToolUse Python process and only then starts the rewritten command and its
runner. It therefore measured initialization as well as the background drain.
Production `GRACE_SECONDS` is 3.0 and starts after the command's status arrives.

Four unchanged local runs, instrumented with command-start/end fixture files,
measured:

| Stage | Observed duration |
| --- | --- |
| Separate PreToolUse call | 0.079–0.107 s |
| Runner launch to command start | 0.315–0.512 s |
| Foreground command body | 0.0005–0.0011 s |
| Command end to runner completion | 3.019–3.026 s |

A controlled three-second delay in the temporary fixture launcher reproduced
the old assertion failure: 6.515 seconds total, despite a 3.021-second drain
after readiness. No production file was changed. Conversely, setting the grace
period to 30 seconds in a temporary runner shim caused the post-readiness
5.5-second bound to fail while the six-second background child remained active.
These controls distinguish initialization delay from loss of bounded draining.

The CI failure log has no stage timestamps, so its precise cause—initialization,
scheduling or another delay—cannot be established retrospectively. Local results
do not prove which delay happened in that job or rule out every possible runtime
race. They do demonstrate a defect in the original test's timing boundary.

## Corrected regression

Only the test changes. A tiny fixture helper writes a shared monotonic timestamp
immediately before the original command starts. The observer waits for the real
runner's `started` line and then uses the remaining time until
**producer timestamp + 5.5 seconds**. It does not restart the timer when the line is read; a delayed
observer cannot shorten the measured drain or grant extra time.

The original commands, six-second late writer, exit-status check and raw-value
assertions remain. A separate 40-second readiness bound covers initialization.
Failure cleanup terminates both the test's isolated wrapper group and the private
command group recorded by the fixture helper. Successful cases retain the original
wait for the late writer to finish. There are no retries,
expected failures or relaxed drain thresholds. Production runner code is unchanged.

The actual revised test passed with a three-second launcher delay. A second control
disabled grace and delayed the observer's first read by two seconds; the test still
failed at its producer-based 5.5-second bound. The delayed read did not grant extra time.

An initial cleanup control found that killing only the outer group could leave a
60-second background descendant alive: the command monitor had already reported
foreground exit. That private group was explicitly terminated during diagnosis.
After recording and terminating the fixture's private command group as well, the
same control found no live group members after 0.030 seconds. The recorded PGID
matched the background descendant's actual PGID; cleanup never targets an arbitrary
user process or the test runner's own group.

Production normal grace closes the output pipes; it does not promise to terminate
every lingering background job. This test-cleanup change makes no new claim about
production cancellation after foreground completion or every termination signal.

The focused background/liveness and within-grace output tests passed (10 cases).
Local raw measurements are in
`.live/readiness-validation/drain-stage-timings.json`,
`drain-negative-controls.json`, `drain-corrected-test-controls.json` and
`drain-cleanup-control.json`.
