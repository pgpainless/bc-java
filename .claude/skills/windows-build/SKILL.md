---
name: windows-build
description: Use when building or testing bc-java on a Windows checkout driven from Claude Code's Git Bash and PowerShell tools — docs/claude/build-and-test.md describes a Linux box and its paths don't apply. Covers driving gradlew from Bash vs PowerShell, restricting a module :test run to one JDK, checking the results are this run's, a fast single-class JUnit loop through PowerShell (Git Bash mangles the ;-separated classpath), running hang-prone test classes with per-process logs and the Wait-Process trap, and the CRLF / Glob tooling traps specific to this setup.
---

# Building and testing bc-java on Windows

[docs/claude/build-and-test.md](../../../docs/claude/build-and-test.md) is written for a Linux machine, so
uses Linux paths for JDKs, tools and scripts. Everything there about *what* to run and how to verify a run still
applies; this skill covers *how* to run it from a Windows checkout through Claude Code's two shell tools.

## Gradle

Either shell tool drives Gradle: `./gradlew <task>` from the Bash tool or `.\gradlew.bat <task>` from PowerShell,
at the repo root. Both use whatever `JAVA_HOME` / `java` on PATH resolves to, so no override is needed when that
is a supported JDK (check with `java -version` first). Gradle's arguments never contain `;`, so the Bash
classpath-mangling problem below does not apply here, and Bash is the simpler choice for a Gradle invocation
whose output you want in a log. **In PowerShell 5.1 do not append `2>&1` to gradlew.bat**: the first javac
warning on stderr gets wrapped as a `NativeCommandError` record (a `.\gradlew.bat : warning: [options] ...` line
followed by `CategoryInfo` / `FullyQualifiedErrorId`), and `$?` reads false on a successful build. Stderr is
captured for you without the redirect.

### Running under one JDK only

With every `BC_JDK*` variable defined (see build-and-test.md for what each adds to a module `:test`), a full
`:<module>:cleanTest :<module>:test` takes several minutes; prefer the single-class loop below while iterating. To
restrict a run to the newest JDK, remove every other `BC_JDK*` variable in the same tool call as gradlew
(`Remove-Item Env:BC_JDK8, Env:BC_JDK11, ... -ErrorAction SilentlyContinue` in PowerShell,
`env -u BC_JDK8 -u BC_JDK11 ... ./gradlew ...` in Bash); Gradle forwards the client's environment to a reused
daemon. The configure phase echoes what it saw (`Looking for JDK ENV 'BC_JDK8' found null`,
`<module>: Adding testNN as dependency for test task ...`) - read those lines to confirm the task set before
waiting on the run. Clean the newest task's results too (`cleanTestNN`); `cleanTest` covers only the base task.

### Verifying the run

build-and-test.md's UP-TO-DATE and HEAD-moves warnings apply verbatim, and so does its result layout (flat XML
directory shared by every Test task, per-task HTML index). On this side, `LastWriteTime` is the tool: report
directories from earlier runs persist beside this run's and only the timestamp tells them apart, so compare
against the run's start rather than checking presence. For totals, load each `TEST-*.xml` with
`[xml](Get-Content ...)` and sum `testsuite.tests` / `.failures` / `.errors`, or read the per-task HTML index.

A multi-minute Gradle run goes through the Bash tool's `run_in_background` with output redirected to a scratchpad
log and an `exit: $?` line appended; read the log when the completion notification arrives rather than polling.

## Fast single-class JUnit loop (PowerShell, not Bash)

`junit.textui.TestRunner` on one class avoids the `AllTests` include restriction described in build-and-test.md.
It needs a `;`-separated classpath, and **the Bash tool (Git Bash/MSYS) mangles `;`-separated arguments**: the
run fails with `ClassNotFoundException` even though every jar is present. Always drive it through the
PowerShell tool with backslash paths.

Compile first (`.\gradlew.bat :<module>:compileTestJava -q`), then:

```powershell
$cache = "$env:USERPROFILE\.gradle\caches\modules-2\files-2.1"
$junit = (Get-ChildItem "$cache\junit\junit" -Recurse -Filter 'junit-4.*.jar' |
  Where-Object Name -notmatch 'sources' | Select-Object -First 1).FullName
$hamcrest = (Get-ChildItem "$cache\org.hamcrest\hamcrest-core" -Recurse -Filter 'hamcrest-core-*.jar' |
  Where-Object Name -notmatch 'sources' | Select-Object -First 1).FullName

# core FIRST (see the core-into-prov trap in build-and-test.md), then util/prov/pkix/tls main, then the
# module's test classes. Add prov\build\resources\main for tests that load provider resources.
$CP = "core\build\classes\java\main;util\build\classes\java\main;prov\build\classes\java\main;" +
      "prov\build\resources\main;pkix\build\classes\java\main;tls\build\classes\java\main;" +
      "tls\build\classes\java\test;$junit;$hamcrest"

foreach ($t in 'org.bouncycastle.tls.test.DTLSTestSuite', 'org.bouncycastle.tls.test.DTLSProtocolTest') {
  "== $t"
  java -cp $CP junit.textui.TestRunner $t 2>&1 | Select-String '^OK \(|^Tests run|FAILURES'
}
```

Filter out `-sources` jars when searching the Gradle cache; they sit beside the binaries. The whole DTLS battery
(`DTLSTestSuite` plus the individual `DTLS*Test` classes) runs in seconds this way: the tests bound their own
handshake resends and stalls, so a DTLS test that runs for minutes is a real problem, not bad luck.

## Tests that may hang

Launch each class as its own process with a log file, so a stuck one can be inspected without losing the others:

```powershell
$p = Start-Process java -ArgumentList "-cp `"$CP`" junit.textui.TestRunner $t" `
  -RedirectStandardOutput "$env:TEMP\$t.log" -PassThru -NoNewWindow
```

Then wait **per process id**. `Wait-Process -Id $a,$b` inside try/catch returns immediately (it throws
"cannot find a process") as soon as any listed pid has already exited, so a "wait N seconds, then check" loop can
silently take no time at all and make a stall look several times longer than it was. `jstack <pid>` on the
suspect JVM is the
definitive answer to "hung or slow".

## Tooling traps on this setup

- **The working copy is CRLF** (`core.autocrlf=true`). Use the Edit/Write tools for source edits. `sed -i` and
  `perl -0pi` rewrite the file to LF (a user-level hook denies them), and a `\n` regex silently matches nothing
  across CRLF lines.
- **The Glob tool has returned no matches for files that exist** (drive-letter casing is the suspect). Use Grep,
  or `Get-ChildItem -Recurse -Include` in PowerShell.
- **Shell state does not persist between tool calls.** Set `$CP` and run `java` in the same PowerShell call.
  The same goes for `Remove-Item Env:...`: it must be in the call that launches gradlew.
- **`Out-File -Encoding utf8` in PowerShell 5.1 writes a BOM.** A log written that way starts with U+FEFF, so
  `grep '^HEAD'` misses the first line. Write logs from Bash, or start the file with a throwaway line.
