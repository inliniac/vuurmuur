# Testing harness for rule generation (non-root)

Status: design. Owner: TBD. Target: `make check` that exercises the iptables
ruleset generation end-to-end, as an unprivileged user, on any host, in CI and locally.

## 1. Goals

1. Deterministic coverage of the rule-generation pipeline: config tree -> object model ->
   `analyze_all_rules()` -> **the generated `iptables-restore` input file**.
2. Run **without root**, without `/etc/vuurmuur`, without `/var/run`, without a real
   `iptables` binary, without network interfaces matching any particular name or address.
3. Golden-file (snapshot) testing so that any change in generated output is explicit,
   reviewable and diffable. The restore file *is* the contract; command streams are
   secondary and temporary (legacy path goes in §8 P5).
4. Cheap enough to run on every commit (`make check`, seconds), plus sanitizer/coverage
   variants.
5. No behaviour change for production/root users, and **the seams stay test-only** - no
   user-facing `--dry-run` (decided). Every hook must be inert when the harness is not
   driving it.

Non-goals for this phase: kernel-level correctness (does iptables *accept* the ruleset,
do packets match), conntrack/NFLOG daemons, the ncurses GUI, IPv6-in-the-kernel,
`tc` shaping behaviour. Those stay manual or move to a privileged VM job later.

## 2. Why it cannot be tested today (privilege dependencies)

| # | Dependency | Site | Effect |
|---|---|---|---|
| D1 | Hard root gate | `vuurmuur/vuurmuur.c:284`, `vuurmuur_script/vuurmuur_script.c:97` | exits with "you are not root" |
| D2 | Config/log/temp files must be **owned by uid/gid 0** | `lib/io.c:167` in `vrmr_stat_ok()` (used by `vuurmuur_fopen`/`opendir`) | every open fails as non-root |
| D3 | `SYSCONFDIR` / `DATADIR` / `PLUGINDIR` baked at compile time | `lib/config.c:1343,1361,1370` | cannot point at a fixture tree |
| D4 | Backend root from `$etcdir/vuurmuur/plugins/textdir.conf` | `lib/textdir/textdir_plugin.c:1101-1113` | needs a writable system etc |
| D5 | Rule load = `popen()` of `iptables-restore`/`ip6tables-restore`/`/bin/bash` | `vuurmuur/ruleset.c:1124,1141,1187`, `vuurmuur/rules.c` (many), `vuurmuur/shape.c:144` | needs root + real binaries |
| D5b | Two commands **parse iptables stdout** | `lib/rules.c:2802` (`iptables -t X -nL` chain listing), `lib/interfaces.c:1171` (`iptables -vnL <chain> --exact` counters) | need canned output, not just a no-op sink |
| D6 | `iptables --version` sanity checks during config parse | `lib/config.c:150-175,179+` via `libvuurmuur_exec_command` | needs the binaries present |
| D7 | iptables capability probe creates real chains | `lib/iptcap.c` (`vrmr_load_iptcaps`), called `vuurmuur/vuurmuur.c:365-375` | root + modules; already skippable (`-t`, `conf.vrmr_check_iptcaps`) |
| D8 | `/proc/sys/...` reads+writes for protect rules | `vuurmuur/rules.c:2266-2280`, `lib/info.c:897-941`, `lib/proc.c` | read-only-ish for user, writes need root |
| D9 | Interface addresses via `ioctl(SIOCGIFCONF/SIOCGIFADDR)` | `lib/info.c:516-573,629+` | host-dependent IPs -> nondeterministic output |
| D10 | Interface counters via `iptables -L` | `vuurmuur/ruleset.c:1289-1360` | skipped when `DEVICE` empty or virtual |
| D11 | pidfiles `/var/run/vuurmuur*.pid` | `vuurmuur/main.h:59`, `vuurmuur_log/vuurmuur_log.h:39`, `vuurmuur/misc.c:30` | unwritable; only on the daemon path |
| D12 | tempfiles hardcoded `/tmp/vuurmuur-XXXXXX` | `vuurmuur/ruleset.c:1485-1487,1648-1649` | parallel-test collisions, no per-case capture |
| D13 | SysV shm + semaphores for reload/IPC | `vuurmuur/vuurmuur.c:494-542`, `vuurmuur_log/vuurmuur_ipc.c:35` | daemon/GUI path only, not generation |
| D14 | log dir created/validated under `LOGDIR` | `lib/config.c:63-135` | configurable -> fixtures use a temp dir |

Already-good news: `vuurmuur` **without `-D`** is one-shot - it generates, loads and exits
without daemonizing or creating shm (`cmdline.loop` only set for `-l/-D`, `vuurmuur.c:222`)
- and `-k` already preserves the generated restore file for inspection
(`ruleset.c:1602`). So a non-root oracle exists in the binary today; only D1-D4, D9 and D12
block using it. Separately, `-b` routes commands to `fprintf(stdout)` instead of `popen()`
(`lib/io.c:465`), which is the legacy path's own oracle (§8 P5 removes it).

Note: this dev box has **no `iptables` binary at all** and **user/network namespaces are
denied** (`unshare: Operation not permitted`), so namespace- or netns-based sandboxing is
not an option here. The design therefore uses in-code seams + fake executables.

## 3. Harness architecture

Four tiers, each independently useful. Tiers 0-2 are the deliverable; tier 3 is CI polish.

**The oracle is the generated `iptables-restore` input file**, not a stream of commands
(decided): that file is what the production path hands to the kernel
(`iptables-restore --counters --noflush < /tmp/vuurmuur-XXXXXX`, `vuurmuur/ruleset.c:1124`),
it is complete, ordered and diffable, and capturing it requires no change to the emission
logic itself. The legacy per-command path (`-b`) is covered by a secondary golden only until
it is deleted (§8 P5).

```
          ┌────────────────────────────────────────────────────┐
 tier 3   │ differential / corpus: git A vs B, ASan, coverage  │
          ├────────────────────────────────────────────────────┤
 tier 2   │ real binaries in a sandbox                         │ <- fake iptables-restore
          │  vuurmuur -n -t -k ; vuurmuur_script add/list      │    copies stdin
          ├────────────────────────────────────────────────────┤
 tier 1   │ in-process: tests/vrmr_gen_test                    │ <- capture ops
          │  ctx -> load -> analyze -> load_ruleset()          │    snapshot restore file
          ├────────────────────────────────────────────────────┤
 tier 0   │ pure unit: parse/encode/decode, portranges,        │ <- no sandbox, no fixtures
          │  regexes, list/hash, icmp tables                   │
          └────────────────────────────────────────────────────┘
                       all tiers assert on the same artifact:
                  the generated iptables-restore input file
```

### Tier 0 - pure unit tests

No fixtures, no filesystem beyond a private temp file the case creates and removes.
Targets:

* `vrmr_rules_parse_line()` (`lib/rules.c:706`), `vrmr_rules_encode_rule/decode_rule`
  (`:2886`, `:2910`), `parse_option()` (`:1941`), `vrmr_rules_actiontoi()` (`:2621`),
  `vrmr_rules_determine_ruletype()` (`:2937`)
* `vrmr_split_portrange()` (services), ICMP type/code tables (`lib/icmp.c`)
* `vrmr_list_*`, hash table + comparators (`lib/hash.c`), `vrmr_get_string()` (`lib/util.c`),
  `strlcpyu/strlcatu`
* zone/host/service/interface regexes (`include/vuurmuur.h:204-221`) incl. the 32-char
  edges that must agree with `VRMR_MAX_*`

Fuzzing hooks in here (see §7).

### Tier 1 - in-process golden generation (the core)

A test driver binary, `tests/vrmr_gen_test`, that links the engine and:

1. builds a sandbox root (`$TMPDIR/vuurmuur-test.<case>.XXXX/`) and seeds it from
   `tests/fixtures/<case>/`;
2. constructs a `struct vrmr_ctx` via a new `vrmr_test_ctx_init()` helper
   (`vrmr_init` + `vrmr_init_config`, with D1-D4 neutralised by the seams of §4);
3. installs **capture ops** so nothing executes, and answers the two state queries from
   fixtures (§4 S1);
4. loads backends, services, interfaces, zones, blocklist, rules and calls
   `analyze_all_rules()`;
5. runs the emit stage `load_ruleset()` (`vuurmuur/ruleset.c:1757`); the capture op
   snapshots the **restore file** referenced by the `iptables-restore ... < path` command
   it was asked to run, into `artifacts/<case>/iptables.restore` (same for the IPv6 file
   and for the `--counters`/shape script); every other command line is logged to
   `artifacts/<case>/side-effects.txt`;
6. normalizes (§5) and diffs against `tests/golden/<case>/`.

The driver takes `--case NAME [--update] [--artifact=restore|commands] [--profile=caps-X]`.
Optionally it can drive `apply_changes()` twice to cover the reload/diff path in-process.

### Tier 2 - end-to-end CLI tests

Shell/TAP driver that runs the *real* binaries against a sandbox, with a fake
`iptables-restore` that simply copies stdin to `$SB/out/restore.<n>.txt` - which yields the
**same artifact as tier 1**, so the two tiers cross-check each other:

```
VUURMUUR_SYSCONFDIR=$SB/etc VUURMUUR_TMPDIR=$SB/tmp PATH=$SB/bin:$PATH \
  vuurmuur/vuurmuur -t -k -c $SB/etc/vuurmuur/config.conf
```

`-t` skips the capability probe (D7); `-k` keeps the tempfiles (`cmdline.keep_file`,
`vuurmuur/vuurmuur.c:258` -> `vuurmuur/ruleset.c:1602`) so the restore file survives for
inspection. No `-D`/`-l` means one-shot: `cmdline.loop` stays 0 (`vuurmuur.c:222`), so the
process builds the ruleset, loads it and exits without daemonizing, creating shm or
touching a pidfile (D11/D13 disappear on this path). `$SB/bin/` also holds fake `iptables`,
`ip6tables`, `tc`, `sysctl`, `modprobe` for the config sanity checks (D6). Never pass
`-d 3`: at debug level HIGH the loader sleeps 15 s "so you can look into the tmpfile"
(`vuurmuur/ruleset.c:1568`).

`vuurmuur -b -t -c ...` is used separately, only to pin the legacy per-command path
(`create_all_rules`) until §8 P5 deletes it.

Used for: config parsing, backend plumbing, `vuurmuur_script` CRUD, reload-diff logic
(`apply_changes`), and error/warning-message paths. Also asserts negative cases: bad rule
line, unknown zone/service, oversized names, insecure file permissions (D2 still enforced
within the sandbox owner).

### Tier 3 - corpus / differential

* `make check-corpus`: regenerate goldens for all fixtures, print a unified diff; used to
  review "what does this patch change in the output?".
* `tests/diff-branch.sh <refA> <refB>`: build both into separate build dirs, run the corpus,
  compare. This is the safety net for the eventual nftables or libiptc work.
* sanitiser + coverage variants (§7).

## 4. Production seams to add (the whole diff surface)

Small, additive, each inert unless told otherwise. Ordered by necessity.

### S1 `vrmr_exec_ops` - capture hook (enables D5, D5b, D6, D10)

`include/vuurmuur.h` *public* block stays untouched (test-only seams, decided); the ops
struct and `vrmr_set_exec_ops()` go in a `noinst_HEADERS` private header:

```c
struct vrmr_exec_ops {
    /* fire and forget; 0 ok, -1 error */
    int (*pipe)(struct vrmr_config *, const char *cmdline, char ignore_error);
    /* fork/exec a path with argv (NULL terminated); 0 ok, -1 error */
    int (*exec)(struct vrmr_config *, const char *path, const char *argv[],
                char *output[]);
    /* run a command and capture its stdout (iptables -L style queries) */
    int (*read)(struct vrmr_config *, const char *cmdline, char *buf, size_t size);
};
void vrmr_set_exec_ops(const struct vrmr_exec_ops *ops); /* NULL = real ops */
```

`lib/io.c`: `vrmr_pipe_command()` and `libvuurmuur_exec_command()` become
`ops->pipe(...)` / `ops->exec(...)` wrappers; the existing bodies move into
`vrmr_real_exec_ops` unchanged (bash-mode stdout printing stays where it is). Add
`vrmr_command_output(cnf, cmd, buf, size)` implemented as `ops->read()` and **route the
two remaining direct `popen()` sites into it** (`lib/rules.c:2794-2802`,
`lib/interfaces.c:1166-1171`) so the tree has exactly three auditable execution points.
Default pointer = real ops, so production is one indirect call.

The harness installs capture ops that:

* log every command line to `side-effects.txt` and return 0 (or fail on `--fail-at N=<glob>`
  to exercise the `ruleset_store_failed_set`/rollback paths);
* **snapshot any sandbox tempfile a command references** (`... --noflush < $SB/tmp/x` or
  `/bin/bash $SB/tmp/x`) as a golden artifact - this is how the restore file is captured
  with no change to `ruleset.c`;
* for `read()`, return canned text from the case dir
  (`tests/fixtures/<case>/iptables/<table>-nL.txt`, `.../<chain>-counters.txt` - state is
  queried as `iptables -t <table> -nL` and `iptables -vnL <chain> --exact`, so fixtures are
  stored per invocation kind, with a default "no custom chains yet" output for a clean-slate
  case).

The assertion "`side-effects.txt` contains nothing but the restore invocations" is the
invariant that lets the legacy path be deleted safely in §8 P5.

Audit rule for reviewers: `grep -rn 'popen\|execv' --include='*.c' lib/ vuurmuur/
vuurmuur_script/` must stay empty outside `lib/io.c`. (The GUI's own `fork`/`execv` and its
log-search `popen` - `vuurmuur_conf/vuurmuur_conf.c:66`, `logview_section.c:1382` - are out
of scope for these tiers.)

### S2 path rooting (enables D3, D4, D11, D12)

`lib/config.c:1335 vrmr_pre_init_config()` gains env overrides, documented in `doc/`:

```c
const char *e = getenv("VUURMUUR_SYSCONFDIR");  /* default xstr(SYSCONFDIR) */
e = getenv("VUURMUUR_DATADIR");                 /* default xstr(DATADIR)   */
e = getenv("VUURMUUR_RUNDIR");                  /* pidfile dir, default /var/run */
e = getenv("VUURMUUR_TMPDIR");                  /* ruleset tempdir, default /tmp  */
```

Store `rundir`/`tmpdir` in `struct vrmr_config` (new fields) so `PIDFILE`/`/tmp/vuurmuur-*`
literals become `cfg->rundir`/`cfg->tmpdir` prefixes (`vuurmuur/ruleset.c:1485`,
`vuurmuur/main.h:59`, `vuurmuur_log/vuurmuur_log.h:39`, `vuurmuur/misc.c:30`).
Rooting the tempdir is what makes the restore file findable and parallel-runnable.
Config-file location keeps the existing `-c` override (`conf.configfile`).
Production: unset env -> byte-identical paths.

### S3 owner check (enables D2)

`lib/io.c:167` replaces `st_uid != 0 || st_gid != 0` with:

```c
uid_t want_uid = (cnf->trusted_uid) ? cnf->trusted_uid : 0;
```

`trusted_uid` is 0 by default and the harness sets it to `geteuid()`. Alternative,
zero-config: `geteuid() ? geteuid() : 0` - same effect, but the explicit field keeps the
production policy unambiguous and greppable. Add `VUURMUUR_TRUSTED_UID=auto` handling in
`vrmr_pre_init_config()` for tier 2's sake.
Everything else in `vrmr_stat_ok()` (no symlinks, `max_permission` enforcement incl. the
auto-`chmod`) stays: fixtures are created by the harness, so they satisfy it.

### S4 non-root opt-in (enables D1)

`vuurmuur/vuurmuur.c:284` and `vuurmuur_script/vuurmuur_script.c:97`:

```c
if (!vrmr_am_root() && !cnf->allow_unprivileged) { ... exit ... }
```

`allow_unprivileged` set only by `VUURMUUR_ALLOW_NONROOT=1`. Tier 1 doesn't need this at
all (the driver never enters `main()`); it exists so tier 2 exercises the real binaries.
Also assert that the generation path itself (D5 capture) cannot touch the kernel, so a
misconfigured harness fails loudly rather than modifying the host firewall.

### S5 system-info hooks (enables D7, D8, D9, D10)

* **capabilities** (D7): no new code. `conf.vrmr_check_iptcaps=FALSE` (`-t`) plus the
  driver filling `vctx.iptcaps` from a profile file. Profiles in
  `tests/profiles/*.caps` (key=value, mapped onto `struct vrmr_iptcaps`,
  `include/vuurmuur.h:1120`): `modern` (raw/rpfilter/ct all true), `no-rpfilter`,
  `no-nfqueue`, `ipv4-only`. Only 5 real consumers, all in `vuurmuur/ruleset.c:368,410,614,702`.
* **proc** (D8): `lib/proc.c` resolves paths against `cfg->procdocdir`
  (new, default `/proc`); harness points it at `<sandbox>/proc` with a pre-created fake
  tree. Protect-rule generation then asserts on the values written.
* **interface addresses** (D9): `lib/info.c:516,629` consult an optional
  `cfg->iface_addr_map` (`name=ip[,ip6]` list) before `ioctl()`; harness sets it from the
  case manifest (`eth0=10.0.0.1`, `eth1=203.0.113.2`, ...). Without the map (production)
  the ioctl path runs unchanged. This is what makes goldens portable across machines.
* **counters** (D10): fixtures use empty/`DEVICE=""` or virtual devices
  (`vuurmuur/ruleset.c:1307`), or `ops->read()` returns canned `--exact` output.
* **system chains** (`vrmr_rules_get_system_chains`, called from `vuurmuur/ruleset.c:359`
  and `vuurmuur/rules.c:94,2387,2470` with the return value ignored): served by
  `ops->read()` fixtures, so "first load vs reload" becomes a fixture instead of live
  kernel state. Its `(void)` casts are themselves a testability hazard - a failed listing
  currently looks like "no chains exist".

### S6 build structure

Convenience libraries so both the daemons and tests link the same objects:

* `lib/Makefile.am`: add `noinst_LTLIBRARIES += libvuurmuur_core.la` (the current sources
  minus nothing) and keep `libvuurmuur.la` as `-version-info`d shared lib wrapping it -
  or simpler: link tests against `../lib/libvuurmuur.la` as the programs already do.
* `vuurmuur/Makefile.am`: split into
  `noinst_LTLIBRARIES = libvuurmuur_engine.la` (`createrule.c misc.c reload.c rules.c
  ruleset.c shape.c`) and `vuurmuur_SOURCES = vuurmuur.c` + `vuurmuur_LDADD =
  libvuurmuur_engine.la`. `vuurmuur/main.h` moves to `noinst_HEADERS` shared with tests.
  `vuurmuur/ruleset.c` needs `ruleset_create_ruleset()` exposed (or the driver calls
  `load_ruleset()`, which is already public).
* `Makefile.am`: `SUBDIRS += tests`; `configure.ac`: `AC_CONFIG_FILES([tests/Makefile])`,
  plus `--enable-asan --enable-ubsan --enable-coverage --disable-tests` options.

## 5. Fixtures, goldens, normalizer

```
tests/
  DESIGN.md            this file
  Makefile.am          check_PROGRAMS, TESTS, EXTRA_DIST
  lib/                 tiny test framework: TAP emitter, sandbox, ctx builder, diff
  unit/                tier 0
  gen/                 tier 1 driver + cases
  e2e/                 tier 2 shell cases
  fixtures/<case>/     etc/vuurmuur/config.conf
                       etc/vuurmuur/plugins/textdir.conf   (LOCATION -> $SB/state)
                       state/{interfaces,services,zones,rules}/...  (textdir tree)
                       proc/sys/**                       (fake /proc, optional)
                       profile                           (which .caps profile, opts)
  profiles/*.caps
  golden/<case>/{iptables.restore,ip6tables.restore,shape.sh,side-effects.txt,
                 warnings.txt,exitcode}
```

Case discovery: one directory = one test; `tests/gen/main.c` iterates `fixtures/*`.

**Normalizer** (`tests/lib/normalize.c`), applied to both golden and captured output before
diff, so goldens stay stable:
* drop the `# Generated by Vuurmuur <version>` header line (`vuurmuur/ruleset.c:362`) so
  version bumps do not touch goldens; keep every other line
* rewrite sandbox paths to `$SB` (and `$RULESET`/`$SHAPE` for the tempfiles)
* keep `[0:0]` counters: they are literal text in the generated file, not live values, so
  asserting on them is free. Live counters only appear in `read()` fixtures
  (`iptables -vnL <chain> --exact`), which are inputs, not output
* keep emission **order** (order is semantics: chain declarations, `--new`, `COMMIT`, and
  rule order inside a chain all matter); never sort
* collapse trailing whitespace, one rule per line, strip CR

Assertion style: exact text diff of the restore file (a changed golden *is* the finding),
plus opt-in structural queries for focused tests: `expect_chain("filter","INPUT")`,
`expect_rule("INPUT", "-s 10.0.0.0/8", "-j ACCEPT")`, `expect_absent("-j LOG")`,
`count_rules("FORWARD") == N`, `expect_new_chain("PRE-VRMR-PREROUTING")`, and "no rule
contains an unexpanded placeholder or an empty address".

### Case taxonomy (first corpus, ~25 cases)

| Area | Cases |
|---|---|
| rule types | input, output, forward, portfw, redirect, dnat, snat, masq, bounce |
| actions | accept, drop, reject, log (nflog group), nfqueue, chain, separator |
| zones | zone, network, host, group, multi-net zone, zone aliases, inactive zone |
| expansion | host<->host, host<->net, net<->net, any, multi-iface src+dst |
| services | tcp range, udp range, both, icmp named types, helper (ftp/tftp), broadcast |
| options | mac, mark/connmark, limit/burst, length, state, helper, rpfilter, ct, tcpmss, nflog/nfqueue num |
| protection | synlimit, udplimit, antispoof, blocklist entries, protect rules (sysctl/proc) |
| shaping | shape on iface+rule: tc script capture + SHAPE* chains (expect `tc` invocations, no exec) |
| v6 | ipv6-only rules, dual-stack rule set, `check_ipv6` failure path |
| capability profiles | same rule set under 4 `.caps` profiles -> 4 goldens |
| ordering/idempotence | load same tree twice, second pass must emit `NOCHANGES` and an identical ruleset |
| negative | unknown object, malformed rule line, oversized name, bad perms, empty ruleset, `--force-start` |
| reload diffs | change 1 object, assert only the touched chains change (tier 2, `apply_changes`) |

## 6. Framework choice

No new third-party dependency in the repo (autotools project, distcheck-clean).
Allocation sites (`malloc`/`calloc`/`realloc`/`strdup`) far outnumber the explicit
`free()` calls and there is no ownership tooling, so tier 0/1 under ASan is a bug
finder in its own right. Count them with
`git grep -hE '\b(malloc|calloc|realloc|strdup)\b' -- '*.c' | wc -l`; the number
moves, so it is not quoted here.

What landed is one program per test in `tests/unit`, run through automake's default
driver with `TESTS = $(check_PROGRAMS)`, and a 106-line emitter in `tests/lib/tap.c`
that writes `ok`/`not ok` and `#` notes.

Still planned, each with a cost that has to be paid in the open:

* `# SKIP` in the emitter. A case that cannot apply on a host currently has to fail,
  which is the wrong answer for privileges the harness cannot ask for.
* `tap-driver.sh` as `LOG_DRIVER`, so the plan line (`1..N`) is checked and a missing
  assertion is visible instead of showing up only as a wrong exit code.
* Grouped drivers (`t00-unit.sh`, `t10-gen.sh`, `t20-e2e.sh`) once the corpus makes a
  flat `TESTS` list unreadable.
* Optional `--enable-uninstalled` style hooks later; keep the default build unmodified.

## 7. Sanitizers, coverage, fuzzing

`--with-sanitizers` -> `-fsanitize=address,undefined -fno-omit-frame-pointer`, landed.
A single switch for both families, because there is no case for running one without
the other here. Leak checking stays off (`detect_leaks=0`): teardown paths leave
allocations attached at exit, and an invalid free is what ASan is being asked to find.
Run tier 0+1 under it in CI once the suite runs there at all.
* `--enable-coverage` -> `--coverage`, `make check-codecov` + `lcov --rc
  lcov_branch_coverage=1` report limited to `lib/` + `vuurmuur/`.
* Fuzz targets (tier 0, `check_PROGRAMS`, run 30 s in CI nightly):
  `vrmr_rules_parse_line`, `parse_option`, `vrmr_rules_decode_rule`,
  `vrmr_split_portrange`, `vrmr_ask_configfile` - all parse config-sourced bytes and all
  sit next to fixed-size buffers (`VRMR_MAX_RULE_LENGTH`, `cmd[512]`, `chain[32]`).
  Two surfaced without a fuzzer: the terminator write in
  `vrmr_rules_parse_line` ran one past a field for an over-long token, and the
  newline strip read `line[-1]` for an empty line.
  Seed corpus from `tests/fixtures/*/state/rules/*.conf`. libFuzzer when clang is
  available, else deterministic corpus replay so the CI job needs no fuzzing runtime.

## 8. Rollout plan

| Phase | Content | Size |
|---|---|---|
| P0 | `tests/` skeleton + TAP emitter, tier 0 for `lib/rules.c` parsers (strict build prerequisite: done) | S |
| P1 | S1 exec-capture + S6 build split, tier 1 driver, sandbox helper, 6 golden cases | M |
| P2 | S2 rooting, S3 owner, S5 proc/iface-address hooks, tier 2 CLI cases, 15 more goldens | M |
| P3 | normalizer hardening, capability profiles, idempotence + reload-diff cases, corpus target (~25) | M |
| P4 | CI job (`make check` in the ubuntu matrix + ASan job), `diff-branch.sh`, coverage gate | S |
| P5 | **delete the legacy per-command path** (decided: after the harness lands): drop `create_all_rules()`/`*-rules(..., NULL, ...)` call shapes, reroute `-b` through the ruleset path (or retire the flag), then drop the `commands.txt` goldens | M |
| P6 | fuzz targets + nightly, seed corpus | S |

Gate for P5: the whole restore-file corpus must be green before and after the deletion
(`diff-branch.sh` proving byte-identical artifacts), and `side-effects.txt` must already be
empty of non-restore commands.

Each phase must keep `make distcheck` green; every golden is committed and reviewed as
part of the PR that changes it.

## 9. Risks / open questions

1. **Legacy duplicate code path.** *Decided:* harness first, deletion in P5. Consequence:
   until P5 the golden corpus covers two implementations of the same intent, so the
   `side-effects.txt` invariant ("nothing but restore invocations") is what makes the
   eventual deletion reviewable rather than a leap.
2. **Ordering flakiness.** Chain emission order and rule order inside chains come from
   config traversal; any hashing (hashtables in `lib/hash.c`) must never leak into emit
   order - a tier 1 invariant test should assert that.
3. **`vrmr_stat_ok()` auto-`chmod`** rewrites fixture modes on failure; harness must set
   modes correctly (0600 files / 0700 dirs) or goldens get noisy.
4. **Buffer limits vs realism.** `VRMR_MAX_*` sizes and `cmd[512]` mean long
   host/interface lists silently truncate; cases must include near-limit expansions so
   truncation becomes a golden diff instead of a wrong firewall.
5. **Query-vs-fire commands.** Some `iptables` invocations exist only to read kernel state
   (D5b). If they are not modelled, tests silently assert against an empty chain list and
   the `PRE-VRMR-*` / custom-chain logic goes untested. First-class in S1.
6. **IPv6 in CI.** `--disable-ipv6` and `check_ipv6` must both be exercised; pick one
   canonical configure flag set for goldens (`IPV6_ENABLED` changes emitted output).
7. **Bootstrap deps.** See §10 - the build works locally and is `-Werror` clean on all four
   available compilers; `vm-build.sh` covers the gettext workaround until the NLS handling
   is made optional upstream.
8. **Nftables abstraction is explicitly out of scope for now** (decided): the sink is the
   restore file, i.e. iptables-restore syntax is the golden format. When/if an nftables
   emitter appears, it gets its own artifact type and the restore goldens stay as the
   iptables contract. No premature backend-agnostic IR.
9. Should the harness be usable as a **`vuurmuur --dry-run` for users**? *Decided: no -
   the seams stay test-only.* But they are env-var-gated in production code, so the
   wording of that rule is: the env vars exist in the shipped binary (they are the only
   injection route for tier 2) but are documented as unsupported/for-testing, and
   `vrmr_set_exec_ops()` stays declared in a header the tests include, not in
   `include/vuurmuur.h`'s public block. Risk to watch: a future user-facing dry-run would
   turn these into API and want a `conf` key instead of an env var.

## 10. Local build recipe (verified on this box)

`gettext` is not installed and there is no root/apt here, which blocks `autogen.sh`
(`AM_GNU_GETTEXT` left unexpanded -> `configure` dies at the `AM_GNU_GETTEXT(external)`
line). Workaround in use, no repo changes required:

```sh
apt-get download gettext && dpkg-deb -x gettext_*.deb ~/opt/gettext-local   # one-off
PATH=~/opt/gettext-local/usr/bin:$PATH ACLOCAL_PATH=~/opt/gettext-local/usr/share/aclocal \
  bash autogen.sh          # note: gettextize deletes po/Makefile.in.in -> git checkout -- po/Makefile.in.in
cp ~/opt/gettext-local/usr/share/gettext/po/Makefile.in.in po/  # repo copy is from gettext 0.20
./configure --prefix=/usr --sysconfdir=/etc && make -j8
```

`~/opt/bin/vm-build.sh` wraps all of the above (it also restores `po/Makefile.in.in` on
exit so `git status` stays clean; `WERROR=1` reproduces the CI flag set). A strict build is
now also available without any flag gymnastics: `./configure --enable-werror`.

**Warning status.** The build is clean under `-Wall -Wextra -Werror
-Wno-unused-parameter -Wno-unused-function` clean with gcc 15, gcc 16 and clang 21.
clang 22 compiles clean but fails the link step: its `gcc-install-dir-libstdcxx`
notice is promoted to an error when libtool hands CFLAGS to the driver, and the
`-Wno-error=` demotion that fixes the compile step does not reach there.
(76 translation units each). Earlier `-Wdiscarded-qualifiers` failures under C23
string-search results and the set-but-unused counters are fixed on master. CI still sets the
same flags through a `CFLAGS` override, which also drops `-g -O2`; switching the workflows
to `./configure --enable-werror` would make CI and local strict builds identical (open
cleanup, no harness dependency).

**The override is the trap, and it has teeth.** CI does not have one warning set. The alpine
and Ubuntu `features` jobs compile with `CFLAGS="-Werror -Wall -Wextra"` (alpine: same flags,
`CC=gcc`) and **without** `-Wno-unused-parameter`, while my local strict loop passed a set that
includes it. A seam that added an unused parameter — `vrmr_real_pipe()` keeps `cnf` for the hook
signature, `splice_str()` in the harness took a buffer base it never used — was green across all
five compilers locally and red in three CI jobs. A `CFLAGS` override replaces whatever configure
would have set, so it silently tests a different program than the one CI builds; same class of
mistake as picking a sanitizer in `CFLAGS` without `LDFLAGS`.

So reproduce the jobs verbatim before pushing anything that changes a signature:

```sh
git archive HEAD | tar -x -C /tmp/src && (cd /tmp/src && bash autogen.sh)
mkdir -p /tmp/b && cd /tmp/b
CFLAGS="-Werror -Wall -Wextra" /tmp/src/configure --with-widec=yes >/dev/null
make -k all && make -k check     # -k: enumerate, do not stop at the first
```

`make -k check` matters: `check_PROGRAMS` are not built by `make all`, so harness-only code is
where a warning set can still hide a failure.

Other env facts that shaped this design: no `iptables` binary on the host, and
unprivileged user/network namespaces are denied (`unshare: Operation not permitted`), so
neither fake-kernel nor netns sandboxing is available - hence the explicit capture seam.

