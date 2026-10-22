# Testing harness for rule generation (non-root)

Status: tier 0 and the tier 1 generation path are landed - `make check` runs assertions over the
rules.conf line parser, the option grammar and the log reader, plus golden cases over the whole
generation pipeline. Nothing in `make check` needs root, `iptables` or a config tree. Tracker:
https://github.com/inliniac/vuurmuur/issues/54. Target: `make check` exercising the iptables
ruleset generation end-to-end, as an unprivileged user, on any host, in CI and locally.

## 1. Goals

1. Deterministic coverage of the rule-generation pipeline: config tree -> object model ->
   `analyze_all_rules()` -> **the generated `iptables-restore` input file**.
2. Run **without root**, without `/etc/vuurmuur`, without `/var/run`, without a real
   `iptables` binary, without network interfaces matching any particular name or address.
3. Golden-file (snapshot) testing so that any change in generated output is explicit,
   reviewable and diffable. The restore file *is* the contract; command streams are
   secondary and temporary (legacy path goes in §8 P5).
4. Cheap enough to run on every commit (`make check` - tier 0 measures 0.5 s wall warm in an
   out-of-tree build, about 1.4 s cold, so a CI job's first run costs more than a local loop), plus sanitizer/coverage
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
| D5 | Rule load and every per-rule command: `popen()`/`execv()` of `iptables-restore`, `ip6tables-restore`, `/bin/bash`, `tc` | `vuurmuur/createrule.c` (61 sites, the bulk), `vuurmuur/rules.c` (26 sites, first `:110`), `vuurmuur/ruleset.c:1141,1187`, `lib/iptcap.c` (17 via `libvuurmuur_exec_command`, first `:85`), `vuurmuur/shape.c:144` | needs root + real binaries |
| D5b | Two commands **parse iptables stdout** | `lib/rules.c:2818` (`iptables -t X -nL` chain listing, in `vrmr_rules_get_system_chains_per_table` at `:2799`), `lib/interfaces.c:1171` (`iptables -vnL <chain> --exact` counters) | need canned output, not just a no-op sink |
| D6 | `iptables --version` **and `tc -V`** sanity checks during config parse | `lib/config.c:150-175,179+`, `tc -V` at `lib/config.c:285`, via `libvuurmuur_exec_command` | needs the binaries present |
| D7 | iptables capability probe creates real chains and `modprobe -q`s modules | `lib/iptcap.c` (`vrmr_load_iptcaps`, `modprobe` at `:85`), called `vuurmuur/vuurmuur.c:365-375` | root + modules; skippable via `-t`/`conf.vrmr_check_iptcaps`, module loading via `conf.load_modules` |
| D8a | `/proc/sys/...` reads+writes for protect rules | `vuurmuur/rules.c:2266-2280`, `lib/info.c:897-941`, `lib/proc.c` | read-only-ish for user, writes need root |
| D8b | **`sysctl -w` as an external binary**, independent of D8a | `sysctl_exec()` `vuurmuur/misc.c:69-81` via `libvuurmuur_exec_command`; called at `vuurmuur/createrule.c:4443,4448` (`pre_rules`) and `:4733,4743,4759,4769` (`post_rules`); binary from `SYSCTL`, default `/sbin/sysctl` (`include/vuurmuur.h:132`) | fires on the restore-file path: guarded by `conntrack_accounting`/`forward_rules`, **not** by `ruleset == NULL`; `bash_out` only short-circuits inside `sysctl_exec` (`misc.c:71-74`), and the return value is discarded |
| D9a | Interface addresses via `ioctl(SIOCGIFCONF/SIOCGIFADDR)` | `lib/info.c:516-573,629+` | host-dependent IPs -> nondeterministic output |
| D9b | Interface **up/down** read from a hardcoded `/proc/net/dev` | `lib/interfaces.c:1003` (`fopen` at `:1038`) via `vrmr_read_interface_info` (`:244`, call at `:508-509`, set at `:513/:517`); `->up` gates emission at 9 sites: `vuurmuur/rules.c:1581,1651,1758,1886,1935,2022` and `vuurmuur/createrule.c:4807,4945,5004` | **reads succeed unprivileged** - no failure, just the host's own interface state leaking into the artifact. In `bash_out` mode every interface is forced up (`vuurmuur/vuurmuur.c:70-71,409-410`), which is itself a difference the goldens must not depend on |
| D10 | Interface counters via `iptables -L` | `vuurmuur/ruleset.c:1289-1360` | skipped when `DEVICE` empty or virtual |
| D11 | pidfiles `/var/run/vuurmuur*.pid` | `vuurmuur/main.h:59`, `vuurmuur_log/vuurmuur_log.h:39`, `vuurmuur/misc.c:30` | unwritable; only on the daemon path |
| D12 | tempfiles hardcoded `/tmp/vuurmuur-XXXXXX` | `vuurmuur/ruleset.c:1485-1487,1648-1649` | parallel-test collisions, no per-case capture |
| D13 | SysV shm + semaphores for reload/IPC | `vuurmuur/vuurmuur.c:494-542`, `vuurmuur_log/vuurmuur_ipc.c:35` | daemon/GUI path only, not generation |
| D14 | log dir created/validated under `LOGDIR` | `lib/config.c:63-135` | configurable -> fixtures use a temp dir |

Already-good news: `vuurmuur` **without `-D`** is one-shot - it generates, loads and exits
without daemonizing or creating shm (`cmdline.loop` only set for `-l/-D`, `vuurmuur/vuurmuur.c:222`)
- and `-k` already preserves the generated restore file for inspection
(`vuurmuur/ruleset.c:1602`). So a non-root oracle exists in the binary today; only D1-D4, D9a, D9b and D12
block using it. Separately, `-b` routes commands to `fprintf(stdout)` instead of `popen()`
(`lib/io.c:465`), which is the legacy path's own oracle (§8 P5 removes it).

Two environment properties are treated as constraints rather than assumptions: a real
`iptables` binary may be absent, and unprivileged user/network namespaces may be unusable
(`unshare` returning `EPERM` is routine in containers). Neither netns-based nor fake-kernel
sandboxing can be relied on, so isolation is done with in-code seams and fake executables.

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

* `vrmr_rules_parse_line()` (`lib/rules.c:721`), `vrmr_rules_encode_rule/decode_rule`
  (`:2902`, `:2926`), `parse_option()` (`:1957`), `vrmr_rules_actiontoi()` (`:2637`),
  `vrmr_rules_determine_ruletype()` (`:2953`)
(All `lib/rules.c` numbers here are post-`5b83c7e`; that commit grew the file by 16 lines, so citations
written against `d08263b` sit 15-16 lower.)
* `vrmr_split_portrange()` (services), ICMP type/code tables (`lib/icmp.c`)
* `vrmr_list_*`, hash table + comparators (`lib/hash.c`), `vrmr_get_string()` (`lib/util.c`),
  `strlcpyu/strlcatu`
* zone/host/service/interface regexes (`include/vuurmuur.h:204-221`) incl. the 32-char
  edges that must agree with `VRMR_MAX_*`

Fuzzing hooks: see §7.

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
VUURMUUR_SYSCONFDIR=$SB/etc VUURMUUR_TMPDIR=$SB/tmp \
  vuurmuur/vuurmuur -t -k -c $SB/etc/vuurmuur/config.conf
```
The fake binaries are selected by **config keys, not by `PATH`** - prepending `$SB/bin` to
`PATH` does nothing. Nothing in the generation path resolves a bare command name:
`libvuurmuur_exec_command` reaches `execv()` (`lib/io.c:546`), which never searches `PATH`, and
every `popen()` string interpolates a configured location (`vuurmuur/createrule.c:125-127`,
`vuurmuur/ruleset.c:1123,1131`, `vuurmuur/shape.c:197`, `lib/iptcap.c:84`, `lib/config.c:163-284`).
So the fixture's `vuurmuur.conf` must set `IPTABLES=`, `IPTABLESRESTORE=`, `IP6TABLES=`,
`IP6TABLESRESTORE=`, `SYSCTL=`, `TC=` and `MODPROBE=` to `$SB/bin/*`; their compiled defaults are
all absolute (`include/vuurmuur.h:132-141`), so a fixture that forgets one runs the real
`/sbin/iptables-restore` on the host - exactly what §4 S4 promises cannot happen - or fails to
parse config if the binary is absent. One literal is not configurable: `/bin/bash`
(`vuurmuur/ruleset.c:1180`), which needs the same path hook as everything else or a fixture
that never reaches it.

`-t` skips the capability probe (D7); `-k` keeps the tempfiles (`cmdline.keep_file`,
`vuurmuur/vuurmuur.c:258` -> `vuurmuur/ruleset.c:1602`) so the restore file survives for
inspection. No `-D`/`-l` means one-shot: `cmdline.loop` stays 0 (`vuurmuur/vuurmuur.c:222`), so the
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

### S1 `vrmr_exec_ops` - capture hook (enables D5, D5b, D6, D8b, D10)

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
two remaining direct `popen()` sites into it** (`lib/rules.c:2810-2818`, popen at `:2818` in `vrmr_rules_get_system_chains_per_table` `:2799`,
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

The assertion "`side-effects.txt` contains nothing beyond a declared whitelist - the restore
invocations plus whatever `sysctl -w`/`tc`/`modprobe` calls the fixture config enables - is the
invariant that lets the legacy path be deleted safely in §8 P5.

Audit rule for reviewers: `grep -rn 'popen\|execv' --include='*.c' lib/ vuurmuur/
vuurmuur_script/` must stay empty outside `lib/io.c` **once S1 lands** - today it returns two sites
outside (`lib/rules.c:2818`, `lib/interfaces.c:1171`), which is exactly what S1 moves. (The GUI's own `fork`/`execv` and its
log-search `popen` - `vuurmuur_conf/vuurmuur_conf.c:66`, `vuurmuur_conf/logview_section.c:1382` - are out
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
if (vctx.user_data.user > 0 || vctx.user_data.group > 0) { ... exit ... }   /* today */
if ((vctx.user_data.user > 0 || vctx.user_data.group > 0) && !cnf->allow_unprivileged) { ... exit ... }
```
There is no `vrmr_am_root()`; the existing test is on the setuid-dropped ids, which is why the hook
has to be added at that expression rather than around a helper.

`allow_unprivileged` set only by `VUURMUUR_ALLOW_NONROOT=1`. Tier 1 doesn't need this at
all (the driver never enters `main()`); it exists so tier 2 exercises the real binaries.
Also assert that the generation path itself (D5 capture) cannot touch the kernel, so a
misconfigured harness fails loudly rather than modifying the host firewall.

### S5 system-info hooks (enables D7, D8a, D9a, D9b, D10)

* **capabilities** (D7): no new code. `conf.vrmr_check_iptcaps=FALSE` (`-t`) plus the
  driver filling `vctx.iptcaps` from a profile file. Profiles in
  `tests/profiles/*.caps` (key=value, mapped onto `struct vrmr_iptcaps`,
  `include/vuurmuur.h:1120`): `modern` (raw/rpfilter/ct all true), `no-rpfilter`,
  `no-nfqueue`, `ipv4-only`. Only 5 real consumers, all in `vuurmuur/ruleset.c:369,371,411,615,703`.
* **proc** (D8a): `lib/proc.c` resolves paths against `cfg->procdocdir`
  (new, default `/proc`); harness points it at `<sandbox>/proc` with a pre-created fake
  tree. Protect-rule generation then asserts on the values written.
* **interface addresses** (D9a): `lib/info.c:516,629` consult an optional
  `cfg->iface_addr_map` (`name=ip[,ip6]` list) before `ioctl()`; harness sets it from the
  case manifest (`eth0=10.0.0.1`, `eth1=203.0.113.2`, ...). Without the map (production)
  the ioctl path runs unchanged. This is what makes goldens portable across machines.
* **interface up/down** (D9b): owned by the same hook family, and it needs it - the state is read
  from a hardcoded `/proc/net/dev` (`lib/interfaces.c:1003`, `fopen` at `:1038`) that no
  `procdocdir` prefix reaches. Two options, in order of preference: fixtures mark devices
  `device_virtual_oldstyle`, which skips the read outright (`lib/interfaces.c:506`), or
  `vrmr_get_iface_stats()` grows an optional map keyed by device name. Without one of the two the
  artifact depends on whether the build host has an interface up, silently.
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
                 warnings.txt,restore.stderr,exitcode}
```

Case discovery: one directory = one test; `tests/gen/main.c` iterates `fixtures/*`.
Regenerating goldens after an intended change is `make check-corpus` (§3), and that is the only
supported way to refresh them - a golden diff is a finding, so nobody edits `golden/` by hand.
`restore.stderr` is the kernel's answer to the load (`2>>` at `vuurmuur/ruleset.c:1123`, `:1131`, `:1180`; not `:1486`, which is the `cur_result_path` declaration) and the
only signal for "would a real kernel have taken this ruleset"; in tier 1 it captures the fake
binary's stderr, so it stays empty, and in tier 2 it is where a rejected rule shows up.

**Normalizer** (`tests/lib/normalize.c`), applied to both golden and captured output before
diff, so goldens stay stable:
* drop the `# Generated by Vuurmuur <version>` header line (`vuurmuur/ruleset.c:362`) so
  version bumps do not touch goldens; keep every other line
* rewrite sandbox paths to `$SB` (and `$RULESET`/`$SHAPE` for the tempfiles)
* strip the audit prefix, and know that it is **not the process user**: `vrprint.username` is
  the owner of **fd 0** (`lib/info.c:1086-1095`, `readlink("/proc/self/fd/0")` + `lstat` +
  `getpwuid`, assigned at `lib/config.c:1660`, printed at `lib/log.c:139,225,333`). From a
  terminal it is your username, under automake (`stdin` from `/dev/null`) it is `root`, and when
  fd 0 is a pipe the `lstat` fails and `lib/info.c:1109-1113` fills `"unknown"` and returns -1.
  So `warnings.txt` carries a field that changes between a hand run and a CI run unless the
  normaliser removes `^[^ ]+ : ` or the driver pins stdin
* `[0:0]` is literal text **only on chain declaration lines** (13 `snprintf`s in
  `ruleset_fill_file`: `vuurmuur/ruleset.c:377-427,619-625,707-713`). **Rule** lines get their
  counters from the kernel: `ruleset_add_rule_to_set()` prints `"[%" PRIu64 ":%" PRIu64 "] "`
  whenever either is non-zero (`vuurmuur/ruleset.c:274-277`), and the values come from
  `ruleset_save_interface_counters()` (`:1289`, called `:1499,:1661`) reading
  `iptables -vnL <chain> --exact` through `vrmr_get_iface_stats_from_ipt()`
  (`lib/interfaces.c:1140`, popen `:1167/:1171`). That is the counter-preserving reload
  mechanism, so it is by design, not an accident. Consequence: tier 1 goldens are stable only
  while the `read()` fixture is honest (the canned "no custom chains yet" answer yields zeros),
  and a tier 2 golden with a real `iptables` **moves on every run**. Tier 2 must pin that read
  or normalise `\[[0-9]+:[0-9]+\] ` on rule lines; "asserting on them is free" is false.
* keep emission **order** (order is semantics: chain declarations, `--new`, `COMMIT`, and
  rule order inside a chain all matter); never sort
* collapse trailing whitespace, one rule per line, strip CR

Assertion style: exact text diff of the restore file (a changed golden *is* the finding),
plus opt-in structural queries for focused tests: `expect_chain("filter","INPUT")`,
`expect_rule("INPUT", "-s 10.0.0.0/8", "-j ACCEPT")`, `expect_absent("-j LOG")`,
`count_rules("FORWARD") == N`, `expect_new_chain("PRE-VRMR-PREROUTING")`, and "no rule
contains an unexpanded placeholder or an empty address".

### Case taxonomy

The table names **64** inputs, and it is a starting inventory rather than a plan: the `options`
row is a modifier set that multiplies across rule types and directions, so the honest denominator
is the number of emission branches in `ruleset_create_ruleset()`, not the number of rows. The
corpus budget below (6 at P1, 15 at P2, then widening at P3) is a first slice of that inventory,
not a claim that 25 covers the tree; whoever plans a later phase sizes against the 64, and against
the branch count, not against this heading.

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
moves, so it is not quoted.

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
A single switch for both families, because there is no case for running one without the
other. Leak checking is an `ASAN_OPTIONS` choice rather than a build setting; §13 records what
tier 0 shows with it on. An invalid free is what ASan is asked to find.

**Where CI actually lives:** the pipeline that builds this repository is not in it. Project 9 sets
`ci_config_path = .gitlab-ci.yml@inliniac/vuurmuur-ci`, so every job named below is a file in the
`inliniac/vuurmuur-ci` project that no reader of this document can patch from here; the only CI file in
this tree is `.github/workflows/builds.yml`. Today `make check` runs in exactly two jobs -
`ubuntu:26.04:arm64` and `ubuntu:26.04:armhf`, the only ones that execute the suite on arm - and
`build` runs `make -j<N> distcheck`, which runs the suite a second time in a VPATH tree;
`ubuntu:26.04:amd64` compiles without running it. A sanitized variant is therefore a configure flag on
an existing recipe, not new machinery: the `fedora:43/44:sanitizers` jobs compile with
`-fsanitize=*` CFLAGS and never execute a binary, which is the same `CFLAGS`-override trap §10 warns
about, in the opposite direction.
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
| P0 | ✅ `tests/` skeleton + TAP emitter, tier 0 for `lib/rules.c` parsers | done |
| P0b | sanitizer/coverage execution in CI - partly done: `make check` already runs in the two `ubuntu:26.04:arm*` jobs and in `build`'s distcheck; what remains is the sanitizer job actually executing binaries | S |
| P1 | ✅ S1 exec-capture + S2 config/state rooting + S3 owner + S5 interface-address hook + S6 engine split, tier 1 driver, sandbox helper, golden cases | done |
| P2 | S4 rundir/pidfile rooting, tier 2 CLI cases (`vuurmuur -k`), `#include`d host facts, more goldens | M |
| P3 | normalizer hardening, capability profiles, idempotence + reload-diff cases, corpus target (~25) | M |
| P4 | CI job (`make check` in the ubuntu matrix + ASan job), `diff-branch.sh`, coverage gate | S |
| P5 | **delete the legacy per-command path** (decided: after the harness lands). Not a cut-out: `create_all_rules()` (`vuurmuur/rules.c:328-444`, 117 lines) calls the *same* builders with `ruleset = NULL`, and the split is per rule inside `process_rule()`, so the inventory is 31 `if (ruleset == NULL)` sites in `vuurmuur/createrule.c` (:257, :2785-:3209, :3374, :3834-:4291, :4500, :4582 - ~473 lines), 71 `bash_out` references under `vuurmuur/` (createrule.c 58, vuurmuur.c 7, rules.c 3, misc.c 2, main.h 1), and `oldrules_create_custom_chains()` (`vuurmuur/rules.c:84-123`), the sole caller of the `iptables -N` chain creation. Reroute `-b` through the ruleset path (or retire the flag), then drop the `commands.txt` goldens | **L** (checklist-sized; budget as if it were XL) |
| P6 | fuzz targets + nightly, seed corpus | S |

**Exit criteria, since the table gives sizes but no finish line.** A phase is done when `make check`
passes on the tree it lands in, when the next phase can be written without editing that phase's
fixtures, and when every artifact it produces is diffed against a golden rather than eyeballed. For
P1-P3 the definition of done is the corpus: one case per emission branch the current implementation
supports, which is the 64-input inventory in §5 narrowed by whatever `ruleset_create_ruleset()`
actually branches on. The harness as a whole is done when a rules-generation change can break a test
without root, a VM, or a network namespace - which is the reason it exists.

Gate for P5: the whole restore-file corpus must be green before and after the deletion
(`diff-branch.sh` proving byte-identical artifacts), and `side-effects.txt` must already be
empty of non-restore commands.

Each phase must keep `make distcheck` green; every golden is committed and reviewed as
part of the PR that changes it.

## 9. Risks / open questions

1. **Legacy duplicate code path.** *Decided:* harness first, deletion in P5. Consequence:
   until P5 the golden corpus covers two implementations of the same intent, so the
   `side-effects.txt` invariant (nothing beyond the restore invocations and the declared
   `sysctl`/`tc`/`modprobe` calls) is what makes the
   eventual deletion reviewable rather than a leap.
2. **Ordering.** Already true, and worth stating so nobody wastes a test on it: there is no
   hashing and no `qsort` on the generation path. The claim is the one a reader can check in a
   grep: **`vrmr_hash_*` measures 0 in `vuurmuur/*.c` and 0 in `lib/rules.c`** - it is used
   elsewhere (`lib/hash.c`, `lib/conntrack.c`, `lib/config.c:1758,1765`, `vuurmuur_log/`,
   `vuurmuur_conf/`), which is beside the point - and `qsort` appears once in the whole tree, in
   `vuurmuur_conf/conn_sec.c:496`. The lists feeding the artifact are FIFO over rules-file order (`lib/rules.c:678`, appended by
   `vrmr_list_append` `lib/linkedlist.c:144`, artifact append `vuurmuur/ruleset.c:303`).
   The dependence that *does* exist is filesystem order: object lists come from `readdir()`
   (`lib/textdir/textdir_list.c:75,137,222,288,346,404,493`) and are tamed by a **sorted insert
   at load time** (`lib/interfaces.c:48`, `lib/services.c:53`, `vrmr_insert_zonedata_list` `lib/zones.c:157`, decision at `:220`) - there is no
   sort in any save path. That is what an invariant test should pin: two fixtures holding the
   same objects created in different directory order must produce byte-identical artifacts. It
   is deterministic today by construction rather than by assertion, so a future load-time
   optimisation could break goldens silently.
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
7. **Bootstrap deps.** See §10 - the build works locally, and `--enable-werror` is clean
   with gcc 15, gcc 16 and clang 21; clang 22 fails only at the link step on a toolchain
   notice, which is a host property rather than a code one. NLS handling is still a hard
   configure requirement, so a host without gettext macros cannot build from a clean
   checkout; that is worth an upstream look at making it optional.
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

## 10. Build recipe

`autogen.sh` needs no staging where the gettext m4 macros are installed. The reason to keep this
section at all is that a workaround outlived its problem: without those macros `AM_GNU_GETTEXT`
was left unexpanded and `configure` died at the `AM_GNU_GETTEXT(external)` line. If that
regression returns it should be diagnosed as a broken `autogen.sh`, not as a missing package.

```sh
bash autogen.sh
./configure --prefix=/usr --sysconfdir=/etc
make -j8
```

Nothing beyond `autogen.sh` from a clean checkout is assumed: no wrapper script, no pre-unpacked
prefix. A strict build is `./configure --enable-werror`, sanitizers are `./configure
--with-sanitizers`; neither is a `CFLAGS` exercise, which is the point of having the options.

**Warning status.** With `--enable-werror` the build is clean with gcc 15, gcc 16 and clang 21.
clang 22 compiles clean but fails the link step: its `gcc-install-dir-libstdcxx` notice is
promoted to an error when libtool hands `CFLAGS` to the driver, and the `-Wno-error=` demotion
that settles the compile step does not reach there. Earlier `-Wdiscarded-qualifiers` failures
over C23 string-search results, and set-but-unused counters, are fixed on master. The GitHub
workflow jobs configure with `--enable-werror` (`.github/workflows/builds.yml:46,79,185`) rather
than a `CFLAGS` override, so CI and a local strict build describe the same program; the two
scan-build jobs still pass `${DEFAULT_CFLAGS}` (`:141,:144`) on purpose, because `--status-bugs`
must not turn an analyzer finding into a build failure before the report exists.

**The override was the trap, and it still has teeth.** CI used to carry two warning sets: the
alpine and Ubuntu `features` jobs compiled with `CFLAGS="-Werror -Wall -Wextra"` (alpine: same
flags, `CC=gcc`) and **without** `-Wno-unused-parameter`, while the local strict loop used a set
that included it. A seam that added an unused parameter - in the first-cut harness, whose names (`vrmr_real_pipe`,
harness `splice_str`) never reached this tree - green across
five compilers locally and red in three CI jobs. A `CFLAGS` override replaces whatever configure
chose, so it silently builds a different program from the one CI tests; the same class of mistake
as picking a sanitizer in `CFLAGS` without `LDFLAGS`, and the reason both options exist.

So reproduce the jobs verbatim before pushing anything that changes a signature:

```sh
git archive HEAD | tar -x -C /tmp/src && (cd /tmp/src && bash autogen.sh)
mkdir -p /tmp/b && cd /tmp/b
CFLAGS="-Werror -Wall -Wextra" /tmp/src/configure --with-widec=yes >/dev/null
make -k all && make -k check     # -k: enumerate, do not stop at the first
```

`make -k check` matters: `check_PROGRAMS` are not built by `make all`, so harness-only code is
where a warning set can still hide a failure.

`make distcheck` runs and passes, and it is worth stating plainly because it is what CI's `build`
job runs (in `inliniac/vuurmuur-ci`, see §7) alongside the two arm jobs that call `make check`
directly: a failing assertion breaks those, which is the sense in which this suite is in CI today. Build the VPATH tree from `git archive`, never from a tar of the
working directory - a leftover `*.log` or `*.trs` makes `make check` die with `failed to create
... .log`, which reads like a test failure and is not one.

The two constraints from §2 are worth restating: they are why a capture seam exists at all
rather than a netns wrapper or a fake kernel.

## 11. Findings from tier 0

* `logprefix` can never be rejected for being too long: the copy caps at 12 characters, so
  the `strlen(op->logprefix) > 14` branch that warns and clears the flag is unreachable
  (`lib/rules.c:2155-2171`, the test at `:2162`). Long prefixes are silently truncated instead. Pinned by a
  test, so fixing it shows up as a deliberate diff.
* The options disagree about quoting: `in_int`, `out_int`, `via_int`, `chain`, `comment`
  and `logprefix` start copying two characters past the key and so require `key="value"`,
  while `limit`, `nfmark`, `redirectport`, `in_max` etc. start one past and filter quotes,
  so both forms work. An unquoted `in_int=eth0` silently yields `th`.
* Unknown options are accepted in silence (`parse_option`'s fallback `return(-1)` is
  commented out), so a typo in a rules file surfaces as a missing match in the generated
  ruleset instead of a load failure.
* The token terminators in `vrmr_rules_parse_line` wrote one byte past a field whenever
  a token was at least as long as its destination, and the newline strip read
  `line[-1]` on an empty line. Both are fixed in
  `lib: keep the rule line parser inside its buffers` and held there by
  `test_overlong_tokens`. A per-site mutation run decides whether the tests hold: revert
  one of the fifteen clamps, rebuild, `make check` under `--with-sanitizers`. Twelve fail,
  each naming the line it mutated; the three that stay silent cannot overshoot - the
  action copy stops at `sizeof(action_str) - 1` and the `'against'` and `'from'` keyword
  copies at the length of those words, so their clamps are defensive rather than
  load-bearing.

* `markiptstate` and the `queue` option are obsolete but harmless; the `queue` *action* is
  refused with a pointer to `nfqueue`, the option is not.



## 12. Log viewer line reading

The tail logic the log viewer used to own inline is now `vrmr_lineread()` in
`lib/lineread.c`, so it is reachable without ncurses. `unit/lineread` pins the five
branches that were easy to get wrong:

* an incomplete line at the end of the file is *parked*, not consumed: polling it
  repeatedly leaves the position alone until the newline lands;
* a line longer than the buffer arrives in full-size chunks instead of being dropped;
* after a read error the flag is cleared and the position re-anchored, which is what keeps
  `ftell()` and any later seek trustworthy on a tailled file;
* a NUL at the start of a line is dropped with the line consumed. Stalling there would
  freeze the viewer.
* a stream that cannot seek back (a pipe) still returns 0 on a partial line; the rewind
  fails and the branch that logs it runs. The bytes are gone, which is the honest
  outcome for a stream that never promised to be rewound.

Quitting the viewer mid-search used to run `fclose()` on the search pipe and then
`pclose()` on the same handle; both teardown paths now close each stream by name.
The rest of that function is UI and still uncovered.

## 13. Sanitizer build

`./configure --with-sanitizers` appends `-fsanitize=address,undefined
-fno-omit-frame-pointer` to `CFLAGS` and `LDFLAGS` after the defaults, so `-g -O2`
survives; a link probe fails the configure if the compiler cannot do it. It is a flag
rather than a CI `CFLAGS` override for the same reason `--enable-werror` is: the
override replaces what configure chose, and the set that runs stops being a project
decision.

The tier 0 tests pass under it with `ASAN_OPTIONS=abort_on_error=1` and no sanitizer
output.

Leak checking is not a build option, so the build says nothing about it. Under
`detect_leaks=1` these three programs report zero leaks, and the zero is worth something
because a control allocation in the same binary is reported, which shows LSan is actually
linked and running in that mode. Nothing in tier 0 has a teardown path to leak from. The
later tiers are where allocations get left attached at exit, and `detect_leaks=0` is their
recipe's business, not this one's.

UndefinedBehaviorSanitizer recovers and prints by default, so a finding would land on
stderr while `make check` still reports `# PASS: 3`. `AM_TESTS_ENVIRONMENT` in
`tests/Makefile.am` therefore exports `UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`,
which makes the suite fail where the tests are defined instead of depending on a CI job
remembering to set it.

The order of the commits is the other half of the same argument. With the parser fix
placed after the tests that found it, the sanitizer build this branch advertises fails at
the test commit - exit 2, `# PASS: 2 # FAIL: 1`, ASan `stack-buffer-underflow` at
`lib/rules.c:728` (now `:743-744` after the clamp fix), which is the empty-line read rather than a
terminator, so the guard is
not even what makes it fail - while every strict build stays green. A `git bisect` run with
sanitizers would stop at a commit that was never broken in the shipped program. The fix
therefore comes first, and the guard lands with the tests that need it.

What the sanitizers cannot reach yet is `vuurmuur_conf`'s quit-mid-search path, where
the double close that section 12 describes lived: nothing drives the UI. That needs a
pty-driven test of its own.

## 14. Findings from tier 1

* `vrmr_backends_unload()` has to be called by anything that loads objects in a loop: the
  textdir backend opens a `DIR *` per object type (`setup_textdir` `:1136`, `open_textdir`
  `:240/:268/:296`) and nothing else closes them. The tier 1 driver generates twice per case,
  so a missing unload leaks a megabyte before the first assertion even runs.
* A leak-checking run still reports a few hundred kilobytes under `regexec()` from
  `vrmr_validate_zonename/servicename/interfacename`: `vrmr_regex_setup(UNLOAD)` frees only
  part of `struct vrmr_regex`, so the glibc DFA caches of the rest stay allocated to exit.
  It is a product teardown gap rather than a harness one, bounded at one cache per regex, and
  it is the reason tier 1 is not yet gated on `detect_leaks=1`.

* `vrmr_create_tempfile()` created the ruleset tempfiles with mode **0000**: it wrapped
  `mkstemp()` in `umask(0600)`, which subtracts the owner bits instead of setting them.
  Root cannot tell, so a non-root reader simply got `EACCES`. Fixed to `umask(0177)`.
* Protect rules do not belong in `rules.conf` any more - they are dropped with a warning
  (`lib/rules.c:662-676`). The supported place is `RULE="protect against <danger>"` in
  `interfaces/<name>.conf` (and the network equivalents), parsed by
  `vrmr_interfaces_rule_parse_line`. A case (`protect`) pins both halves.
* The object file names are inconsistent: interfaces and rules are `<name>.conf`, services
  are `<name>` with no suffix, because `VRMR_SERV_REGEX` has no dot in its character class
  and `get_filelocation` appends the raw name for services.
* `deny` is not an action (`drop` is); a rule using it fails to parse as a whole, which is
  how the options case ended up silently one rule short.
* Generation asks the kernel twice per ruleset: whether each interface is up
  (`vrmr_get_iface_stats`) and what its address is (`vrmr_get_dynamic_ip`). Both were
  host facts, so the harness gets `vrmr_set_iface_probe_config()`: with it installed the
  configured address is taken as the actual one. Production is unchanged.
* Whether `PRE-VRMR-*` chains already exist changes the output (the `--new` lines are
  skipped), and the check is a live `iptables -t <table> -nL`. Those answers come from
  `cases/<name>/iptables/<table>.txt`; no file means an empty table, i.e. a fresh boot.
* `--counters --noflush < tmp 2>> tmp` is the load invocation, so a case records the
  ruleset tempfile content as it exists at that moment; it is deleted right after.
* The engine referenced `cmdline`, `version_string`, `shm_table` and `sem_id`, which were
  defined in `vuurmuur/vuurmuur.c`. They moved to `vuurmuur/misc.c` so a test can link the
  engine without a `main()`.

