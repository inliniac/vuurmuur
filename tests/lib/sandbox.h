#ifndef __VRMR_TEST_SANDBOX_H
#define __VRMR_TEST_SANDBOX_H

#include <stddef.h>

/* Build a sandbox for a case: cases/common/etc is copied first and the case
 * tree on top of it, so a case only holds what differs. The config, tempfile
 * and /proc locations then point inside the sandbox and the execution hooks
 * record instead of run. Call before vrmr_init.
 *
 * A file the case must delete is emptied by writing "#", the rules parser
 * ignores comment lines. */
int vrmr_test_sandbox_setup(const char *cases_dir, const char *name);

void vrmr_test_sandbox_teardown(void);

/* Forget the captured commands; used to separate loading from applying. Fixture
 * problems are NOT cleared here: they outlive the phase they were recorded in,
 * which unit/markers.c pins.
 */
void vrmr_test_effects_reset(void);

/* Record why the harness could not answer a read, or could not even name a
 * file. The list lands in the artifact's "# fixtures" block and makes the case
 * fail before a golden is compared or written.
 */
void vrmr_test_fixture_problem(const char *fmt, ...);

/* The checked path joins the harness builds its file names with. Both return
 * FALSE and record `# too large:` when the result would not fit, which is the
 * property unit/markers.c can break; a truncated path names a different file.
 */
int vrmr_test_join_path(char *dst, size_t size, const char *dir, const char *name);
int vrmr_test_cat_path(char *dst, size_t size, const char *dir, const char *tail);

/* The captured run as one normalized text: the command list, then the content
 * of every file a command consumed. Returns the length or -1 if it does not
 * fit in buf. */
int vrmr_test_render(char *buf, size_t size);

/* Same, with host dependent noise replaced: the sandbox prefix, the mkstemp
 * suffixes and the version banner. */
void vrmr_test_normalize(char *dst, size_t size, const char *src);

#endif
