// Test-only LD_PRELOAD shim for the local validator: shifts CLOCK_REALTIME by
// DAGON_CLOCK_OFFSET_SECONDS (monotonic clocks untouched). The validator's
// vote timestamps, and so the Clock sysvar, then run that far ahead of wall
// time from genesis on, consistently. The lifecycle test uses it to reach a
// note's UTC-day expiry bucket within minutes instead of up to 24 hours.
// Built and used only by scripts/localnet/stack.mjs; never in a deployment.
#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static long offset_seconds(void) {
    static long offset = -1;
    if (offset < 0) {
        const char *value = getenv("DAGON_CLOCK_OFFSET_SECONDS");
        offset = value ? atol(value) : 0;
        if (offset < 0) offset = 0;
    }
    return offset;
}

int clock_gettime(clockid_t clock, struct timespec *ts) {
    int result = (int)syscall(SYS_clock_gettime, clock, ts);
    if (result == 0 && (clock == CLOCK_REALTIME || clock == CLOCK_REALTIME_COARSE)) {
        ts->tv_sec += offset_seconds();
    }
    return result;
}

int gettimeofday(struct timeval *restrict tv, void *restrict tz) {
    int result = (int)syscall(SYS_gettimeofday, tv, tz);
    if (result == 0 && tv) tv->tv_sec += offset_seconds();
    return result;
}

time_t time(time_t *out) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return (time_t)-1;
    if (out) *out = ts.tv_sec;
    return ts.tv_sec;
}
