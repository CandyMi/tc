#include <tc.h>
#include <stdbool.h>
#include <time.h>

#ifdef _WIN32
  #include <stdlib.h>
  #include <process.h>
  #define getpid    _getpid
  #define tc_thread_local __declspec(thread)
  static inline int rand_r(unsigned int* randomValue) {
    unsigned int val = *randomValue;
    rand_s(&val);
    *randomValue = val;
    return val;
  }
  #define tc_now(ts) timespec_get(ts, TIME_UTC)
#else
  #include <unistd.h>
  #define tc_thread_local __thread
  #define tc_now(ts) clock_gettime(CLOCK_REALTIME, ts)
#endif

/* Cuban prime */
#define prime1 (0xf9cd)
#define prime2 (0xec4d)

tc_thread_local bool rand_init = 0;
tc_thread_local unsigned int rseed = 0;

void tc_random_init () {
  if (!rand_init)
  {
    rand_init = 1;
    rseed = (unsigned int)time(NULL) ^ clock() ^ getpid();
  }
}

int tc_random_next() {
  tc_random_init();
  return (int)rand_r(&rseed);
}

int tc_randomkey(unsigned char *rbuf, unsigned int rsize) {
  if (rbuf == NULL || rsize < RKEY_MIN_LENGTH)
    return 0;
  
  tc_random_init();
  unsigned int i, j;
  char tmp1[RKEY_MIN_LENGTH]; char tmp2[RKEY_MIN_LENGTH];
  for (j = 0; j < RKEY_MIN_LENGTH; j++) {
    tmp1[j] = (tc_random_next() ^ prime1) & 0xff;
    tmp2[j] = (tc_random_next() ^ prime2) & 0xff;
  }
  for (i = 0; i < rsize; i++)
    rbuf[i] = (tmp1[i % RKEY_MIN_LENGTH] ^ tmp2[i % RKEY_MIN_LENGTH]) & 0xff;
  return 1;
}

#define tc_get_time(V, X, Y) {                     \
  struct timespec ts; tc_now(&ts);			           \
  *V = ts.tv_sec * (int)X + (int)(ts.tv_nsec * Y); \
}

int tc_time(tc_time_t *t) {
  if (!t) return 0;
  tc_get_time(t, 1, 0);
  return 1;
}

int tc_time_millisecond(tc_longtime_t *t) {
  if (!t) return 0;
  tc_get_time(t, 1e3, 1e-6);
  return 1;
}

int tc_time_microsecond(tc_longtime_t *t) {
  if (!t) return 0;
  tc_get_time(t, 1e6, 1e-3);
  return 1;
}