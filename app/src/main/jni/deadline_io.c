/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <jni.h>
#include <fcntl.h>
#include <errno.h>

/* Android's public Os.fcntlInt API starts at 30. This keeps API 26 pipes bounded. */
JNIEXPORT jint JNICALL
Java_eu_nosini_signet_api_NativeIo_setNonblocking(JNIEnv *env, jobject object, jint fd) {
    (void)env;
    (void)object;
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return errno;
    return 0;
}
