/*
 * differential_driver_cjson.c — ADR-016 behavioral-equivalence differential driver.
 *
 * Linked with EITHER (A) the trusted cJSON.c source OR (B) the candidate recompiled
 * renamed-decompiled-C, this driver reads ONE JSON document from stdin (a synthetic, benign input
 * vector — see cjson_input_vectors.json; NO untrusted/real-malware data, master §5), exercises a
 * few public cJSON API paths, and prints a SHORT, DETERMINISTIC summary to stdout. The harness
 * compares (exit_code, stdout) byte-exactly between build A and build B (D2): when the candidate's
 * recovered names match the real cJSON API (a good client namer), B links + runs and the summaries
 * line up; a stub/partial candidate fails to link or behaves differently → an honest low score.
 *
 * It calls ONLY the public cJSON surface by name (cJSON_Parse / cJSON_Print / cJSON_GetArraySize /
 * cJSON_IsObject / cJSON_Delete / cJSON_free) so build B links iff those names were recovered. No
 * network, no files, bounded stdin read — safe + deterministic. The hostile binary is NEVER run
 * (ADR-001 / D1): build B is recompiled C, not the analyzed sample.
 *
 * Output contract (stdout), exactly:
 *   parse=<0|1>            // 1 if cJSON_Parse returned non-NULL
 *   kind=<obj|arr|other>   // top-level item kind (only when parse=1)
 *   size=<n>               // cJSON_GetArraySize of the root (only when parse=1)
 * Exit code: 0 on a successful parse, 1 on a parse failure (deterministic per input vector).
 */
#include "cJSON.h"
#include <stdio.h>
#include <string.h>

/* Bounded stdin read — cap the document so a flood input cannot grow the buffer unbounded.
 * (The sandbox also caps memory/time/output; this is defense in depth at the driver.) */
#define MAX_INPUT 65536

int main(void) {
    static char buf[MAX_INPUT + 1];
    size_t n = fread(buf, 1, MAX_INPUT, stdin);
    buf[n] = '\0';

    cJSON *root = cJSON_Parse(buf);
    if (root == NULL) {
        printf("parse=0\n");
        return 1;
    }

    printf("parse=1\n");
    if (cJSON_IsObject(root)) {
        printf("kind=obj\n");
    } else if (cJSON_IsArray(root)) {
        printf("kind=arr\n");
    } else {
        printf("kind=other\n");
    }
    printf("size=%d\n", cJSON_GetArraySize(root));

    cJSON_Delete(root);
    return 0;
}
