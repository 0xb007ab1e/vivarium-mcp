/*
 * driver_cjson.c — tiny benign driver linked with cJSON.c to produce a fixture binary with a
 * real, non-trivial internal call graph (WS5 e2e ground truth). NOT shipped anywhere; compiled
 * only by the gated fixtures-build job. No I/O beyond stdout, no untrusted input (the JSON is a
 * fixed literal), so it is safe and deterministic (master §5 / PLAN §6: no real malware).
 *
 * It drives the cJSON parse + print + accessor paths so the extracted ground truth contains a
 * meaningful caller->callee graph (cJSON_Parse -> parse_value -> parse_object/array/string/...,
 * cJSON_Print -> print_value -> ..., plus the accessors and cJSON_Delete teardown).
 */
#include "cJSON.h"
#include <stdio.h>

int main(void) {
    const char *json =
        "{\"name\":\"fixture\",\"nums\":[1,2,3,4],\"nested\":{\"ok\":true,\"f\":1.5},"
        "\"tags\":[\"a\",\"b\"]}";

    cJSON *root = cJSON_Parse(json);
    if (root == NULL) {
        return 1;
    }

    char *printed = cJSON_Print(root);
    if (printed != NULL) {
        printf("%s\n", printed);
        cJSON_free(printed);
    }

    const cJSON *nums = cJSON_GetObjectItemCaseSensitive(root, "nums");
    int n = cJSON_GetArraySize(nums);
    printf("nums=%d\n", n);

    const cJSON *nested = cJSON_GetObjectItemCaseSensitive(root, "nested");
    const cJSON *ok = cJSON_GetObjectItemCaseSensitive(nested, "ok");
    printf("ok=%d\n", cJSON_IsTrue(ok));

    cJSON_Delete(root);
    return 0;
}
