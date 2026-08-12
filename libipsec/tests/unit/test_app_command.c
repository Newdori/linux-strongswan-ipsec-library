#include "app_internal.h"

#include <stdio.h>
#include <string.h>

static int32_t FailAppCommandTest(const char *pcMessage)
{
    (void)fprintf(stderr, "app command test failed: %s\n", pcMessage);
    return 1;
}

static int32_t CheckNativeAppCommand(
    const char *pcInput,
    uint32_t uiExpectedCount,
    const char *const *ppcExpected)
{
    char acLine[NATIVE_APP_COMMAND_LINE_LENGTH];
    char *pacArguments[NATIVE_APP_COMMAND_ARGUMENT_COUNT];
    uint32_t uiArgumentCount = 0U;
    uint32_t uiIndex;
    int32_t iLength;

    iLength = snprintf(acLine, sizeof(acLine), "%s", pcInput);
    if ((0 > iLength) || ((uint32_t)iLength >= sizeof(acLine))) {
        return FailAppCommandTest("test input is too long");
    }
    else if (!ParseNativeAppCommandLine(
                 acLine, pacArguments, NATIVE_APP_COMMAND_ARGUMENT_COUNT,
                 &uiArgumentCount)) {
        return FailAppCommandTest("valid command was rejected");
    }
    else if (uiExpectedCount != uiArgumentCount) {
        return FailAppCommandTest("argument count mismatch");
    }
    else {
        /* Compare each decoded argument below. */
    }

    for (uiIndex = 0U; uiIndex < uiArgumentCount; uiIndex++) {
        if (0 != strcmp(ppcExpected[uiIndex], pacArguments[uiIndex])) {
            return FailAppCommandTest("decoded argument mismatch");
        }
        else {
            /* This argument matches. */
        }
    }
    return 0;
}

int main(void)
{
    static const char *const pacShow[] = {"show", "all"};
    static const char *const pacShowDetail[] = {
        "show", "ike", "detail", "app-test"
    };
    static const char *const pacConfigLoad[] = {
        "config", "load", "/tmp/config file.conf"
    };
    static const char *const pacConfigSet[] = {
        "config", "set", "local_id", "side a"
    };
    static const char *const pacEmpty[] = {
        "config", "set", "remote_id", ""
    };
    static const char *const pacEscaped[] = {
        "config", "set", "local_id", "side a"
    };
    char acInvalid[] = "config set local_id \"unterminated";
    char acOverflow[] = "one two three";
    char *pacArguments[NATIVE_APP_COMMAND_ARGUMENT_COUNT];
    char *pacSmall[2];
    uint32_t uiArgumentCount = 0U;
    uint32_t uiValue = 0U;
    NativeAppShowOptions_t ShowOptions = {0};
    char *pacShowDetailArguments[] = {
        "show", "ike", "detail", "app-test"
    };
    char *pacInvalidShowArguments[] = {
        "show", "daemon", "peer-a"
    };

    if ((0 != CheckNativeAppCommand("  show all  \n", 2U, pacShow)) ||
        (0 != CheckNativeAppCommand(
                  "show ike detail app-test", 4U, pacShowDetail)) ||
        (0 != CheckNativeAppCommand(
                  "config load '/tmp/config file.conf'", 3U,
                  pacConfigLoad)) ||
        (0 != CheckNativeAppCommand(
                  "config set local_id \"side a\"", 4U, pacConfigSet)) ||
        (0 != CheckNativeAppCommand(
                  "config set remote_id \"\"", 4U, pacEmpty)) ||
        (0 != CheckNativeAppCommand(
                  "config set local_id side\\ a", 4U, pacEscaped))) {
        return 1;
    }
    else if (ParseNativeAppCommandLine(
                 acInvalid, pacArguments,
                 NATIVE_APP_COMMAND_ARGUMENT_COUNT, &uiArgumentCount)) {
        return FailAppCommandTest("unterminated quote was accepted");
    }
    else if (ParseNativeAppCommandLine(
                 acOverflow, pacSmall, 2U, &uiArgumentCount)) {
        return FailAppCommandTest("argument overflow was accepted");
    }
    else if (!ParseNativeAppNumber("4294967295", &uiValue) ||
             (UINT32_MAX != uiValue) ||
             ParseNativeAppNumber("4294967296", &uiValue) ||
             ParseNativeAppNumber("10ms", &uiValue)) {
        return FailAppCommandTest("number validation mismatch");
    }
    else if (!ParseNativeAppShowOptions(4U, pacShowDetailArguments,
                                        &ShowOptions) ||
             (0 != strcmp("ike", ShowOptions.pcScope)) ||
             !ShowOptions.bDetail ||
             (0 != strcmp("app-test", ShowOptions.pcName)) ||
             ParseNativeAppShowOptions(3U, pacInvalidShowArguments,
                                       &ShowOptions)) {
        return FailAppCommandTest("show option validation mismatch");
    }
    else {
        (void)printf("application command parser passed\n");
        return 0;
    }
}
