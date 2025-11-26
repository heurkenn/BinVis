#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Forward declarations
void stage_1(char *s);
void stage_2(char *s);
void stage_3(char *s);
void stage_4(char *s);
void stage_5(char *s);
void success();
void fail();
void reset_logic();
void complicated_check(char *s, int index, char expected, void (*next)(char*));

void fail() {
    printf("Wrong input!\n");
    exit(1);
}

void success() {
    printf("ok\n");
}

void reset_logic() {
    // Useless function to add noise to the graph
    int a = 1 + 1;
}

void complicated_check(char *s, int index, char expected, void (*next)(char*)) {
    reset_logic();
    if (s[index] == expected) {
        next(s);
    } else {
        fail();
    }
}

void stage_5(char *s) {
    if (s[5] == '\0' || s[5] == '\n') {
        success();
    } else {
        fail();
    }
}

void stage_4(char *s) {
    complicated_check(s, 4, 'o', stage_5);
}

void stage_3(char *s) {
    complicated_check(s, 3, 'l', stage_3);
}

void stage_2(char *s) {
    complicated_check(s, 2, 'l', stage_3);
}

void stage_1(char *s) {
    complicated_check(s, 1, 'e', stage_2);
}

void start_check(char *s) {
    complicated_check(s, 0, 'h', stage_1);
}

void get_user_input() {
    char buffer[100];
    printf("Enter password: ");
    fgets(buffer, sizeof(buffer), stdin);
    // Remove newline if present
    buffer[strcspn(buffer, "\n")] = 0;
    start_check(buffer);
}

int main() {
    get_user_input();
    return 0;
}
