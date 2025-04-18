__attribute__((naked)) void test() {
    __asm__ volatile (
        "sub $0x80, %rsp\n"
        "movabs $0x1122334455667788, %r11\n"
        "jmp *%r11\n"
    );
}
