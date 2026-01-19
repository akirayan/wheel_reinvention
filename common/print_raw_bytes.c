
/**
 * @brief Print each byte as hex
 * @param p The starting address
 * @param length The count of bytes to print
 */
void print_raw_bytes(uint8_t *p, int length) {
    for (int i=0; i < length; ++i) {
        printf("%02x ", *(p + i));
        if (((i+1) % 8)==0) printf(" ");
        if (((i+1) % 16)==0) printf("\n");
    }
    printf("\n");
}

