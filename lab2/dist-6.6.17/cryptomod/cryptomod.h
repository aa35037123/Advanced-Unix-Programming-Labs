#ifndef CRYPTOMOD_H
#define CRYPTOMOD_H

#include <crypto/skcipher.h>
#include <linux/scatterlist.h>

#define CM_KEY_MAX_LEN 32
#define CM_BLOCK_SIZE 16
#define MAX_BUFFER_SIZE 1024

// ENC: encryption, DEC: decryption
enum CryptoMode { ENC, DEC };
// BASIC: basic I/O mode, ADV: advanced I/O mode
enum IOMode { BASIC, ADV };

struct CryptoSetup {
    char key[CM_KEY_MAX_LEN];
    // valid key length are 16, 24, 32
    int key_len;
    enum IOMode io_mode;
    enum CryptoMode c_mode;
};

struct cryptodev_state {
    int configured;  // set to 1 after configure CM_IOC_SETUP
    int finalized;   // set to 1 after finalize CM_IOC_FINALIZE
    enum CryptoMode c_mode;
    enum IOMode io_mode;
    int key_len;
    char key[CM_KEY_MAX_LEN];

    unsigned char in_buf[MAX_BUFFER_SIZE];
    int in_len;  // total in_buf length
    
    // out buffet needs to padding to be mulitple of block size 
    unsigned char out_buf[MAX_BUFFER_SIZE];
    int out_len;  // total out_buf length
    int out_offset;  // current read position in out_buf

    unsigned long total_written;
    unsigned long total_read;

    // used when adv io_mode
    struct crypto_skcipher *tfm;
};
// ioctl command
#define CM_IOC_MAGIC 'k'
#define CM_IOC_SETUP _IOW(CM_IOC_MAGIC, 1, struct CryptoSetup)
#define CM_IOC_FINALIZE _IO(CM_IOC_MAGIC, 2)
#define CM_IOC_CLEANUP _IO(CM_IOC_MAGIC, 3)
#define CM_IOC_CNT_RST _IO(CM_IOC_MAGIC, 4)

// state maintained by each opened file descriptor

#endif
