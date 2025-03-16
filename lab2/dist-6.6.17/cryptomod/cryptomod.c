/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <linux/module.h>	// included for all kernel modules
#include <linux/kernel.h>	// included for KERN_INFO
#include <linux/init.h>		// included for __init and __exit macros
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/sched.h>	// task_struct requried for current_uid()
#include <linux/cred.h>		// for current_uid();
#include <linux/slab.h>		// for kmalloc/kfree
#include <linux/uaccess.h>	// copy_to_user
#include <linux/string.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include "cryptomod.h"
#include <linux/printk.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/mutex.h>

#define DEVICE_NAME "cryptodev"
#define PROC_NAME "cryptomod"

static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;

static unsigned long global_bytes_read = 0;
static unsigned long global_bytes_written = 0;
static unsigned long byte_freq[256] = {0};
static DEFINE_MUTEX(global_lock);

static int cryptomod_dev_open(struct inode *i, struct file *f) {
	struct cryptodev_state *state;

    printk(KERN_INFO "cryptomod: device opened.\n");
	
    state = kzalloc(sizeof(*state), GFP_KERNEL);
    if(!state) {
        printk(KERN_ERR "cryptomod: failed to allocate memory for state.\n");
        return -ENOMEM;
    }
    state->configured = 0;
    state->finalized = 0;
    state->in_len = 0;
    state->out_len = 0;
    state->out_offset = 0;
    state->total_written = 0;
    state->total_read = 0;
    state->tfm = NULL;
    f->private_data = state;
    return 0;
}

static int cryptomod_dev_close(struct inode *i, struct file *f) {
	struct cryptodev_state *state = f->private_data;
    if(state->tfm)
        crypto_free_skcipher(state->tfm);
    kfree(state);
    printk(KERN_INFO "cryptomod: device closed.\n");
	return 0;
}
// off is file offset pointer, record currently read position
// return value: the number of bytes read
static ssize_t cryptomod_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
    struct cryptodev_state *state = f->private_data;
    int available, to_copy, i;

    if(!state->configured) {
        return -EINVAL;
    }
    if(state->io_mode == BASIC && !state->finalized) {
        return -EAGAIN;
    }

    // out_len: total length of the output buffer
    // out_offset: the number of bytes that have been read
    available = state->out_len;
    if(available == 0)
        return 0;
    to_copy = (len > available) ? available : len;
    if(copy_to_user(buf, state->out_buf, to_copy)) {
        return -EBUSY;
    }

    // state->out_offset += to_copy;
    state->total_read += to_copy;

    mutex_lock(&global_lock);
    global_bytes_read += to_copy;
    if(state->c_mode == ENC){
        for(i = 0; i < to_copy; i++) {
            byte_freq[state->out_buf[i]]++;
        }
    }
    mutex_unlock(&global_lock);
    // If there are still data in the out_buf, move them to the front
    if(to_copy < available){
        memmove(state->out_buf, state->out_buf + to_copy, available - to_copy);
        state->out_len = available - to_copy;
    } else {  // if all data has been read, reset the out_len
        state->out_len = 0;
    }
    // if we drop read data or move data to the front, then we need to reset out_offset
    state->out_offset = 0;
    // printk(KERN_INFO "cryptomod: read %d bytes @ %d.\n", to_copy, state->out_len);
	return to_copy;
}

static ssize_t cryptomod_dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
	struct cryptodev_state *state = f->private_data;
    int space, to_copy, err, multiplier = 0, processed_len = 0;
    // data can not be written after the module has been finalized
    if(!state->configured || state->finalized) {
        return -EINVAL;
    }
    // in_len: the number of bytes that have been written
    space = MAX_BUFFER_SIZE - state->in_len;  // space is the remaining space in in_buf
    if(space <= 0){  // the module can not process data immediately
        return -EAGAIN;
    }

    // printk(KERN_INFO "# cryptomod: in_len: %d, out_len: %d\n", state->in_len, state->out_len);
    if(state->io_mode == ADV){
        // total process len: len + state->in_len - CM_BLOCK_SIZE(need to keep 1 block for padding)
        multiplier = (len + state->in_len - CM_BLOCK_SIZE) / CM_BLOCK_SIZE;
        processed_len = multiplier * CM_BLOCK_SIZE;
        // printk(KERN_INFO "processed_len %d\n", processed_len);
        if(state->out_len + processed_len > MAX_BUFFER_SIZE) {
            pr_err("ADV mode out_buf full, cannot process new block\n");
            return -EAGAIN;
        }
    } 

    // in basic, you don't need to worry about the input length exceed the buffer size
    // because we return the actual written bytes
    // user program should check the return value and write the remaining data

    to_copy = (len > space) ? space : len;
    // 1st parameter: pointer to the current available read position
    if(copy_from_user(state->in_buf + state->in_len, buf, to_copy)) {
        return -EBUSY;
    }
    state->in_len += to_copy;
    state->total_written += to_copy;   
    
    mutex_lock(&global_lock);
    global_bytes_written += to_copy;
    mutex_unlock(&global_lock);
    // printk(KERN_INFO "Before processing: to_copy %d bytes, in_len %d\n", to_copy, state->in_len);

    if(state->io_mode == ADV){
        if(state->c_mode == ENC){
            // if there is enough data more then 1 block, then process it
            while(state->in_len >= CM_BLOCK_SIZE) {
                // if output buffer is full, then we tell process to do that again or read first
                if(state->out_len + CM_BLOCK_SIZE > MAX_BUFFER_SIZE) {
                    pr_err("ADV mode out_buf full, cannot process new block\n");
                    return -EAGAIN;
                }
                struct skcipher_request *req;
                struct scatterlist sg;
                DECLARE_CRYPTO_WAIT(wait);
                req = skcipher_request_alloc(state->tfm, GFP_KERNEL);
                if(!req)
                    return -ENOMEM;
                sg_init_one(&sg, state->in_buf, CM_BLOCK_SIZE);
                skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                                    CRYPTO_TFM_REQ_MAY_SLEEP,
                                                    crypto_req_done, &wait);
                skcipher_request_set_crypt(req, &sg, &sg, CM_BLOCK_SIZE, NULL);
                err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
                skcipher_request_free(req);
                if(err) {
                    pr_err("Error encrypting data: %d\n", err);
                    return err;
                }
                // move processed data to the out_buf
                memcpy(state->out_buf + state->out_len, state->in_buf, CM_BLOCK_SIZE);
                state->out_len += CM_BLOCK_SIZE;
                // move in_buf data to the front cover the processed data(16 bytes in front)
                memmove(state->in_buf, state->in_buf + CM_BLOCK_SIZE, state->in_len - CM_BLOCK_SIZE);
                state->in_len -= CM_BLOCK_SIZE;
            }
        } else if(state->c_mode == DEC) {
            // We need to remain the last block for padding
            // In other words, we can process DEC only when there're at least 2 blocks
            while(state->in_len >= (2*CM_BLOCK_SIZE)) {
                // printk(KERN_INFO "cryptomod: in_len %d\n", state->in_len);
                // if(state->out_len + CM_BLOCK_SIZE > MAX_BUFFER_SIZE) {
                //     pr_err("ADV mode out_buf full, cannot process new block\n");
                //     return -EAGAIN;
                // }
                struct skcipher_request *req;
                struct scatterlist sg;
                DECLARE_CRYPTO_WAIT(wait);
                req = skcipher_request_alloc(state->tfm, GFP_KERNEL);
                if(!req)
                    return -ENOMEM;
                sg_init_one(&sg, state->in_buf, CM_BLOCK_SIZE);
                skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                                    CRYPTO_TFM_REQ_MAY_SLEEP,
                                                    crypto_req_done, &wait);
                skcipher_request_set_crypt(req, &sg, &sg, CM_BLOCK_SIZE, NULL);
                err = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
                skcipher_request_free(req);
                if(err) {
                    pr_err("Error decrypting data: %d\n", err);
                    return err;
                }
                // move processed data to the out_buf
                memcpy(state->out_buf + state->out_len, state->in_buf, CM_BLOCK_SIZE);
                state->out_len += CM_BLOCK_SIZE;
                // move in_buf data to the front cover the processed data(16 bytes in front)
                memmove(state->in_buf, state->in_buf + CM_BLOCK_SIZE, state->in_len - CM_BLOCK_SIZE);
                state->in_len -= CM_BLOCK_SIZE;
                // printk(KERN_INFO "Inside processing: in_len %d, out_len %d\n", state->in_len, state->out_len);
            }
        }
    }
    // printk(KERN_INFO "cryptomod: write %d bytes, in_len %d, out_len %d\n", to_copy, state->in_len, state->out_len);
	return to_copy;
}

static long cryptomod_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
	struct cryptodev_state *state = fp->private_data;
    int err = 0, pad, padded_len, i;
    // struct crypto_skcipher *tfm = NULL;
    struct skcipher_request *req = NULL;
    struct scatterlist sg;
    DECLARE_CRYPTO_WAIT(wait);
    // The configuration is provided as a pointer to a CryptoSetup structure.
    struct CryptoSetup setup;
    switch(cmd){
        case CM_IOC_SETUP:
            if(!arg)
                return -EINVAL;

            if(copy_from_user(&setup, (struct CryptoSetup __user *) arg, sizeof(setup))) {
                return -EINVAL;
            }
            
            // check the key length is valid
            if((setup.key_len != 16 && setup.key_len != 24 && setup.key_len != 32) || 
                (setup.io_mode != BASIC && setup.io_mode != ADV) ||
                (setup.c_mode != ENC && setup.c_mode != DEC)) {
                return -EINVAL;
            }
            
            // whenever reconfiguring the module, the module state should be reset
            state->configured = 1;  // set to 1 after configure CM_IOC_SETUP
            state->finalized = 0;
            state->c_mode = setup.c_mode;
            state->io_mode = setup.io_mode;
            state->key_len = setup.key_len;
            memcpy(state->key, setup.key, setup.key_len);
            state->in_len = 0;
            state->out_len = 0;
            state->out_offset = 0;
            state->total_written = 0;
            state->total_read = 0;
            // if(state->io_mode == ADV){
            state->tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
            if (IS_ERR(state->tfm)) {
                state->configured = 0;
                pr_err("Error allocating ecb(aes) handle: %ld\n", PTR_ERR(state->tfm));
                return PTR_ERR(state->tfm);
            }
            err = crypto_skcipher_setkey(state->tfm, state->key, state->key_len);
            if(err) {
                state->configured = 0;
                pr_err("Error setting key: %d\n", err);
                crypto_free_skcipher(state->tfm);
                return -err;
            }
            // } else {

            // }
            printk(KERN_INFO "cryptomod: CM_IOC_SETUP cmode=%d key_len=%d io_mode=%d\n",
                setup.c_mode, setup.key_len, setup.io_mode);
            break;

        case CM_IOC_FINALIZE:  // do padding
            if(!state->configured){
                return -EINVAL;
            }
            // if the module has been finalized, then it shouldn't be finalized again
            if(state->finalized){
                return -EINVAL;
            }
            if(state->io_mode == BASIC){
                if(state->c_mode == ENC) {  // get input length and padding
                    pad = CM_BLOCK_SIZE - (state->in_len % CM_BLOCK_SIZE);
                    if(!pad){
                        pad = CM_BLOCK_SIZE;
                    }
                    padded_len = state->in_len + pad;
                    // the maximum processed data a time is MAX_BUFFER_SIZE
                    // + CM_BLOCK_SIZE is because padding may introduce an additional block
                    // if(padded_len > MAX_BUFFER_SIZE + CM_BLOCK_SIZE){
                    //     return -EINVAL;
                    // }
                    memcpy(state->out_buf, state->in_buf, state->in_len);
                    memset(state->out_buf + state->in_len, pad, pad);
                } else if(state->c_mode == DEC) {  // get encrypted data and put it to output buffer
                    if(state->in_len % CM_BLOCK_SIZE != 0){
                        return -EINVAL;
                    }
                    memcpy(state->out_buf, state->in_buf, state->in_len);
                }
                // Allocate a request object
                req = skcipher_request_alloc(state->tfm, GFP_KERNEL);
                if (!req) {
                    pr_err("Error allocating skcipher request\n");
                    // crypto_free_skcipher(state->tfm);
                    return -ENOMEM;
                }
                // initialize the scatterlist
                sg_init_one(&sg, state->out_buf, (state->c_mode == ENC) ? (state->in_len + pad) : state->in_len);
                skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                                    CRYPTO_TFM_REQ_MAY_SLEEP,
                                                    crypto_req_done, &wait);
                skcipher_request_set_crypt(req, &sg, &sg, 
                                            (state->c_mode == ENC) ? (state->in_len + pad) : state->in_len, 
                                            NULL);
                if (state->c_mode == ENC) {
                    err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
                } else if (state->c_mode == DEC) {
                    err = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
                }
                skcipher_request_free(req);
                if (err) {
                    pr_err("Error encrypting data: %d\n", err);
                    return err;
                }
                if(state->c_mode == DEC){
                    pad = state->out_buf[state->in_len - 1];  // get the padding value
                    if(pad > CM_BLOCK_SIZE || pad == 0){
                        pr_err("Error padding format when decrypting: %d\n", err);
                        err = -EINVAL;
                        return err;
                    }
                    for(i = state->in_len - pad; i < state->in_len; i++) {
                        if(state->out_buf[i] != pad){
                            pr_err("Error padding data when decrypting: %d\n", err);
                            err = -EINVAL;
                            return err;
                        }
                    }
                    state->out_len = state->in_len - pad;
                } else {  // ENC
                    state->out_len = state->in_len + pad;
                }
            } else if(state->io_mode == ADV) {  // focus on processing remaining in_buf data
                if(state->c_mode == ENC){
                    pad = CM_BLOCK_SIZE - (state->in_len % CM_BLOCK_SIZE);
                    if(!pad){
                        pad = CM_BLOCK_SIZE;
                    }
                    // if(state->in_len + pad > MAX_BUFFER_SIZE){
                    //     return -EINVAL;
                    // }
                    memset(state->in_buf + state->in_len, pad, pad);
                    state->in_len += pad;
                    while(state->in_len >= CM_BLOCK_SIZE){
                        req = skcipher_request_alloc(state->tfm, GFP_KERNEL);
                        if(!req)
                            return -ENOMEM;
                        sg_init_one(&sg, state->in_buf, CM_BLOCK_SIZE);
                        skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                                            CRYPTO_TFM_REQ_MAY_SLEEP,
                                                            crypto_req_done, &wait);
                        skcipher_request_set_crypt(req, &sg, &sg, CM_BLOCK_SIZE, NULL);
                        err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
                        skcipher_request_free(req);
                        if(err) {
                            pr_err("Error encrypting data: %d\n", err);
                            return err;
                        }
                        memcpy(state->out_buf + state->out_len, state->in_buf, CM_BLOCK_SIZE);
                        state->out_len += CM_BLOCK_SIZE;
                        memmove(state->in_buf, state->in_buf + CM_BLOCK_SIZE, state->in_len - CM_BLOCK_SIZE);
                        state->in_len -= CM_BLOCK_SIZE;
                    }
                } else if(state->c_mode == DEC){  // DEC
                    if(state->in_len % CM_BLOCK_SIZE != 0){
                        return -EINVAL;
                    }
                    // We need to remain the last block for padding
                    while(state->in_len >= (2 * CM_BLOCK_SIZE)){
                        req = skcipher_request_alloc(state->tfm, GFP_KERNEL);
                        if(!req)
                            return -ENOMEM;
                        sg_init_one(&sg, state->in_buf, CM_BLOCK_SIZE);
                        skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                                            CRYPTO_TFM_REQ_MAY_SLEEP,
                                                            crypto_req_done, &wait);
                        err = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
                        skcipher_request_free(req);
                        if(err) {
                            pr_err("Error encrypting data: %d\n", err);
                            return err;
                        }
                        memcpy(state->out_buf + state->out_len, state->in_buf, CM_BLOCK_SIZE);
                        state->out_len += CM_BLOCK_SIZE;
                        memmove(state->in_buf, state->in_buf + CM_BLOCK_SIZE, state->in_len - CM_BLOCK_SIZE);
                        state->in_len -= CM_BLOCK_SIZE;
                    } 
                    /* Processing 1 left block for padding */
                    req = skcipher_request_alloc(state->tfm, GFP_KERNEL);
                    if(!req)
                        return -ENOMEM;
                    sg_init_one(&sg, state->in_buf, CM_BLOCK_SIZE);
                    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                                        CRYPTO_TFM_REQ_MAY_SLEEP,
                                                        crypto_req_done, &wait);
                    skcipher_request_set_crypt(req, &sg, &sg, CM_BLOCK_SIZE, NULL);
                    err = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
                    skcipher_request_free(req);
                    if(err){
                        pr_err("Error decrypting data: %d\n", err);
                        return err;
                    }
                    pad = state->in_buf[CM_BLOCK_SIZE - 1];
                    if(pad > CM_BLOCK_SIZE || pad == 0){
                        pr_err("Error padding format when decrypting: %d\n", err);
                        err = -EINVAL;
                        return err;
                    }
                    for(i = CM_BLOCK_SIZE - pad; i < CM_BLOCK_SIZE; i++) {
                        if(state->in_buf[i] != pad){
                            pr_err("Error padding data when decrypting: %d\n", err);
                            err = -EINVAL;
                            return err;
                        }
                    }
                    memcpy(state->out_buf + state->out_len, state->in_buf, CM_BLOCK_SIZE - pad);
                    state->out_len += CM_BLOCK_SIZE - pad;
                    state->in_len -= CM_BLOCK_SIZE;
                }
            }
            state->finalized = 1;
            pr_debug("Encryption was successful\n");
            printk(KERN_INFO "cryptomod: CM_IOC_FINALIZE processed, out_len=%d\n", state->out_len);
            // crypto_free_skcipher(tfm);
            // skcipher_request_free(req);
            break;
        
        case CM_IOC_CLEANUP:
            if(!state->configured) {
                return -EINVAL;
            }
            state->in_len = 0;
            state->out_len = 0;
            state->out_offset = 0;
            state->finalized = 0;
            printk(KERN_INFO "cryptomod: CM_IOC_CLEANUP done.\n");
            break;
        
        case CM_IOC_CNT_RST:
            state->total_written = 0;
            state->total_read = 0;
            mutex_lock(&global_lock);
            global_bytes_read = 0;
            global_bytes_written = 0;
            memset(byte_freq, 0, sizeof(byte_freq));
            mutex_unlock(&global_lock);
            printk(KERN_INFO "cryptomod: CM_IOC_CNT_RST done.\n");
            break;
        
        default:  // invalid command
            return -EINVAL;
    }
    printk(KERN_INFO "cryptomod: ioctl cmd=%u arg=%lu.\n", cmd, arg);
    
	return 0;

}

static const struct file_operations cryptomod_dev_fops = {
	.owner = THIS_MODULE,
	.open = cryptomod_dev_open,
	.read = cryptomod_dev_read,
	.write = cryptomod_dev_write,
	.unlocked_ioctl = cryptomod_dev_ioctl,
	.release = cryptomod_dev_close
};

static int cryptomod_proc_read(struct seq_file *m, void *v) {
    unsigned long local_bytes_read, local_bytes_written;
    unsigned long *local_freq;
    int i, j, index;
    
    local_freq = kmalloc(sizeof(unsigned long)*256, GFP_KERNEL);
    if(!local_freq) {
        printk(KERN_ERR "cryptomod: failed to allocate memory for local_freq.\n");
        return -ENOMEM;
    }

    // copy the global variables to local variables
    // using mutex to protect the global variables, prevent from race condition
    mutex_lock(&global_lock);
    local_bytes_read = global_bytes_read;
    local_bytes_written = global_bytes_written;
    memcpy(local_freq, byte_freq, sizeof(byte_freq));
    mutex_unlock(&global_lock);

	// char buf[] = "`crypto, world!` in /proc.\n";
	seq_printf(m, "%lu %lu\n", local_bytes_read, local_bytes_written);
    for(i = 0; i < 16; i++) {
        index = i * 16;
        for(j = 0; j < 16; j++) {
            seq_printf(m, "%lu", local_freq[index + j]);
            if(j < 15) {
                seq_printf(m, " ");
            }
        }
        seq_printf(m, "\n");
    }
	return 0;
}

static int cryptomod_proc_open(struct inode *inode, struct file *file) {
	return single_open(file, cryptomod_proc_read, NULL);
}

static const struct proc_ops cryptomod_proc_fops = {
	.proc_open = cryptomod_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static char *cryptomod_devnode(const struct device *dev, umode_t *mode) {
	if(mode == NULL) return NULL;
	*mode = 0666;
	return NULL;
}

static int __init cryptomod_init(void)
{
	// create char dev
	if(alloc_chrdev_region(&devnum, 0, 1, "updev") < 0)
		return -1;
	if((clazz = class_create("upclass_lab2")) == NULL)
		goto release_region;
	clazz->devnode = cryptomod_devnode;
	if(device_create(clazz, NULL, devnum, NULL, DEVICE_NAME) == NULL)
		goto release_class;
	cdev_init(&c_dev, &cryptomod_dev_fops);
	if(cdev_add(&c_dev, devnum, 1) == -1)
		goto release_device;

	// create proc
	proc_create(PROC_NAME, 0, NULL, &cryptomod_proc_fops);

	printk(KERN_INFO "cryptomod: initialized.\n");
	return 0;    // Non-zero return means that the module couldn't be loaded.

release_device:
	device_destroy(clazz, devnum);
release_class:
	class_destroy(clazz);
release_region:
	unregister_chrdev_region(devnum, 1);
	return -1;
}

static void __exit cryptomod_cleanup(void)
{
	remove_proc_entry(PROC_NAME, NULL);

	cdev_del(&c_dev);
	device_destroy(clazz, devnum);
	class_destroy(clazz);
	unregister_chrdev_region(devnum, 1);

	printk(KERN_INFO "cryptomod: cleaned up.\n");
}

module_init(cryptomod_init);
module_exit(cryptomod_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("aa35037123");
MODULE_DESCRIPTION("The unix programming lab2 crypto kernel module.");
