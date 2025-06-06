/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>     /* kmalloc() */
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
#include "aesd_ioctl.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("John Hogan");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *dev;

    PDEBUG("open");

    // get a pointer to aesd_dev object
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;

    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");

    // not sure if there is anything to do here
    return 0;
}

loff_t aesd_llseek(struct file *filp, loff_t off, int whence) {
    uint8_t index;
    struct aesd_buffer_entry *entry;
	loff_t new_off;
	loff_t dev_size = 0;
	struct aesd_dev *aesd_device = filp->private_data;

	PDEBUG("llseek");

	// get total size of file
    if (mutex_lock_interruptible(&aesd_device->lock)) {
        return -ERESTARTSYS;
    }
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device->buffer, index) {
        dev_size += (loff_t)entry->size;
    }
    mutex_unlock(&aesd_device->lock);

    new_off = fixed_size_llseek(filp, off, whence, dev_size);

    if (new_off < 0) return -EINVAL;
    filp->f_pos = new_off;
    return new_off;
}

static long aesd_adjust_file_offset(struct file *filp, int write_cmd, int write_cmd_offset) {
    int buff_idx;
    int index;
    int cmds_in_buffer;
    size_t new_off = 0;
	struct aesd_dev *aesd_device = filp->private_data;
	struct aesd_circular_buffer buffer = aesd_device->buffer;

    if (mutex_lock_interruptible(&aesd_device->lock)) {
        return -ERESTARTSYS;
    }

    cmds_in_buffer = buffer.full ? AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED : 
                                   (buffer.in_offs + AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED - buffer.out_offs) 
                                    % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    if (write_cmd >= cmds_in_buffer) {
        return -EINVAL;
    }

    // starting from read pointer, add up the size of first write_cmd entries
    buff_idx = buffer.out_offs;
    for (index = 0; index < write_cmd; index++) {
        new_off += buffer.entry[buff_idx].size;
        INCR_OFFSET(buff_idx);
    }
    // next, bounds check write_cmd_offset then add that number to the new
    // offset
    if (write_cmd_offset >= buffer.entry[buff_idx].size) {
        return -EINVAL;
    }
    mutex_unlock(&aesd_device->lock);

    new_off += write_cmd_offset;
    filp->f_pos = new_off;
    return new_off;
}

long aesd_ioctl(struct file *filp,
                unsigned int cmd, unsigned long arg) {
	long retval = 0;
    
	PDEBUG("ioctl");
	/*
	 * extract the type and number bitfields, and don't decode
	 * wrong cmds: return ENOTTY (inappropriate ioctl) before access_ok()
	 */
	if (_IOC_TYPE(cmd) != AESD_IOC_MAGIC) return -ENOTTY;
	if (_IOC_NR(cmd) > AESDCHAR_IOC_MAXNR) return -ENOTTY;

	switch(cmd) {
        case AESDCHAR_IOCSEEKTO: {
            struct aesd_seekto seekto;
            if (copy_from_user(&seekto, (const void __user *)arg, sizeof(struct aesd_seekto))) {
                retval = -EFAULT;
            } else {
                retval = aesd_adjust_file_offset(filp, seekto.write_cmd, seekto.write_cmd_offset);
            }
            break;
        }
	    default:  /* redundant, as cmd was checked against MAXNR */
            return -ENOTTY;
    }

	return retval;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    struct aesd_dev *aesd_device = filp->private_data;
    ssize_t retval = 0;
    struct aesd_buffer_entry *entry;
    size_t entry_offset;

    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);

    if (mutex_lock_interruptible(&aesd_device->lock)) {
        return -ERESTARTSYS;
    }

    // find the correct entry
    entry = aesd_circular_buffer_find_entry_offset_for_fpos(
        &aesd_device->buffer, *f_pos, &entry_offset);
    if (!entry) {
        mutex_unlock(&aesd_device->lock);
        return 0;
    }

    // only write out the bytes from this entry
    if (entry->size - entry_offset < count) {
        count = entry->size - entry_offset;
    }

    if (copy_to_user(buf, entry->buffptr + entry_offset, count)) {
        retval = -EFAULT;
        goto out;
    }
    *f_pos += count;
    retval = count;

    mutex_unlock(&aesd_device->lock);

out:
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    struct aesd_dev *aesd_device = filp->private_data;
    struct aesd_buffer_entry *working = &aesd_device->working;
    ssize_t retval = -ENOMEM;
    char *new_buf;

    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);

    if (mutex_lock_interruptible(&aesd_device->lock)) {
        return -ERESTARTSYS;
    }

    if (working->buffptr) {
        // if there is a leftover buffer, use realloc and append data to
        // existing
        new_buf = krealloc(
                working->buffptr, working->size + count + 1, GFP_KERNEL);
        if (!new_buf) {
            goto out;
        }

        if (copy_from_user(new_buf + working->size, buf, count)) {
            retval = -EFAULT;
            goto out;
        }
        new_buf[working->size + count] = '\0';

        working->buffptr = new_buf;
        working->size += count;
    } else {
        char *new_buf = kmalloc(count + 1, GFP_KERNEL);
        if (!new_buf) {
            goto out;
        }
        if (copy_from_user(new_buf, buf, count)) {
            retval = -EFAULT;
            goto out;
        }
        new_buf[count] = '\0';

        working->buffptr = new_buf;
        working->size = count;
    }

    char *pch = strrchr(working->buffptr, '\n');
    if (pch) {
        if (pch - working->buffptr < working->size - 1) {
            // corner case, there is a \n in the middle
            // for now, I'll ignore corner case and write the whole working buffer
            PDEBUG("found a carriage return in middle of command\n");
        }

        const char *buf_to_free =
            aesd_circular_buffer_add_entry(&aesd_device->buffer, working);
        if (buf_to_free) {
            kfree((char*)buf_to_free);
        }

        // reset the working buffer since we wrote its data to the circular
        // buffer
        working->buffptr = NULL;
        working->size = 0;
    }

    mutex_unlock(&aesd_device->lock);

    retval = count;

out:
    return retval;
}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .llseek =   aesd_llseek,
	.unlocked_ioctl = aesd_ioctl,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * initialize the AESD specific portion of the device
     */
    aesd_circular_buffer_init(&aesd_device.buffer);
    mutex_init(&aesd_device.lock);

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    uint8_t index;
    struct aesd_buffer_entry *entry;

    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * cleanup AESD specific poritions here as necessary
     */
    // free all memory
    index = 0;
    entry = NULL;
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, index) {
        kfree(entry->buffptr);
    }


    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
