#pragma region Linux Headers

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/overflow.h>

#pragma endregion

#include "reader_ioctl.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Friend");
MODULE_DESCRIPTION("My friend");

// How big the array of watch references is
// Also used to iterate over the array for cleanup
#define WATCH_COUNT 10

#pragma region Structs

static long my_ioctl(struct file* file, unsigned int cmd, unsigned long arg);
static int my_mmap(struct file* file, struct vm_area_struct* vma);
static int my_open(struct inode *inode, struct file *file);
static int my_release(struct inode *inode, struct file *file);

static const struct file_operations my_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = my_ioctl,
    .mmap           = my_mmap,
    .open           = my_open,
    .release        = my_release,
};

static struct miscdevice my_misc_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "friend",
    .fops  = &my_fops,
    // TODO: Change this -- serious security risk
    .mode  = 0666,
};

#pragma region Private data context

// Memory allocation info
struct MaInfo
{
    void* ma_start_address;
    size_t ma_size;
};

struct Friend_Context {
    // The pid of the process targeted by all operations
    pid_t pid;

    // Info of the dump vma
    struct MaInfo dump_info;

    // Info of the watches
    struct MaInfo watch_info[WATCH_COUNT];
};

#pragma endregion

#pragma region Dump structs

struct Area_Dump
{
    __u64 target_address;
    __u64 area_size;
    __u8 dump_data[/*area_size*/];
};

struct Dump_Header
{
    __u64 area_count;
    struct Area_Dump area_dumps[/*area_count*/];
};

#pragma endregion

#pragma endregion

#pragma region Init and exit

static int __init my_init(void)
{
    int ret;

    ret = misc_register(&my_misc_device);
    if (ret) {
        pr_err("[friend]: misc_register failed: %d\n", ret);
        return ret;
    }

    pr_info("[friend]: loaded\n");
    return 0;
}

static void __exit my_exit(void)
{
    misc_deregister(&my_misc_device);
    pr_info("[friend]: unloaded\n");
}

module_init(my_init);
module_exit(my_exit);

#pragma endregion

#pragma region MMap + open + release

static int my_mmap(struct file* file, struct vm_area_struct* vma)
{
    unsigned long allocation_selector = vma->vm_pgoff;

    // Userspace wants to map the dump allocation
    if(allocation_selector == 0)
    {
        // Cast private data to context struct
        struct Friend_Context* friend_context = file-> private_data;

        // Get dump buffer location and size from private data
        void* dump_buffer = friend_context-> dump_info.ma_start_address;
        size_t dump_size = friend_context-> dump_info.ma_size;

        // If there is no dump allocation stored, error
        if(!dump_buffer)
        {
            pr_info("[friend]: During mmap, no buffer was stored\n");
            return -EINVAL;
        }

        // Ensure that user-space has not requested more than we have
        size_t requested_size = vma->vm_end - vma->vm_start;
        if(requested_size > dump_size)
        {
            pr_info("[friend]: During mmap, requested size was bigger than dump size\n");
            return -EINVAL;
        }

        // Perform the remap
        return remap_vmalloc_range(vma, dump_buffer, 0);
    }
    // Userpsace wants to map a watch allocation
    else
    {
        // Not implemented for now...
        return -EINVAL;
    }
}

static int my_open(struct inode *inode, struct file *file)
{
    struct Friend_Context *ctx;

    ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx)
        return -ENOMEM;

    file->private_data = ctx;

    return 0;
}

static int my_release(struct inode *inode, struct file *file)
{
    struct Friend_Context *ctx = file->private_data;

    if (ctx) {
        // Free dump
        void* dump_start_address = ctx->dump_info.ma_start_address;
        if (dump_start_address)
        {
            vfree(dump_start_address);
        }
        // Free watches
        for(int watch_index = 0; watch_index < WATCH_COUNT; watch_index++)
        {
            void* watch_start_address = ctx->watch_info[watch_index].ma_start_address;
            if(watch_start_address)
            {
                vfree(watch_start_address);
            }
        }

        kfree(ctx);
    }

    return 0;
}

#pragma endregion

#pragma region IOCTL switch

// Needs the PID
static int SetTarget(struct file*, unsigned long arg);
// Needs the struct to return allocated size to user-space
static int DumpProcess(struct file*, unsigned long arg);
// Needs an address list struct
static int DumpProcessAddressList(struct file*, unsigned long arg);
// Needs an address list struct
static int WatchProcessAddressList(struct file*, unsigned long arg);

static long my_ioctl(struct file* file,
                     unsigned int cmd,
                     unsigned long arg)
{
    // Reject commands that do not belong to this driver.
    if (_IOC_TYPE(cmd) != FRIEND_IOC_MAGIC)
        return -ENOTTY;

    switch (cmd) {
        case FRIEND_SET_TARGET_IOC:
            return SetTarget(file, arg);

        case FRIEND_DUMP_PROCESS_IOC:
            return DumpProcess(file, arg);

        case FRIEND_DUMP_PROCESS_ADDRESSLIST:
            return DumpProcessAddressList(file, arg);
        
        case FRIEND_WATCH_PROCESS_ADDRESSLIST:
            return WatchProcessAddressList(file, arg);

    default:
        return -ENOTTY;
    }
}

#pragma endregion

#pragma region IOCTL function definitions

// Sets the PID inside of the private data which is used for the other functions
static int SetTarget(struct file* file, unsigned long arg)
{
    // Get the PID from the arg
    __s32 pid;
    if(copy_from_user(&pid, (__s32 __user*)arg, sizeof(pid)))
    {
        // Copy failed
        return -EFAULT;
    }

    // Set the PID
    ((struct Friend_Context*)(file->private_data))-> pid = pid;
    
    return 0;
}

// Dumps the currently targeted process to a kernel vma
// The reference to this vma is stored in private data and can be mmap'd by the user
static int DumpProcess(struct file* file, unsigned long arg)
{
    // Initialise initial structures
    #pragma region Initial structs

    // Get context instance
    struct Friend_Context* friend_context_instance = (struct Friend_Context*)(file->private_data);

    // PID struct
    struct pid* pid_struct_pointer = NULL;
    // Task struct
    struct task_struct* task_struct_pointer = NULL;
    // mm struct
    struct mm_struct* mm_struct_pointer = NULL;
    // Are the VMAs currently locked?
    bool vmas_currently_locked = false;
    // Has an error of any kind ocurred?
    bool is_error = false;
    // Get the PID of the target process
    pid_t pid = friend_context_instance -> pid;

    // Initialise shared_buffer
    void* shared_buffer = NULL;

    // Get PID struct
    pid_struct_pointer = find_get_pid(pid);
    if (!pid_struct_pointer)
    {
        pr_info("[friend]: Failed to get PID struct\n");
        is_error = true;
        goto release;
    }

    // Get task struct
    task_struct_pointer = get_pid_task(pid_struct_pointer, PIDTYPE_TGID);      
    if (!task_struct_pointer)
    {
        pr_info("[friend]: Failed to get task struct\n");
        is_error = true;
        goto release;
    }

    // Get mm struct
    mm_struct_pointer = get_task_mm(task_struct_pointer);
    if (!mm_struct_pointer)
    {
        pr_info("[friend]: Failed to get mm struct\n");
        is_error = true;
        goto release;
    }

    #pragma endregion

    // Iterate over userspace VMAs for info: total vma size and region count
    #pragma region Iterate over VMAs first pass for info

    // The total size of all of the VMAs
    // An estimate because when the VMAs are unlocked this could be slightly wrong
    size_t total_vma_size_estimate = 0;
    // The total number of VMAs
    size_t total_vma_count = 0;

    // Lock the VMAs
    mmap_read_lock(mm_struct_pointer);
    vmas_currently_locked = true;
    
    // Begin iteration
    struct vm_area_struct* vma;
    VMA_ITERATOR(vmi, mm_struct_pointer, 0);
    for_each_vma(vmi, vma)
    {
        unsigned long start = vma->vm_start;
        unsigned long end   = vma->vm_end;
        unsigned long flags = vma->vm_flags;

        // Is the virtual memory area not readable?
        if(!(flags & VM_READ))
        {
            // VMA is not readable
            continue;
        }

        // Increment total size
        size_t vma_size = end-start;
        if (check_add_overflow(total_vma_size_estimate, vma_size, &total_vma_size_estimate))
        {
            // When adding, we overflowed
            pr_info("[friend]: When calculating VMA total size, overflow\n");
            is_error = true;
            goto release;
        }

        // Increment region count
        if (check_add_overflow(total_vma_count, 1, &total_vma_count))
        {
            pr_info("[friend]: When calculating total region count, overflow\n");
            is_error = true;
            goto release;
        }
    }

    // Total vma size is 0?
    if (total_vma_size_estimate == 0)
    {
        pr_info("[friend]: Total calculated vma size was 0\n");
        is_error = true;
        goto release;
    }

    #pragma endregion

    // Calcuate how much memory we need to allocate
    #pragma region Calculate size to allocate

    // Size of the header that goes at the top of the region
    size_t dump_header_size = sizeof(struct Dump_Header);

    // Size of all area dump metadata
    size_t total_area_metadata_size;
    if(check_mul_overflow(total_vma_count, sizeof(struct Area_Dump), & total_area_metadata_size))
    {
        pr_info("[friend]: When calculating VMA dump metadata total size, overflow\n");
        goto release;
    }
    
    // Add everything together
    size_t total_size_to_allocate = 0;
    if(check_add_overflow(total_size_to_allocate, dump_header_size, &total_size_to_allocate) ||
       check_add_overflow(total_size_to_allocate, total_area_metadata_size, &total_size_to_allocate) ||
       check_add_overflow(total_size_to_allocate, total_vma_size_estimate, &total_size_to_allocate))
    {
        pr_info("[friend]: When calculating total size to allocate, overflow\n");
        is_error = true;
        goto release;
    }

    #pragma endregion

    // Perform the allocation and write the header
    #pragma region Allocate memory

    // Unlock before allocating memory which might take a while
    mmap_read_unlock(mm_struct_pointer);
    vmas_currently_locked = false;
    
    // Allocate a kernel memory region that can be mapped to userspace of the desired size
    shared_buffer = vmalloc_user(total_size_to_allocate);
    if (!shared_buffer) {
        pr_info("[friend]: Failed to allocate shared buffer\n");
        is_error = true;
        goto release;
    }

    #pragma endregion
    
    // Go over the VMAs again to initialise metadata within the shared buffer
    #pragma region Iterate over VMAs second pass for metadata write
    
    // Write the header to the shared buffer
    u8* current_write_location = shared_buffer;
    struct Dump_Header* dump_header = current_write_location;
    current_write_location += sizeof(struct Dump_Header);

    // Lock the VMAs
    mmap_read_lock(mm_struct_pointer);
    vmas_currently_locked = true;

    // Begin iteration again
    size_t number_of_area_dumps_written = 0;
    vma_iter_set(&vmi, 0);
    for_each_vma(vmi, vma)
    {
        unsigned long start = vma->vm_start;
        unsigned long end   = vma->vm_end;
        unsigned long flags = vma->vm_flags;

        // Is the virtual memory area not readable?
        if(!(flags & VM_READ))
        {
            // VMA is not readable
            continue;
        }

        size_t vma_size = end-start;

        // Before we write anymore - will we write beyond the allocated buffer?
        u8* buffer_end = (u8*)shared_buffer + total_size_to_allocate;
        if(current_write_location + sizeof(struct Area_Dump) + vma_size > buffer_end)
        {
            pr_info("[friend]: VMA sizes have expanded since allocation or there are more VMAs. Overflow prevented - potential information loss.\n");
            is_error = true;
            break;
        }

        // Write target address and size to current area_dump
        struct Area_Dump* current_area_dump = current_write_location;
        current_area_dump-> target_address = start;
        current_area_dump-> area_size = vma_size;
        number_of_area_dumps_written += 1;

        // Increment by size of metadata and by size of dump_data (which we will add later)
        current_write_location += sizeof(struct Area_Dump);
        current_write_location += vma_size;
    }

    // Write to the dump header how many area headers we have written.
    // It may actually be less than total_vma_count if the number of VMAs has decreased since the allocation took place
    dump_header-> area_count = number_of_area_dumps_written;

    // Unlock the VMAs
    mmap_read_unlock(mm_struct_pointer);
    vmas_currently_locked = false;

    #pragma endregion

    // Traverse the metadata and read the target proces
    #pragma region Traverse metadata

    // Where we are currently reading from within the shared buffer
    u8* current_read_location = (u8*)shared_buffer + sizeof(struct Dump_Header);

    // Iterate over all of the area dump structs within our shared bufffer
    for(size_t vma_index = 0; vma_index < dump_header->area_count; vma_index++)
    {
        struct Area_Dump* current_area_dump = current_read_location;

        if (current_area_dump-> area_size > INT_MAX)
        {
            pr_info("[friend]: VMA too large to read\n");
            is_error = true;
            goto release;
        }

        // Read from the current target address
        int bytes_read = access_process_vm(
            task_struct_pointer,
            current_area_dump-> target_address,
            current_area_dump-> dump_data,
            current_area_dump-> area_size,
            0
        );

        // Increment our read location
        current_read_location += sizeof(struct Area_Dump);
        current_read_location += current_area_dump-> area_size;
    }

    #pragma endregion

    // Save shared allocation handle to private data and return size to user
    #pragma region Save information

    void** current_dump_handle = &(friend_context_instance-> dump_info.ma_start_address);
    size_t* current_dump_size = &(friend_context_instance->dump_info.ma_size);

    // If a handle is already present, free it
    if (*current_dump_handle)
    {
        vfree(*current_dump_handle);
        *current_dump_size = 0;
        *current_dump_handle = NULL;
    }

    // Save handle to private data
    *current_dump_handle = shared_buffer;
    *current_dump_size = total_size_to_allocate;
    
    // Clear local shared_buffer so we don't free it later on
    shared_buffer = NULL;

    // Return size to user
    struct Friend_Dump_Result friend_dump_result;
    friend_dump_result.kernelVmaSizeOutput = total_size_to_allocate;

    if(copy_to_user((void __user*)arg, &friend_dump_result, sizeof(friend_dump_result)))
    {
        pr_info("[friend]: Failed to copy allocated size back to user\n");
        is_error = true;
        goto release;
    }

    #pragma endregion

    #pragma region Release goto

    release:
    // Free PID struct
    if(pid_struct_pointer)
    {
        put_pid(pid_struct_pointer);
    }
    // Free task struct
    if(task_struct_pointer)
    {
        put_task_struct(task_struct_pointer);
    }
    // Unlock VMAs if they are currently locked
    if(vmas_currently_locked)
    {
        mmap_read_unlock(mm_struct_pointer);
    }
    // Free mm struct
    if(mm_struct_pointer)
    {
        mmput(mm_struct_pointer);
    }
    // Free shared buffer
    if(shared_buffer)
    {
        vfree(shared_buffer);
    }
    if(is_error)
    {
        return -EFAULT;
    }

    #pragma endregion

    return 0;
}

#pragma endregion