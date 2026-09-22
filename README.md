# linux-kernel-module
Through the IOCTLS, a target process can be selected by its thread group ID.
Once selected, it can be dumped to a kernel buffer that has been marked for user-space mapping and the user can subsequently mmap the buffer through another IOCTL.

Dumping is done by locking Virtual Memory Areas to scrape for metadata and then unlocking during dumping. This produces a "fuzzy" scan but is an noninvasive approach.
