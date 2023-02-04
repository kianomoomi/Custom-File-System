#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define _UTHREAD_PRIVATE

#include "disk.h"
#include "fs.h"


// Very nicely display "Function Source of error: the error message"
#define fs_error(fmt, ...) \
    fprintf(stderr, "%s: ERROR-"fmt"\n", __func__, ##__VA_ARGS__)

#define EOC 0xFFFF
#define EMPTY 0

typedef enum {
    false, true
} bool;

/* 
 * Superblock:
 * The superblock is the first block of the file system. Its internal format is:
 * Offset	Length (bytes)	Description
 * 0x00		8-				Signature (must be equal to "ECS150FS")
 * 0x08		2-				Total amount of blocks of virtual disk
 * 0x0A		2-				Root directory block index
 * 0x0C		2-				Data block start index
 * 0x0E		2				Amount of data blocks
 * 0x10		1				Number of blocks for FAT
 * 0x11		4079			Unused/Padding
 *
 */

struct superblock_t {
    char signature[8];
    uint16_t num_blocks;
    uint16_t root_dir_index;
    uint16_t data_start_index;
    uint16_t num_data_blocks;
    uint8_t num_FAT_blocks;
    uint8_t unused[4079];
    int dirty_blocks[4096];
} __attribute__((packed));


/*
 * FAT:
 * The FAT is a flat array, possibly spanning several blocks, which entries are composed of 16-bit unsigned words. 
 * There are as many entries as data *blocks in the disk.
*/

struct FAT_t {
    uint16_t words;
};


/* 
 *
 * Root Directory:
 * Offset	Length (bytes)	Description
 * 0x00		16				Filename (including NULL character)
 * 0x10		4				Size of the file (in bytes)
 * 0x14		2				Index of the first data block
 * 0x16		10				Unused/Padding
 *
 */

struct rootdirectory_t {
    char filename[FS_FILENAME_LEN];
    uint32_t file_size;
    uint16_t start_data_block;
    uint8_t unused[10];
} __attribute__((packed));


struct file_descriptor_t {
    bool is_used;
    int file_index;
    size_t offset;
    char file_name[FS_FILENAME_LEN];
};


struct superblock_t *superblock;
struct rootdirectory_t *root_dir_block;
struct FAT_t *FAT_blocks;
struct file_descriptor_t fd_table[FS_OPEN_MAX_COUNT];


bool cache_is_on = false;
int *dirty_blocks;


// private API
static bool error_free(const char *filename);

static int locate_file(const char *file_name);

static bool is_open(const char *file_name);

static bool is_important_file(const char *filename);

static int locate_avail_fd();

static int get_num_FAT_free_blocks();

static int count_num_open_dir();

static int go_to_cur_FAT_block(int cur_fat_index, int iter_amount);

static bool is_in_read_cache(int index);

static bool is_in_write_cache(int index);

static bool is_in_disk(int index);

static int bring_to_read_cache(int index);

void move_fat_i_to_j(int i, int j);

int find_dirty_block_and_clean(int index);

int fs_write_cache(int fd, void *buf, size_t count, struct rootdirectory_t *the_dir, int extra_blocks);


// Makes the file system contained in the specified virtual disk "ready to be used"
int fs_mount(const char *diskname) {

    superblock = malloc(BLOCK_SIZE);

    // open disk dd
    if (block_disk_open(diskname) < 0) {
        fs_error("failure to open virtual disk \n");
        return -1;
    }

    // initialize data onto local super block
    if (block_read(0, (void *) superblock) < 0) {
        fs_error("failure to read from block \n");
        return -1;
    }
    // check for correct signature
    if (strncmp(superblock->signature, "ECS150FS", 8) != 0) {
        fs_error("invalid disk signature \n");
        return -1;
    }
    // check for correct number of blocks on disk
    if (superblock->num_blocks != block_disk_count()) {
        fs_error("incorrect block disk count \n");
        return -1;
    }

    // initialize data onto local FAT blocks
    FAT_blocks = malloc(superblock->num_FAT_blocks * BLOCK_SIZE);
    for (int i = 0; i < superblock->num_FAT_blocks; i++) {
        // read each fat block in the disk starting at position 1
        if (block_read(i + 1, (void *) FAT_blocks + (i * BLOCK_SIZE)) < 0) {
            fs_error("failure to read from block \n");
            return -1;
        }
    }

    // initialize data onto local root directory block
    root_dir_block = malloc(sizeof(struct rootdirectory_t) * FS_FILE_MAX_COUNT);
    // read the root directory block in the disk starting after the last FAT block
    if (block_read(superblock->num_FAT_blocks + 1, (void *) root_dir_block) < 0) {
        fs_error("failure to read from block \n");
        return -1;
    }

    // initialize file descriptors
    for (int i = 0; i < FS_OPEN_MAX_COUNT; i++) {
        fd_table[i].is_used = false;
    }

    return 0;
}


// Makes sure that the virtual disk is properly closed and that all the internal data structures of the FS layer are properly cleaned.
int fs_umount(void) {

    if (!superblock) {
        fs_error("No disk available to unmount\n");
        return -1;
    }

    if (block_write(0, (void *) superblock) < 0) {
        fs_error("failure to write to block \n");
        return -1;
    }

    for (int i = 0; i < superblock->num_FAT_blocks; i++) {
        if (block_write(i + 1, (void *) FAT_blocks + (i * BLOCK_SIZE)) < 0) {
            fs_error("failure to write to block \n");
            return -1;
        }
    }

    if (block_write(superblock->num_FAT_blocks + 1, (void *) root_dir_block) < 0) {
        fs_error("failure to write to block \n");
        return -1;
    }

    free(superblock);
    free(root_dir_block);
    free(FAT_blocks);

    // reset file descriptors
    for (int i = 0; i < FS_OPEN_MAX_COUNT; i++) {
        fd_table[i].offset = 0;
        fd_table[i].is_used = false;
        fd_table[i].file_index = -1;
        memset(fd_table[i].file_name, 0, FS_FILENAME_LEN);
    }

    block_disk_close();
    return 0;
}


// Display some information about the currently mounted file system.
int fs_info(void) {

    printf("FS Info:\n");
    printf("total_blk_count=%d\n", superblock->num_blocks);
    printf("fat_blk_count=%d\n", superblock->num_FAT_blocks);
    printf("rdir_blk=%d\n", superblock->num_FAT_blocks + 1);
    printf("data_blk=%d\n", superblock->num_FAT_blocks + 2);
    printf("data_blk_count=%d\n", superblock->num_data_blocks);
    printf("fat_free_ratio=%d/%d\n", get_num_FAT_free_blocks(), superblock->num_data_blocks);
    printf("rdir_free_ratio=%d/128\n", count_num_open_dir());

    return 0;
}


/*
Create a new file:
	0. Make sure we don't duplicate files, by checking for existings.
	1. Find an empty entry in the root directory.
	2. The name needs to be set, and all other information needs to get reset.
		2.2 Intitially the size is 0 and pointer to first data block is FAT_EOC.
*/
int fs_create(const char *filename, void *buf, size_t count) {

    // perform error checking first
    if (error_free(filename) == false) {
        fs_error("error associated with filename");
        return -1;
    }

    // finds first available empty file
    int i = 0;
    for (i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if (root_dir_block[i].filename[0] == EMPTY) {

            // initialize file data
            strcpy(root_dir_block[i].filename, filename);
            root_dir_block[i].file_size = 0;
            root_dir_block[i].start_data_block = EOC;
            break;
        }
    }
    if (i == FS_FILE_MAX_COUNT)return -1;

    int fs_fd = fs_open(filename);
    if (fs_fd < 0) {
        fs_error("Cannot open file");
        return -1;
    }

    size_t written = fs_write(fs_fd, buf, count);
    if (written == -1) {
        fs_error("Cannot write file");
        return -1;
    }

    return 0;
}


/*
Remove File:
	1. Empty file entry and all its datablocks associated with file contents from FAT.
	2. Free associated data blocks
*/
int fs_delete(const char *filename) {

    if (is_important_file(filename)) {
        fs_error("file is important. can't delete it");
        return -1;
    }
    if (is_open(filename)) {
        fs_error("file currently open");
        return -1;
    }

    int file_index = locate_file(filename);
    struct rootdirectory_t *the_dir = &root_dir_block[file_index];
    int frst_dta_blk_i = the_dir->start_data_block;

    char bounce_buff[BLOCK_SIZE];
    while (frst_dta_blk_i != EOC) {
        block_write(frst_dta_blk_i + superblock->data_start_index, (void *) bounce_buff); //free data block
        uint16_t tmp = FAT_blocks[frst_dta_blk_i].words;
        FAT_blocks[frst_dta_blk_i].words = EMPTY;
        frst_dta_blk_i = tmp;
    }

    // reset file to blank slate
    memset(the_dir->filename, 0, FS_FILENAME_LEN);
    the_dir->file_size = 0;

    return 0;
}


int fs_ls(void) {

    printf("FS Ls:\n");
    // finds first available file block in root dir
    for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if (root_dir_block[i].filename[0] != 0x00) {
            printf("file: %s, size: %d, ", root_dir_block[i].filename, root_dir_block[i].file_size);
            printf("data_blk: %d\n", root_dir_block[i].start_data_block);
        }
    }

    return 0;
}


/*
Open and return FD:
	1. Find the file
	2. Find an available file descriptor
		2.1 Mark the particular descriptor in_use, and remaining other properties
			2.1.1 Set offset or current reading position to 0
		2.2 Increment number of file scriptors to of requested file object
	3. Return file descriptor index, or other wise -1 on failure
*/
int fs_open(const char *filename) {

    int file_index = locate_file(filename);
    if (file_index == -1) {
        fs_error("file @[%s] doesnt exist\n", filename);
        return -1;
    }

    int fd = locate_avail_fd();
    if (fd == -1) {
        fs_error("max file descriptors already allocated\n");
        return -1;
    }

    fd_table[fd].is_used = true;
    fd_table[fd].file_index = file_index;
    fd_table[fd].offset = 0;

    strcpy(fd_table[fd].file_name, filename);

    return fd;
}


/*
Close FD object:
	1. Check that it is a valid FD
	2. Locate file descriptor object, given its index
	3. Locate its the associated filename of the fd and decrement its fd
	4. Mark FD as available for use
*/
int fs_close(int fd) {

    if (fd >= FS_OPEN_MAX_COUNT || fd < 0 || fd_table[fd].is_used == 0) {
        fs_error("invalid file descriptor supplied \n");
        return -1;
    }

    struct file_descriptor_t *fd_obj = &fd_table[fd];

    int file_index = locate_file(fd_obj->file_name);
    if (file_index == -1) {
        fs_error("file @[%s] doesnt exist\n", fd_obj->file_name);
        return -1;
    }

    fd_obj->is_used = false;

    return 0;
}


/*
Return the size of the file corresponding to the specified file descriptor.
	1. Error check
	2. Locate file from root dir from fd
	3. Return file size from appropriate root dir 
*/
int fs_stat(int fd) {
    if (fd >= FS_OPEN_MAX_COUNT || fd < 0 || fd_table[fd].is_used == false) {
        fs_error("invalid file descriptor supplied \n");
        return -1;
    }

    struct file_descriptor_t *fd_obj = &fd_table[fd];

    int file_index = locate_file(fd_obj->file_name);
    if (file_index == -1) {
        fs_error("file @[%s] doesnt exist\n", fd_obj->file_name);
        return -1;
    }

    return root_dir_block[file_index].file_size;
}

/*
Move supplied fd to supplied offset
	1. Make sure the offset is valid: cannot be less than zero, nor can 
	   it exceed the size of the file itself.
	2. Error check 
	3. Update offset of fd
*/
int fs_lseek(int fd, size_t offset) {
    struct file_descriptor_t *fd_obj = &fd_table[fd];
    int file_index = locate_file(fd_obj->file_name);
    if (file_index == -1) {
        fs_error("file @[%s] doesnt exist\n", fd_obj->file_name);
        return -1;
    }

    int32_t file_size = fs_stat(fd);

    if (offset < 0 || offset > file_size) {
        fs_error("file @[%s] is out of bounds \n", fd_obj->file_name);
        return -1;
    } else if (fd_table[fd].is_used == false) {
        fs_error("invalid file descriptor [%s] \n", fd_obj->file_name);
        return -1;
    }

    fd_table[fd].offset = offset;
    return 0;
}

/*
 Find fs_fd from fd_table using filename.
 return -1 if it doesn't exist.
 */
int find_fs_fd(char *filename) {
    for (int i = 0; i < FS_OPEN_MAX_COUNT; i++) {
        if (!strcmp(filename, fd_table[i].file_name)) {
            return i;
        }
    }
    return -1;
}

/*
 process for moving FAT_block[i] to FAT_block[j]
 */
void move_fat_i_to_j(int i, int j) {
    FAT_blocks[j].words = FAT_blocks[i].words;
    FAT_blocks[i].words = EMPTY;
    int s;
    for (s = 0; s < superblock->num_FAT_blocks; s++) {
        if (FAT_blocks[s].words == i) {
            FAT_blocks[s].words = j;
            break;
        }
    }
    if (s == superblock->num_FAT_blocks) {
        for (int l = 0; l < FS_FILE_MAX_COUNT; l++) {
            if(root_dir_block[l].start_data_block==i){
                root_dir_block[l].start_data_block=j;
                break;
            }
        }
    }
}

/*
Find one dirty block in cache and write it on index data block in disk
 */
int find_dirty_block_and_clean(int index) {
    int *dirtys = malloc((1 + superblock->num_data_blocks / 3) * sizeof(int));
    int num_dirtys = 0;
    int i;
    for (i = superblock->num_data_blocks / 3; i < 2 * superblock->num_data_blocks / 3; i++) {
        if (superblock->dirty_blocks[i] == 1) {
            dirtys[num_dirtys] = i;
            num_dirtys++;
        }
    }

    time_t t;
    srand((unsigned) time(&t));
    int selected_index = dirtys[rand() % num_dirtys];
    char bounce_buff[BLOCK_SIZE];
    block_read(selected_index + superblock->data_start_index, bounce_buff);
    block_write(index + superblock->data_start_index, (void *) bounce_buff);
    move_fat_i_to_j(selected_index, index);
    superblock->dirty_blocks[selected_index]=0;
    return selected_index;
}

/*
 Find if the index is in write cache or not.
 between 1/3->2/3
 */
bool is_in_write_cache(int index) {
    int num_data_blocks = superblock->num_data_blocks;
    if (index >= num_data_blocks / 3 && index < 2 * num_data_blocks / 3) {
        return true;
    }
    return false;
}
/*
 Find if the index is in read cache or not.
 between 0->1/3
 */
bool is_in_read_cache(int index) {
    int num_data_blocks = superblock->num_data_blocks;
    if (index >= 0 / 3 && index < num_data_blocks / 3) {
        return true;
    }
    return false;
}
/*
 Find if the index is in data disk.
 between 2/3->1
 */
bool is_in_disk(int index) {
    return !(is_in_write_cache(index)|| is_in_read_cache(index));
}

int fs_write_cache(int fd, void *buf, size_t count, struct rootdirectory_t *the_dir, int extra_blocks) {

    int offset = fd_table[fd].offset;

    int num_blocks = ((count + (offset % BLOCK_SIZE)) / BLOCK_SIZE) + 1;
    int cur_block = offset / BLOCK_SIZE;
    int curr_fat_index = the_dir->start_data_block;

    char *write_buf = (char *) buf;
    char bounce_buff[BLOCK_SIZE];

    int amount_to_write = count;
    int left_shift;
    int total_byte_written = 0;
    int location = offset % BLOCK_SIZE;


    // get to starting block
    curr_fat_index = go_to_cur_FAT_block(curr_fat_index, cur_block);

    int available_data_blocks = 0;
    int fat_block_indices[extra_blocks];
    int disk_data_blocks = 0;

    // locate and store indices of the free blocks
    // to avoid overwriting other file contents
    for (int j = (superblock->num_data_blocks) / 3; j < superblock->num_data_blocks; j++) {
        if (FAT_blocks[j].words == 0) {
            fat_block_indices[available_data_blocks] = j;
            available_data_blocks++;
            if (!is_in_write_cache(j)) {
                disk_data_blocks += 1;
            }
        }
        if (available_data_blocks == extra_blocks)
            break;
    }

    // for the case where there are no more available data blocks on disk
    num_blocks = available_data_blocks;

//     extending the fat table for a file when it already
//     contains data
    if(the_dir->start_data_block == EOC) {
        curr_fat_index = fat_block_indices[0];
        the_dir->start_data_block = curr_fat_index;
    }
//    else {
//        int frst_dta_blk_i = the_dir->start_data_block;
//        while(frst_dta_blk_i != EOC){
//            frst_dta_blk_i = FAT_blocks[frst_dta_blk_i].words;
//        }
//        for(int k =0; k < num_blocks; k++){
//            FAT_blocks[frst_dta_blk_i].words = fat_block_indices[k];
//            frst_dta_blk_i = FAT_blocks[frst_dta_blk_i].words;
//        }
//        FAT_blocks[frst_dta_blk_i].words = EOC;
//    }

    num_blocks = ((count + (offset % BLOCK_SIZE)) / BLOCK_SIZE) + 1;

    // write to the disk as much as we can (don't overload the disk)
//    int num_free = get_num_FAT_free_blocks();
//    if (num_blocks > num_free) {
//        num_blocks = num_free;
//    }

    // write on cache blocks
    for (int i = 0; i < num_blocks - disk_data_blocks; i++) {
        if (location + amount_to_write > BLOCK_SIZE) {
            left_shift = BLOCK_SIZE - location;
        } else {
            left_shift = amount_to_write;
        }

//        if (i == 0) block_read(curr_fat_index + superblock->data_start_index, bounce_buff); //correct offsets
        memcpy(bounce_buff + location, write_buf, left_shift);
        block_write(curr_fat_index + superblock->data_start_index, (void *) bounce_buff);
        superblock->dirty_blocks[curr_fat_index]=1;

        // position array to left block
        total_byte_written += left_shift;
        write_buf += left_shift;

        location = 0;
        amount_to_write -= left_shift;

        // updating the final FAT entry values
        if (i < num_blocks - 1) {
            FAT_blocks[curr_fat_index].words = fat_block_indices[i];
            curr_fat_index = FAT_blocks[curr_fat_index].words;
        } else {
            FAT_blocks[curr_fat_index].words = EOC;
            curr_fat_index = FAT_blocks[curr_fat_index].words;
        }
    }
    //replace with random strategy
    for (int i = num_blocks - disk_data_blocks; i < num_blocks; i++) {
        if (location + amount_to_write > BLOCK_SIZE) {
            left_shift = BLOCK_SIZE - location;
        } else {
            left_shift = amount_to_write;
        }

        if (i == 0) block_read(curr_fat_index + superblock->data_start_index, bounce_buff); //correct offsets
        memcpy(bounce_buff + location, write_buf, left_shift);
        block_write(curr_fat_index + superblock->data_start_index, (void *) bounce_buff);
        superblock->dirty_blocks[curr_fat_index]=1;


        // position array to left block
        total_byte_written += left_shift;
        write_buf += left_shift;

        location = 0;
        amount_to_write -= left_shift;

        // updating the final FAT entry values
        if (i < num_blocks - 1) {
            int dirty_block_index = find_dirty_block_and_clean(fat_block_indices[i]);
//            int dirty_block_index = fat_block_indices[i];
            FAT_blocks[curr_fat_index].words = dirty_block_index;
            curr_fat_index = dirty_block_index;
        } else {
            FAT_blocks[curr_fat_index].words = EOC;
            curr_fat_index = FAT_blocks[curr_fat_index].words;
        }
    }

    // update filesize accordingly to how much was written
    if (offset + total_byte_written > the_dir->file_size) {
        the_dir->file_size = offset + total_byte_written;
    }

    fd_table[fd].offset += total_byte_written;
    return total_byte_written;
}

// Write to a file:
int fs_write(int fd, void *buf, size_t count) {
    // Error Checking
    if (count <= 0) {
        fs_error("request nbytes amount is trivial");
        return -1;
    } else if (fd <= -1 || fd >= FS_OPEN_MAX_COUNT) {
        fs_error("invalid file descriptor [%d] \n", fd);
        return -1;
    } else if (get_num_FAT_free_blocks() == EMPTY) {
        fs_error("no free entries to write to");
        return -1;
    } else if (fd_table[fd].is_used == false) {
        fs_error("file descriptor is not open");
        return -1;
    }

    // find relative information about file
    char *file_name = fd_table[fd].file_name;
    if (is_important_file(file_name)) {
        fs_error("file is important. can't write");
        return -1;
    }

    int file_index = locate_file(file_name);
    int offset = fd_table[fd].offset;

    struct rootdirectory_t *the_dir = &root_dir_block[file_index];

    int num_blocks = ((count + (offset % BLOCK_SIZE)) / BLOCK_SIZE) + 1;
    int cur_block = offset / BLOCK_SIZE;
    int curr_fat_index = the_dir->start_data_block;

    // find the extra blocks required for writing count
    // amount of bytes from buffer
    int extra_blocks;
    if (the_dir->file_size != 0) {
        int file_width = the_dir->file_size / BLOCK_SIZE;
        int block_difference = offset + num_blocks * BLOCK_SIZE;
        extra_blocks = (block_difference / BLOCK_SIZE) - 1;
        extra_blocks = extra_blocks - file_width;
    } else extra_blocks = num_blocks;

    if (cache_is_on) {
        return fs_write_cache(fd, buf, count, the_dir, extra_blocks);
    }

    // set up information for iterating through blocks
    char *write_buf = (char *) buf;
    char bounce_buff[BLOCK_SIZE];

    int amount_to_write = count;
    int left_shift;
    int total_byte_written = 0;
    int location = offset % BLOCK_SIZE;


    // get to starting block
    curr_fat_index = go_to_cur_FAT_block(curr_fat_index, cur_block);

    int available_data_blocks = 0;
    int fat_block_indices[extra_blocks];

    // locate and store indices of the free blocks
    // to avoid overwriting other file contents
    for (int j = 0; j < superblock->num_data_blocks; j++) {
        if (FAT_blocks[j].words == 0) {
            fat_block_indices[available_data_blocks] = j;
            available_data_blocks++;
        }
        if (available_data_blocks == extra_blocks)
            break;
    }

    // for the case where there are no more availabe data blocks on disk
    num_blocks = available_data_blocks;

    // extending the fat table for a file when it already
    // contains data
    if (the_dir->start_data_block == EOC) {
        curr_fat_index = fat_block_indices[0];
        the_dir->start_data_block = curr_fat_index;
    } else {
        int frst_dta_blk_i = the_dir->start_data_block;
        while (frst_dta_blk_i != EOC) {
            frst_dta_blk_i = FAT_blocks[frst_dta_blk_i].words;
        }
        for (int k = 0; k < num_blocks; k++) {
            FAT_blocks[frst_dta_blk_i].words = fat_block_indices[k];
            frst_dta_blk_i = FAT_blocks[frst_dta_blk_i].words;
        }
        FAT_blocks[frst_dta_blk_i].words = EOC;
    }

    num_blocks = ((count + (offset % BLOCK_SIZE)) / BLOCK_SIZE) + 1;

    // write to the disk as much as we can (don't overload the disk)
    int num_free = get_num_FAT_free_blocks();
    if (num_blocks > num_free) {
        num_blocks = num_free;
    }

    // main iteration loop for writing block per block
    for (int i = 0; i < num_blocks; i++) {
        if (location + amount_to_write > BLOCK_SIZE) {
            left_shift = BLOCK_SIZE - location;
        } else {
            left_shift = amount_to_write;
        }

        if (i == 0) block_read(curr_fat_index + superblock->data_start_index, bounce_buff); //correct offsets
        memcpy(bounce_buff + location, write_buf, left_shift);
        block_write(curr_fat_index + superblock->data_start_index, (void *) bounce_buff);

        // position array to left block
        total_byte_written += left_shift;
        write_buf += left_shift;

        location = 0;
        amount_to_write -= left_shift;

        // updating the final FAT entry values
        if (i < num_blocks - 1) {
            FAT_blocks[curr_fat_index].words = fat_block_indices[i + 1];
            curr_fat_index = FAT_blocks[curr_fat_index].words;
        } else {
            FAT_blocks[curr_fat_index].words = EOC;
            curr_fat_index = FAT_blocks[curr_fat_index].words;
        }
    }

    // update filesize accordingly to how much was written
    if (offset + total_byte_written > the_dir->file_size) {
        the_dir->file_size = offset + total_byte_written;
    }

    fd_table[fd].offset += total_byte_written;
    return total_byte_written;
}

/*
 * Swap Fat_table array of index i and j
 */
void swap_fat_i_and_j(int i, int j) {
    int s;
    for (s = 0; s < superblock->num_FAT_blocks; s++) {
        if (FAT_blocks[s].words == i) {
            FAT_blocks[s].words = j;
            break;
        }
    }
    int l_temp=-1;
    if (s == superblock->num_FAT_blocks) {
        for (int l = 0; l < FS_FILE_MAX_COUNT; l++) {
            if(root_dir_block[l].start_data_block==i){
                l_temp=l;
                root_dir_block[l].start_data_block=j;
                break;
            }
        }
    }
    int l;
    for (l = 0; l < superblock->num_FAT_blocks; l++) {
        if(l==s)continue;
        if (FAT_blocks[s].words == j) {
            FAT_blocks[s].words = i;
            break;
        }
    }
    if (l == superblock->num_FAT_blocks) {
        for (int k = 0; k < FS_FILE_MAX_COUNT; k++) {
            if(k==l_temp)continue;
            if(root_dir_block[k].start_data_block==j){
                root_dir_block[k].start_data_block=i;
                break;
            }
        }
    }
}


/*
 * Bring index from disk to one cache index block and return its index in read cache.
 * Should change FAT_block array too.
 */
int bring_to_read_cache(int index){
    int available_data_blocks_index = -1;

    for (int j = 0; j < superblock->num_data_blocks/3; j++) {
        if (FAT_blocks[j].words == 0) {
            available_data_blocks_index=j;
            break;
        }
    }
    if(available_data_blocks_index==-1){
        time_t t;
        srand((unsigned) time(&t));
        int selected_index = rand() % (superblock->num_data_blocks/3);
        char bounce_buff0[BLOCK_SIZE];
        block_read(selected_index + superblock->data_start_index, bounce_buff0);
        char bounce_buff1[BLOCK_SIZE];
        block_read(index + superblock->data_start_index, bounce_buff1);

        block_write(index + superblock->data_start_index, (void *) bounce_buff0);
        block_write(selected_index + superblock->data_start_index, (void *) bounce_buff1);
        swap_fat_i_and_j(selected_index, index);
        return selected_index;
    } else{
        char bounce_buff[BLOCK_SIZE];
        block_read(index + superblock->data_start_index, bounce_buff);
        block_write(available_data_blocks_index + superblock->data_start_index, (void *) bounce_buff);
        move_fat_i_to_j(index, available_data_blocks_index);
        return available_data_blocks_index;
    }
}

/*
Read a File:
	1. Error check that the amount to be read is > 0, and that
	   the file descriptor is valid.
*/
int fs_read(int fd, void *buf, size_t count) {

    // error check
    if (fd_table[fd].is_used == false ||
        fd >= FS_OPEN_MAX_COUNT) {
        fs_error("invalid file descriptor [%d]", fd);
        return -1;
    } else if (count <= 0) {
        fs_error("request nbyte amount is trivial");
        return -1;
    }

    // gather nessessary information
    char *file_name = fd_table[fd].file_name;
    int file_index = locate_file(file_name);
    size_t offset = fd_table[fd].offset;

    struct rootdirectory_t *the_dir = &root_dir_block[file_index];

//
//    if (cache_is_on) {
//        return fs_read_cache(fd, buf, count, the_dir, offset);
//    }


    // check if offset of file exceeds the file_size
    int amount_to_read = 0;
    if (offset + count > the_dir->file_size)
        amount_to_read = abs(the_dir->file_size - offset);
    else amount_to_read = count;

    char *read_buf = (char *) buf;
    int16_t FAT_iter = the_dir->start_data_block;
    size_t num_blocks = (amount_to_read / BLOCK_SIZE) + 1;

    // block level
    int cur_block = offset / BLOCK_SIZE;

    // byte level
    int location = offset % BLOCK_SIZE;
    char bounce_buff[BLOCK_SIZE];

    // go to correct current block in fat entry
    FAT_iter = go_to_cur_FAT_block(FAT_iter, cur_block);

    // read through the number of blocks it contains
    int left_shift = 0;
    int total_bytes_read = 0;
    for (int i = 0; i < num_blocks; i++) {
        if (location + amount_to_read > BLOCK_SIZE) {
            left_shift = BLOCK_SIZE - location;
        } else {
            left_shift = amount_to_read;
        }

        if(cache_is_on && is_in_disk(FAT_iter)) {
            FAT_iter = bring_to_read_cache(FAT_iter);
        }
        // read file contents
        block_read(FAT_iter + superblock->data_start_index, (void *) bounce_buff);
        memcpy(read_buf, bounce_buff + location, left_shift);

        // position array to left block
        total_bytes_read += left_shift;
        read_buf += left_shift;

        // next block starts at the top
        location = 0;

        // next
        FAT_iter = FAT_blocks[FAT_iter].words;

        // reduce the amount to read by the amount that was read
        amount_to_read -= left_shift;
    }

    fd_table[fd].offset += total_bytes_read;
    return total_bytes_read;
}


/*
Locate Existing File
	1. Return the position of first filename that matches the search,
	   and is in use (contains data).
*/
static int locate_file(const char *file_name) {
    int i;
    for (i = 0; i < FS_FILE_MAX_COUNT; i++)
        if (strncmp(root_dir_block[i].filename, file_name, FS_FILENAME_LEN) == 0 &&
            root_dir_block[i].filename != EMPTY)
            return i;
    return -1;
}


static int locate_avail_fd() {
    int i;
    for (i = 0; i < FS_OPEN_MAX_COUNT; i++)
        if (fd_table[i].is_used == false)
            return i;
    return -1;
}


/*
Perform Error Checking 
	1. Check if file length>16
	2. Check if file already exists 
    3. Check if root directory has max number of files 
*/
static bool error_free(const char *filename) {

    // get size
    int size = strlen(filename);
    if (size > FS_FILENAME_LEN) {
        fs_error("File name is longer than FS_FILE_MAX_COUNT\n");
        return false;
    }

    // check if file already exists
    int same_char = 0;
    int files_in_rootdir = 0;
    for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        for (int j = 0; j < size; j++) {
            if (root_dir_block[i].filename[j] == filename[j])
                same_char++;
        }
        if (root_dir_block[i].filename[0] != EMPTY)
            files_in_rootdir++;
    }
    // File already exists
    if (same_char == size) {
        fs_error("file @[%s] already exists\n", filename);
        return false;
    }


    // if there are 128 files in rootdirectory
    if (files_in_rootdir == FS_FILE_MAX_COUNT) {
        fs_error("All files in rootdirectory are taken\n");
        return false;
    }

    return true;
}


/*
Is the file open?
	1. A file is open if...
		a) The file exists in the root directory
		b) Its cooresponding file descriptor is active
*/
static bool is_open(const char *filename) {
    int file_index = locate_file(filename);

    if (file_index == -1) {
        fs_error("file @[%s] doesnt exist\n", filename);
        return true;
    }

    struct rootdirectory_t *the_dir = &root_dir_block[file_index];
    for (int i = 0; i < FS_OPEN_MAX_COUNT; i++) {
        if (strncmp(the_dir->filename, fd_table[i].file_name, FS_FILENAME_LEN) == 0
            && fd_table[i].is_used) {
            fs_error("cannot remove file @[%s] as it is currently open\n", filename);
            return true;
        }
    }

    return false;
}

/*
Is the file important?
	1. A file is important if it started with 'lock'
*/
static bool is_important_file(const char *filename) {
    char important_file_tpl[4];
    important_file_tpl[0] = 'l';
    important_file_tpl[1] = 'o';
    important_file_tpl[2] = 'c';
    important_file_tpl[3] = 'k';
    for (int i = 0; i < 4; i++) {
        if (filename[i] != important_file_tpl[i]) {
            return false;
        }
    }
    return true;
}

// helper: info
static int get_num_FAT_free_blocks() {
    int count = 0;
    for (int i = 1; i < superblock->num_data_blocks; i++) {
        if (FAT_blocks[i].words == EMPTY) count++;
    }
    return count;
}


// helper: info
static int count_num_open_dir() {

    int i, count = 0;
    for (i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if (root_dir_block[i].filename[0] == EMPTY)
            count++;
    }
    return count;
}


// helper: read and write 
static int go_to_cur_FAT_block(int cur_fat_index, int iter_amount) {
    for (int i = 0; i < iter_amount; i++) {
        if (cur_fat_index == EOC) {
            fs_error("attempted to exceed end of file chain");
            return -1;
        }
        cur_fat_index = FAT_blocks[cur_fat_index].words;
    }
    return cur_fat_index;
}

