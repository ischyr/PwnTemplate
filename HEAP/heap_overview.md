c# Heap

Heap is the memory region which is appended after the `bss` section with some random offset between them and hence is used to store the variables to that region by allocating the memory by using any of the LIBC function including:-

* `malloc`
* `calloc` 
* `realloc` etc.

The subsequent memory can be freed when it is not needed by using the function `free`.


In order to get the better understanding of the heap exploitation technqiues, I am writing a extensive notes that will help myself in the learning process.


# GNU C Library: Implementation of Heap

This section is tend to focus on how the GLIBC implements the heap structure and how it manages the allocation and deallocatin of the memory and how it recycles it.



The heap memory is obtained by `sbrk` address which expands the process image of the binary and hence providing us a means of use for these region. This results in expanding the process image of the binary, the heap region is added below the `bss` section with a random offset.


```r
---------------------
|    TEXT           |
---------------------
|    BSS            |
---------------------
|    HEAP           |
---------------------
|    LINKER/LIBRARY |
---------------------
```

Once the program made a region which can be then used for dynamic memory use.
When we allocate a memory, sat `malloc(0x20)` it will be alloacted from that region, this allocated region is given with the regards of `top_chunk` or `wilderness`, this is the special chunk which represents the remaining size of the heap itself, when we tend to allocate memory, the `top_chunk_size` subtracts the that amount of memory that has been requested hence updating the `top_chunk_size` and providing a pointer to that address which has to be used.


When we need more memory for usage and the default allocated size of the `top_chunk` is used, the program then requests the system to get more memory for the heap, this then again get expanded by `sbrk` syscall or `mmap`.


When we `free` a chunk, the memory region gets `free`'d and hence transferred to one of the `bins`[1], bins are linked-list type data structure which is used to keep a track of the deallocated chunks so that the heap manager can recycle this alloacted chunk. The bins could be doubly linked-lists or singly linked-list or circular linked-list depending on the `size` of the memory that has been allocated.[2]

# Arenas

Arenas are used to represent the heap memory for a specific threading, these arenas are depend on the memory is being alloacted, arenas are created for a specific threads hence providing a independent heap memory for that thread.

> There's a arena which is referred as main arena[3] which corresponds to the memory heap used by the program itself.

Allocated chunks in the same memory can be accessed in the same linear space and these are navigated by the size of the chunk itself, which is used to get the pointer of the current chunk and then summed up with the size of the current chunk which then aligned, giving the next chunk pointer.

# The Heap Structure


### `heap_info`

The foremost structure we need to learn about is `heap_info`.

```C
typedef struct _heap_info {
        mstate  ar_ptr; /* Arena for this heap. */ 
        struct _heap_info *prev;   /*  Previous  heap.  */  
        size_t    size;     /* Current size in bytes. */ 
	    char     pad[-5 * SIZE_SZ & MALLOC_ALIGN_MASK]; 
	} heap_info; 
```



* `mstate ar_ptr`: This one is used to refer to the arenas of the heap and sets a corresponding link between them.
* `struct heap_info *prev`: This includes a pointer to the previous `heap_info` structure.
* `size_ t`: Size of the heap
* `char pad[-5 * SIZE_SZ & MALLOC_ALIGN_MASK]` : This is used to pad the `heap_info` structure. 

This structure linked list based and is used to store the information about the heap itself, which helps the alogorithm to manage accordingly.


### `malloc state`

```C
struct malloc_state { 
       mutex_t  mutex;  /* Serialize access.  */ 
       int  flags;  /* Flags (formerly in max_fast).  */ 
       #if THREAD_STATS /* Statistics for locking.  Only used if THREAD_STATS is defined.  */ 
       long     stat_lock_direct, stat_lock_loop, stat_lock_wait; 
       #endif 
       mfastbinptr       fastbins[NFASTBINS]; /* Fastbins */ 
       mchunkptr         top; 
       mchunkptr         last_remainder; 
       mchunkptr         bins[NBINS * 2]; 
       unsigned int      binmap[BINMAPSIZE];  /* Bitmap of bins */ 
       struct malloc_state *next;    /* Linked list */ 
       INTERNAL_SIZE_T  system_mem; 
       INTERNAL_SIZE_T  max_system_mem; 
   }; 
```


This structure is used to keep the information of the `malloc state`, this helps the `malloc` to store the neccessary information so that it could be used to work accordingly and keep the track of the heap information and perform the allocation of the memory on behalf of it.

Following are the use of the `malloc_state`'s members:-

* `mutex_t mutex`                        : This ensure that the serialize access should be made in the heap and keeps the track of internal function calling.
* `int flags`                            : This is used to set the flag bits in order to keep the track of the struct members such as the use of fastbins or if the memory is contigous ot not.
* `mchunkptr fastbins[NFASTBINS`         : This array contains the list of the fastbins, a fastbin is a linked list which is used to store the free'd chunk and considered to be the fasted among all the other bins.  
* `mchunkptr top`                        : This chunk points to the top of the heap or wilderness, this chunk stored the size of the heap, it borders with the end of the heap such that it then can be expanded if more memory is needed.
* `mchunkptr last_remainder`             : This points to the last remainder chunk of the heap as the name say, this chunk is used to store the chunk which doesn't fit anywhere else.
* `mchunkptr bins[NBINS * 2]`            : This array contains the bins which is used to store the memory that has been free'd such that it could be recycled effectively.
* `unsigned int binmap[BINMAPSIZE]`      : This array contains the bitmap of the bins that is storing the free'd chunks.
* `struct malloc_state *next`            : This poinst to the next `malloc_state` structure.      
* `INTERNAL_SIZE_T system_mem` & `INTERNAL_SIZE_T max_system_mem`: This is used to store the size of the memory which is being used and the maximun memory it can access.


This is for now, this provides an abstraction and helps to understand more about the allocation of the memory and how it is being managed at the lower of level.

# The Memory Chunk


These chunks are used to store the userdata which we give and the metadata such that the size and the flag bits along with some other important information. To be more precise, a chunk is same for an allocated(malloc'd) region and as well as the unallocated(free'd) memory, the difference which we will see is the use of some pointers which is used to keep track of other chunks and can only be seen in free'd chunk. The structure of these chunk is explained below:-

```C
struct malloc_chunk {
	INTERNAL_SIZE_T      prev_size;
	INTERNAL_SIZE_T      size_t;
	struct malloc_chunk  *fd;
	struct malloc_chunk  *bd;
}
```


* `INTERNAL_SIZE_T prev_size`: This is used to refer to the size of the previous chunk.
* `INTERNAL_SIZE_T size`     : This is used to store the size of the current heap.
* `struct malloc_chunk  *fd` : This points to the next free chunk, only if the current chunk is free
* `struct malloc_chunk  *bd` : This poinst to the previous free chunk, only if the current chunk is free.

Although, there are two representations of the chunk which can be seen, only being the allocated chunk and the other being the free'd chunk.


The allocated chunk:-

```r
--------------------------------------------------
|            prev_size (if allocated)            |
--------------------------------------------------
|            size                          |A|M|P| 
--------------------------------------------------
|                                                |   
|                                                |
|      ======= USER DATA ========                | 
|                                                |
|                                                |
--------------------------------------------------
```

There are 3 new things, these are flags denoted by the 3 LSB bits.
* `A`: Set to 1, if the chunk is from main arena.
* `M`: Set to 1, if the chunk is mmap'd memory.
* `P`: Set to 1, if the previous chunk is in use.

The free'd chunk depicts the following the layout of chunk:-

```r
--------------------------------------------------
|           prev_size (if allocated)             |
--------------------------------------------------
|           size                           |A|M|P| 
--------------------------------------------------
|           malloc_chunk  *fd(if free)           |
--------------------------------------------------
|           malloc_chunk  *bd(if free)           |
--------------------------------------------------
|               freed data                       | 
|                                                |
|                                                |
--------------------------------------------------
```


Same as of allocated chunk, the new elements we can see:-

* `malloc_chunk *fd` : This points to the next free chunk.
* `malloc_chunk *bd` : This points to the backward free chunk.

 