# Unsorted Bin Attack


This is a very useful technqiue which allow us to overwrite a free'd chunk's `bk` pointer which has to be in unsorted bin that way, when we do allocation again of the same or more size, the heap manager will return the pointer we modified by the use of any overflow, hence doing that so we can take modify any address.


# Prerequisites


* The knowledge of the structure of a chunk, we know that from the `heap_overview.md`.
* How unsorted bin works?

Since we know the malloc chunk structure, now we need to know the workflow of the unsorted bins.


# Unsorted bins

Bins are used to store the free'd chunks which helps in recycling those chunks in a such a way that the whole process remains optimized. There are 4 types of bin:-

* Fast Bin
* Small Bin
* Large Bin
* Unsorted Bin


To be pretty honest, I'll make it long while there exists a good information and references consdering the bins in heap which could be found [here](https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/bins_chunks.html).


# Practical Example

Example from the `/poc/unsorted_bin*` are used to demonstrate the unsorted bin and the how the attack could be done.

```C
#include <stdio.h>
#include <stdlib.h>


/*

This is tested on Ubuntu 18.04.1 with GLIBC 2.27
Distributor ID:	Ubuntu
Description:	Ubuntu 18.04.4 LTS
Release:	18.04
Codename:	bionic

*/

int main()
{
	unsigned long *x, *y;
	fprintf(stderr, "Allocating a large chunk\n");
	x = malloc(0x408);
	y = malloc(0x410);
	getchar();
	fprintf(stderr, "Allcoated a chunks at: %p and %p\n", x, y);
	fprintf(stderr, "Freeing: %p and %p\n", x, y);
	getchar();
	free(x); /* This will end up in tcache bin */
	free(y); /* This will end up in unsorted bin */
	y[1] = 0x1337; /* bk field */
	y[-1] = 0xc0debabe; /* size field */
	fprintf(stderr, "Freed the pointer\n");
	fprintf(stderr, "It should be in unsorted bin\n");
	getchar();
	
	/*
	pwndbg> unsortedbin 
	unsortedbin
	all [corrupted]
	FD: 0x602660 —▸ 0x7ffff7dcfca0 (main_arena+96) ◂— 0x602660
	BK: 0x602660 ◂— 0x1337
	pwndbg> x/5xg 0x602660
	0x602660:	0x0000000000000000	0x00000000c0debabe
	0x602670:	0x00007ffff7dcfca0	0x0000000000001337
	0x602680:	0x0000000000000000
	*/

	return 0;

}
```

# Exploiting and Demomstrating via challenge


I'm using `magicheap` challenge from Hitcon LAB which can be exploited with unsorted bin attack, further can be seen following as we progressed through the source code. In the `/unsorted_bin` directory we have a `magic_heap.c`, let's analyse it:-


```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void read_input(char *buf, size_t size) {
  int ret;
  ret = read(0, buf, size);
  if (ret <= 0) {
    puts("Error");
    _exit(-1);
  }
}

char *heaparray[10];
unsigned long int magic = 0;

void menu() {
  puts("--------------------------------");
  puts("       Magic Heap Creator       ");
  puts("--------------------------------");
  puts(" 1. Create a Heap               ");
  puts(" 2. Edit a Heap                 ");
  puts(" 3. Delete a Heap               ");
  puts(" 4. Exit                        ");
  puts("--------------------------------");
  printf("Your choice :");
}

void create_heap() {
  int i;
  char buf[8];
  size_t size = 0;
  for (i = 0; i < 10; i++) {
    if (!heaparray[i]) {
      printf("Size of Heap : ");
      read(0, buf, 8);
      size = atoi(buf);
      heaparray[i] = (char *)malloc(size);
      if (!heaparray[i]) {
        puts("Allocate Error");
        exit(2);
      }
      printf("Content of heap:");
      read_input(heaparray[i], size);
      puts("SuccessFul");
      break;
    }
  }
}
```

The `create_heap` function asks for size and allocate a memory region of that given size and then take asks for the content and save it at that location, since the `read_input` is taking the input in a secure way this doesn't seems to be vulnerable to overflow, let's move on.


```C
void edit_heap() {
  int idx;
  char buf[4];
  size_t size;
  printf("Index :");
  read(0, buf, 4);
  idx = atoi(buf);
  if (idx < 0 || idx >= 10) {
    puts("Out of bound!");
    _exit(0);
  }
  if (heaparray[idx]) {
    printf("Size of Heap : ");
    read(0, buf, 8);
    size = atoi(buf);
    printf("Content of heap : ");
    read_input(heaparray[idx], size);
    puts("Done !");
  } else {
    puts("No such heap !");
  }
}
```
The `edit_heap` takes a size and then edit the content of the same index from the `heaparray` but here's the vulnerability, since we determined the size of the index in `create_heap`, it tends to be the same but if we gave a much bigger value here, we have a overflow vulnerability here. For example, if we allocated a chunk of size `10` via `create_heap`, that heap region will be of size 10 but after we use `edit_heap` then to edit that chunk, if we gave size 30, we will give 30 bytes since then size on the heap allocated for that chunk was 10 but we gave 30 it'll overwrite the next chunk.


```C
void delete_heap() {
  int idx;
  char buf[4];
  printf("Index :");
  read(0, buf, 4);
  idx = atoi(buf);
  if (idx < 0 || idx >= 10) {
    puts("Out of bound!");
    _exit(0);
  }
  if (heaparray[idx]) {
    free(heaparray[idx]);
    heaparray[idx] = NULL;
    puts("Done !");
  } else {
    puts("No such heap !");
  }
}

```

The `delete_heap` takes the index and free the of that index from that `heaparray` and NULL out it's content, hence no UAF.

```C
void l33t() { system("/bin/sh"); }

```
This function is useful hence we will use this to get shell.


```C
int main() {
  char buf[8];
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  while (1) {
    menu();
    read(0, buf, 8);
    switch (atoi(buf)) {
    case 1:
      create_heap();
      break;
    case 2:
      edit_heap();
      break;
    case 3:
      delete_heap();
      break;
    case 4:
      exit(0);
      break;
    case 4869:
      if (magic > 4869) {
        puts("Congrt !");
        l33t();
      } else
        puts("So sad !");
      break;
    default:
      puts("Invalid Choice");
      break;
    }
  }
  return 0;
}

```

This is a nice menu, we can give the a menu it has an interesting option which takes the `4869` and see if a global variable `magic` s more than `4869`, if true then it returns shell. We know our goal let's start:-