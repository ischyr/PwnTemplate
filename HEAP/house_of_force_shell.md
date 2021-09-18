# House of Force: Spawning shell via `system`


The theory is exact same as of the House of Force we went through, the only difference we see here is that we jump to the GOT table of process memory making it the heap region according to malloc. This, when we look into it, we can overwrite the entry of the GOT table to that of something we can take advantage of i.e. `system`, what I did in the following is, I overwrote the `atoll` with `printf` using the House of Force which is by overwriting the GOT table entry with the help of malloc which, if called returns the GOT pointer thinking it as a part of heap.



# Constraints

* Able to overwrite the top_chunk size field by any overflow vulnerability.
* Able to control the size of allocation.


# Steps to perform:-


### Get heap address

You need to get the heap address in order to calculate the top chunk or wilderness chunk address and the base address of heap. To get a leak, you might have to take advantage of any vulnerablilties for example, a UAF vulnerability will do the work.

### Overwrite top_chunk size to -1

This is important since this will trigget the malloc and provide you an arbitrary write primitive, hence to do this step you have to take advantage of overflow vlnerability which in turn if the chunk is being placed right before the wilderness chunk, we just do give `offse_to_top_chunk + packed(-1)` which will overwrite the top_chunk size.

### Top chunk/wilderness offset

To get the offset of the wilderness chunk, we do"-

```r
(gdb) x/20wx &main_arena

Get the heap addres

Subtract it from the base address
```

### Arbitrary write to a location

To write to a specific location, you have to force malloc to shift the wilderness chunk to that of address you want to overwrite. To calculate the size you have to give to malloc we do:- 

1: `x`        : The address we want to overwrite
2: `top_chunk`: The address of the wilderness 

Now, we subtract the `x` from `top_chunk` and the value we obtained can be given to malloc which will in turn force the wilderness to move to that address, then the next time we try to allocate the memory it will in return give the `x` as the pointer hence we can then write to that address. 

> Note: We know that malloc stores 8 bytes of metadata, so we need to make `x` = `original_x - 8` 

# Attachments


* Gryffindor: INCTF 2017
* CloneWars: KiPodCTF 2019
* Bamboobox: HITCON Lab 
* Cookbook: Boston Key Party CTF 2016
* Exploits has been attached to the referenced directory: `/house/house of force/`

##### References:

