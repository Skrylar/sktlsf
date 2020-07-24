import math, options

const
    FreeHeaderFieldCount = 2

type
    PoolHeader = object
        fli: int
        sli: int
        minimum_block: int
        fla: uint32
        size: uint
        freemem: uint

    BlockHeader = object of RootObj
        # NB: allocations are always aligned to four byte boundaries,
        # so the lowest two bits are stolen for metadata
        aleph: uint
        previous_physical_block: ptr BlockHeader
        # don't write to these two if the header is in use
        next_free, prev_free: ptr BlockHeader

const
    BusyBit = 1
    BusyMask = uint.high xor BusyBit

    LastInPoolBit = BusyBit + 1
    LastInPoolMask = uint.high xor LastInPoolBit

    SizeMask = (uint.high xor BusyBit) xor LastInPoolBit
    SizeMask2 = SizeMask xor typeof(SizeMask).high

proc last_in_pool(header: BlockHeader): bool =
    return (header.aleph and LastInPoolBit) != 0

proc `last_in_pool=`(header: var BlockHeader; flag: bool) =
    var z = header.aleph and LastInPoolMask
    if flag:
        z += LastInPoolBit
    header.aleph = z

proc busy(header: BlockHeader): bool =
    return (header.aleph and BusyBit) != 0

proc `busy=`(header: var BlockHeader; flag: bool) =
    var z = header.aleph and BusyMask
    if flag:
        z += BusyBit
    header.aleph = z

proc size(header: BlockHeader): uint =
    return header.aleph and SizeMask

proc `size=`(header: var BlockHeader; size: uint) =
    header.aleph = (header.aleph and SizeMask2) + (size and SizeMask)

proc second_level_count(sli: uint): int =
    return ceil(pow(2, sli.float)).int

proc calculate_sli_strip_size(sli: int): int =
    return (second_level_count(sli.uint) * pointer.sizeof) + uint32.sizeof

proc calculate_sli_size(sli: int): int =
    return calculate_sli_strip_size(sli) * 32

# XXX counts number of zero bits from MSB down, but is gcc intrinsic
proc clz(x: cuint): cuint {.importc: "__builtin_clz".}
proc ctz(x: cuint): cuint {.importc: "__builtin_ctz".}

proc build_mask(bits: cuint): cuint =
    result = 0
    for i in 0..<bits:
        result += (1.cuint shl i.cuint)

proc mapping(size, sli: cuint): tuple[f, s: cuint] =
    var fh = clz(size.cuint)+1
    var f = (cuint.sizeof*8)-fh
    var s = size and (build_mask(sli) shl (f - sli))
    s = s shr (f - sli)
    return (f - 1, s)

proc index(buffer: ptr PoolHeader; header: ptr BlockHeader) =
    assert buffer != nil
    assert header != nil
    assert header[].size != 0
    let sli_strip = calculate_sli_strip_size(buffer.sli)

    # insert entry in to first level index
    let fs = mapping(header[].size.cuint, buffer.sli.cuint)
    echo(header[])
    echo(fs)
    buffer.fla = buffer.fla or (1.uint32 shl fs.f.uint32)

    # insert entry in to second level index
    let bop = cast[int](buffer) + PoolHeader.sizeof + (fs.f.int * sli_strip.int)
    var mask = cast[ptr uint32](bop)
    mask[] = mask[] or (1'u32 shl fs.s.uint32)

    # insert pointer in to second level slot
    var unmasked = cast[ptr ptr BlockHeader](cast[uint](mask) + uint32.sizeof.uint + (pointer.sizeof.uint * fs.s))
    if unmasked[] != nil:
        unmasked[].prev_free = header
        header.next_free = unmasked[]

    unmasked[] = header

proc unindex(buffer: ptr PoolHeader; header: ptr BlockHeader) =
    assert buffer != nil
    assert header != nil

    let sli_strip = calculate_sli_strip_size(buffer.sli)
    let sli_size = calculate_sli_size(buffer.sli)

    let fs = mapping(header[].size.cuint, buffer.sli.cuint)
    var mask = cast[ptr uint32](cast[uint](buffer) + PoolHeader.sizeof.uint + (fs.f.uint * sli_strip.uint))
    var unmasked = cast[ptr ptr BlockHeader](cast[uint](mask) + uint32.sizeof.uint + (pointer.sizeof.uint * fs.s.uint))

    # cut block from tree
    if unmasked[] == header:
        unmasked[] = header.next_free

    if unmasked[] == nil:
        # unmark this second level as open
        mask[] -= 1'u32 shl fs.s.uint32
        # and possibly unmark at first level
        if mask[] == 0:
            buffer.fla -= (1'u32 shl fs.f.uint32)
    
    if header.prev_free != nil:
        header.prev_free.next_free = header.next_free
    if header.next_free != nil:
        header.next_free.prev_free = header.prev_free

proc initialize_pool*(buffer: pointer; buffer_size: cuint; sli: int = 4) =
    if sli notin 1..32:
        raise newException(RangeError, "Second Level Indices must be in range [1, 32]")
    # TODO flail if sli is also not a power of two

    let sli_size = calculate_sli_size(sli)

    let minimum_pool_size = PoolHeader.sizeof +
        BlockHeader.sizeof +
        sli_size

    if buffer_size < minimum_pool_size.cuint:
        raise newException(ValueError, "Cannot create TLSF pool this small")

    let data_block = PoolHeader.sizeof + sli_size
    let data_block_at = cast[int](buffer) + data_block

    # fill out header
    var header = cast[ptr PoolHeader](buffer)
    header.fli = min(log2(buffer_size.float), 31).int
    header.sli = sli
    header.minimum_block = BlockHeader.sizeof
    header.fla = 0
    header.freemem = buffer_size - (FreeHeaderFieldCount * pointer.sizeof)
    header.size = buffer_size

    # zero out second level index
    zeroMem(cast[pointer](cast[int](buffer) + PoolHeader.sizeof), sli_size)

    # fill out initial block
    var entry = cast[ptr BlockHeader](data_block_at)
    entry.aleph = 0
    entry[].size = (buffer_size.int - data_block).uint
    entry.previous_physical_block = nil
    entry.next_free = nil
    entry.prev_free = nil

    index(header, entry)

proc destroy_pool*(buffer: pointer) =
    var header = cast[ptr PoolHeader](buffer)
    header.fla = 0

proc release*(buffer: pointer; blocc: pointer) =
    var poolheader = cast[ptr PoolHeader](buffer)
    assert cast[uint](blocc) > FreeHeaderFieldCount * pointer.sizeof
    var header = cast[ptr BlockHeader](cast[uint](blocc) - (FreeHeaderFieldCount * pointer.sizeof))

    let sli_strip = calculate_sli_strip_size(poolheader.sli)
    let sli_size = calculate_sli_size(poolheader.sli)

    # first, inject the new block in to our free table
    header[].busy = false
    index(poolheader, header)

    # walk forward in physical blocks to find the rightmost block to start
    # coalescence from
    block forward_walk:
        var walker = cast[uint](header) + header[].size
        let e = (cast[uint](poolheader.size) + cast[uint](buffer))
        while walker < e:
            let prospect = cast[ptr BlockHeader](walker)
            if prospect[].busy == false:
                header = prospect
                walker += header[].size
            else:
                break

    # now walk backwards through blocks, unindexing and merging free ones
    unindex(poolheader, header)
    while true:
        var prev = header.previous_physical_block
        if prev == nil: break
        if prev[].busy == true: break

        unindex(poolheader, prev)

        prev[].size = prev[].size + header[].size
        header = prev
    
    # TODO update previous physical block on the block that comes after us
    index(poolheader, header)

proc claim*(buffer: pointer; size: cuint): pointer =
    var header = cast[ptr PoolHeader](buffer)
    assert header.minimum_block >= BlockHeader.sizeof
    var fs = mapping(size, header.sli.cuint)

    # no buckets at top level so we obviously can't do
    if header.fla == 0: return nil

    let sli_strip = calculate_sli_strip_size(header.sli)
    let sli_size = calculate_sli_size(header.sli)

    for top in fs.f..31:
        let bip = 1 shl top
        if (header.fla and bip.uint32) == 0: continue
        # unpack the bit mask
        let bop = cast[int](buffer) + PoolHeader.sizeof + (sli_strip * top.int)
        var mask = cast[ptr uint32](bop)
        if mask[] == 0: continue
        for second in fs.s..31:
            let z = 1'u shl second
            if (mask[] and z) == 0: continue
            var unmasked = cast[ptr pointer](cast[uint](mask) + uint32.sizeof.uint + (pointer.sizeof.uint * second))
            if unmasked[] == nil: continue
            var blocc = cast[ptr BlockHeader](cast[pointer](unmasked[]))
            blocc[].busy = true

            # make sure we are grabbing sizes that are multiples of four
            var grabass = size + (FreeHeaderFieldCount * pointer.sizeof)
            if grabass < header.minimum_block.uint: grabass = header.minimum_block.cuint
            var offset = grabass mod 4
            grabass += offset

            # cut block from tree
            unmasked[] = blocc.next_free
            if unmasked[] == nil:
                # unmark this second level as open
                mask[] -= z.uint32
                # and possibly unmark at first level
                if mask[] == 0:
                    header.fla -= (1'u32 shl top.uint32)

            # only split if the newly created block would not be too small
            let bloccsize = blocc[].size
            if (grabass + header.minimum_block.uint) <= bloccsize:
                var xptr = cast[uint](blocc)
                xptr += (pointer.sizeof * 2) # step over control header
                xptr += grabass # step over allocated region
                var blocc2 = cast[ptr BlockHeader](xptr)
                blocc2.aleph = 0
                blocc2[].size = bloccsize - grabass
                blocc2.previous_physical_block = blocc
                blocc2.prev_free = blocc.prev_free
                blocc2.next_free = blocc.next_free
                if blocc.next_free != nil:
                    blocc.next_free.prev_free = blocc2
                blocc[].size = grabass
                index(cast[ptr PoolHeader](buffer), blocc2)
            else:
                if blocc[].next_free != nil:
                    if blocc[].prev_free != nil:
                        blocc[].prev_free.next_free = blocc[].next_free
                        blocc[].next_free.prev_free = blocc[].prev_free
                    else:
                        blocc[].next_free.prev_free = nil
            
            # you don't need to change blocc's size
            # i thought you did but its already the size of the whole block
            # and if it was too small we couldn't split it anyway

            return cast[pointer](cast[uint](blocc) + (pointer.sizeof * FreeHeaderFieldCount))

var buffer = alloc(8192)
initialize_pool(buffer, 8192, 4)
var owo = claim(buffer, 1024)
assert owo != nil
var uwu = claim(buffer, 1024)
assert uwu != nil
var awoo = claim(buffer, 1024)
assert awoo != nil
destroy_pool(buffer)

echo(mapping(460, 4))
echo(mapping(560, 4))
echo(mapping(660, 4))
echo(mapping(760, 4))
echo(mapping(2048, 4))
echo(mapping(3000, 4))
