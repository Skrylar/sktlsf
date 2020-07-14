import math, options

type
    PoolHeader = object
        fli: int
        sli: int
        minimum_block: int
        fla: uint32

    UsedBlockHeader = object of RootObj
        # NB: allocations are always aligned to four byte boundaries,
        # so the lowest two bits are stolen for metadata
        aleph: uint
        previous_physical_block: pointer
    
    FreeBlockHeader = object of UsedBlockHeader
        next_free, prev_free: pointer

const
    BusyBit = 1
    BusyMask = uint.high xor BusyBit

    LastInPoolBit = BusyBit + 1
    LastInPoolMask = uint.high xor LastInPoolBit

    SizeMask = (uint.high xor BusyBit) xor LastInPoolBit
    SizeMask2 = SizeMask xor typeof(SizeMask).high

proc last_in_pool(header: UsedBlockHeader): bool =
    return (header.aleph and LastInPoolBit) != 0

proc `last_in_pool=`(header: var UsedBlockHeader; flag: bool) =
    var z = header.aleph and LastInPoolMask
    if flag:
        z += LastInPoolBit
    header.aleph = z

proc busy(header: UsedBlockHeader): bool =
    return (header.aleph and BusyBit) != 0

proc `busy=`(header: var UsedBlockHeader; flag: bool) =
    var z = header.aleph and BusyMask
    if flag:
        z += BusyBit
    header.aleph = z

proc size(header: UsedBlockHeader): uint =
    return header.size and SizeMask

proc `size=`(header: var UsedBlockHeader; size: uint) =
    header.aleph = (header.aleph and SizeMask2) + (size and SizeMask)

proc second_level_count(sli: uint): int =
    return floor(pow(2, sli.float)).int

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

proc initialize_pool*(buffer: pointer; buffer_size: cuint; sli: int = 4) =
    if sli notin 1..32:
        raise newException(RangeError, "Second Level Indices must be in range [1, 32]")
    # TODO flail if sli is also not a power of two

    let sli_size = ((second_level_count(sli.uint) * 33) * pointer.sizeof)

    let minimum_pool_size = PoolHeader.sizeof +
        FreeBlockHeader.sizeof +
        sli_size

    if buffer_size < minimum_pool_size.cuint:
        raise newException(ValueError, "Cannot create TLSF pool this small")

    let data_block = PoolHeader.sizeof + sli_size
    let data_block_at = cast[int](buffer) + data_block

    # fill out header
    var header = cast[ptr PoolHeader](buffer)
    header.fli = min(log2(buffer_size.float), 31).int
    header.sli = sli
    header.minimum_block = UsedBlockHeader.sizeof
    header.fla = 0

    # zero out second level index
    zeroMem(cast[pointer](cast[int](buffer) + PoolHeader.sizeof), sli_size)

    # fill out initial block
    var entry = cast[ptr FreeBlockHeader](data_block_at)
    entry[].size = (buffer_size.int - data_block).uint
    entry.previous_physical_block = nil
    entry.next_free = nil
    entry.prev_free = nil

    # insert entry in to index
    let fs = mapping(buffer_size, sli.cuint)
    header.fla += 1.uint32 shl fs.f.uint32

proc destroy_pool*(buffer: pointer) =
    var header = cast[ptr PoolHeader](buffer)
    header.fla = 0

proc claim*(buffer: pointer; size: cuint): pointer =
    var header = cast[ptr PoolHeader](buffer)
    var fs = mapping(size, header.sli.cuint)

    # no buckets at top level so we obviously can't do
    if header.fla == 0: return nil

    discard

proc release*(buffer: pointer; blocc: pointer) =
    discard

var buffer = alloc(8192)
initialize_pool(buffer, 8192, 4)
destroy_pool(buffer)

echo(mapping(460, 4))
echo(mapping(560, 4))
echo(mapping(660, 4))
echo(mapping(760, 4))
echo(mapping(2048, 4))
echo(mapping(3000, 4))
