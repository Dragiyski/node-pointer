import fs from 'fs';

const properties = {
    buffer: Symbol('buffer'),
    headers: Symbol('headers'),
    info: Symbol('info'),
    sectionIndex: Symbol('sectionIndex'),
    dynamicSymbols: Symbol('dynamicSymbols'),
    symbols: Symbol('symbols')
};

const methods = {
    readHeaders: Symbol('readHeaders'),
    readElfHeader: Symbol('readElfHeader'),
    readProgramHeaders: Symbol('readProgramHeaders'),
    readSectionHeaders: Symbol('readSectionHeaders'),
    getNullTerminatedString: Symbol('getNullTerminatedString'),
    processSymbolTable: Symbol('processSymbolTable')
};

/**
 * @param {string} filename
 * @param {object} options
 * @returns {Promise<object>}
 */
export async function parseFile(filename, options = {}) {
    options = { ...options };
    const handle = await fs.promises.open(filename, 'r');
    const target = Object.create(null);
    target.header = Object.create(null);
    [target.header.EI, target.info] = await parseElfIdentificationHeader(handle);
    target.header.e = await parseElfHeader(handle, target.info);
    target.header.ph = await parseProgramHeaders(handle, target.info, target.header.e);
    target.header.sh = await parseSectionHeaders(handle, target.info, target.header.e);
    target.sections = await parseSections(handle, target.header.sh, target.header.e);
    target.symbols = await parseSymbols(handle, target.info, target.header.sh, target.sections);
    target.linkFunctionList = target.symbols.list.filter(s => s.shndx !== 0 && (s.info & 0xF) === 2 && s._section.header.type === 11 && [1, 2].indexOf(s.info >> 4) >= 0).map(s => s._name).sort();
    await handle.close();
    return target;
}

/**
 * @param {fs.FileHandle} handle
 * @returns {Promise<[ElfIdentificationHeader, ElfInformation]>}
 */
export async function parseElfIdentificationHeader(handle) {
    const info = Object.create(null);
    const headerSize = 16;
    const source = createBufferView(headerSize);
    const { bytesRead } = await handle.read(source.uint8, 0, headerSize, 0);
    if (bytesRead < headerSize) {
        throw new FileBlockError('EI: Invalid file size', 0, headerSize, bytesRead);
    }
    const header = Object.create(null);
    if ((header.MAGIC = source.data.getUint32(0, false)) !== 0x7F454C46) {
        throw new ParseError('EI.MAGIC: Invalid ELF magic number');
    }
    {
        const value = header.CLASS = source.data.getUint8(4);
        if (value === 1) {
            info.bit64 = false;
            info.wordSize = 4;
            info.maxPointerValue = (1n << 32n) - 1n;
        } else if (value === 2) {
            info.bit64 = true;
            info.wordSize = 8;
            info.maxPointerValue = (1n << 64n) - 1n;
        } else {
            throw new ParseError('EI.CLASS: Invalid elf class');
        }
    }
    {
        const value = header.DATA = source.data.getUint8(5);
        if (value === 1) {
            info.littleEndian = true;
        } else if (value === 2) {
            info.littleEndian = false;
        } else {
            throw new ParseError('EI.DATA');
        }
    }
    if ((header.VERSION = source.data.getUint8(6)) !== 1) {
        throw new ParseError('EI.VERSION');
    }
    header.OSABI = source.data.getUint8(0x07);
    header.ABIVERSION = source.data.getUint8(0x08);
    for (let i = 9; i < headerSize; ++i) {
        if (source.uint8[i] !== 0) {
            throw new ParseError('EI.PAD');
        }
    }
    info.stat = await handle.stat({ bigint: true });
    return [header, info];
}

/**
 * @param {fs.FileHandle} handle
 * @param {ElfInformation} info
 * @returns {Promise<ElfHeader>}
 */
export async function parseElfHeader(handle, info) {
    const headerSize = info.bit64 ? 0x30 : 0x24;
    const source = createBufferView(headerSize);
    const { bytesRead } = await handle.read(source.uint8, 0, headerSize, 16);
    if (bytesRead < headerSize) {
        throw new ParseError('e');
    }
    const header = Object.create(null);

    addWordRead(source.data, info.bit64);
    let ptr = 0;

    header.type = source.data.getUint16(ptr, info.littleEndian);
    ptr += 2;

    header.machine = source.data.getUint16(ptr, info.littleEndian);
    ptr += 2;

    header.version = source.data.getUint16(ptr, info.littleEndian);
    ptr += 4;

    header.entry = source.data.getUintWord(ptr, info.littleEndian);
    ptr += info.wordSize;

    header.phoff = source.data.getUintWord(ptr, info.littleEndian);
    ptr += info.wordSize;
    if (header.phoff > Number.MAX_SAFE_INTEGER) {
        throw new ParseError('e.phoff');
    }
    header.phoff = Number(header.phoff);

    header.shoff = source.data.getUintWord(ptr, info.littleEndian);
    ptr += info.wordSize;
    if (header.shoff > Number.MAX_SAFE_INTEGER) {
        throw new ParseError('e.shoff');
    }
    header.shoff = Number(header.shoff);

    header.flags = source.data.getUint32(ptr, info.littleEndian);
    ptr += 4;

    header.ehsize = source.data.getUint16(ptr, info.littleEndian);
    ptr += 2;

    header.phentsize = source.data.getUint16(ptr, info.littleEndian);
    ptr += 2;

    header.phnum = source.data.getUint16(ptr, info.littleEndian);
    ptr += 2;

    header.shentsize = source.data.getUint16(ptr, info.littleEndian);
    ptr += 2;

    header.shnum = source.data.getUint16(ptr, info.littleEndian);
    ptr += 2;

    header.shstrndx = source.data.getUint16(ptr, info.littleEndian);
    ptr += 2;

    if (ptr !== headerSize) {
        throw new Error(`Bug: In [e], parsed ${ptr} bytes, expected ${headerSize} bytes to be parsed`);
    }

    if (header.version !== 1) {
        throw new ParseError('e.version');
    }

    if (header.ehsize !== headerSize + 0x10) {
        throw new ParseError('e.ehsize');
    }

    if (header.shstrndx >= header.shnum) {
        throw new ParseError('e.shstrndx');
    }

    return header;
}

/**
 * @param {fs.FileHandle} handle
 * @param {ElfInformation} info
 * @param {ElfHeader} elfHeader
 * @returns {Promise<Array<ElfProgramHeader>>}
 */
export async function parseProgramHeaders(handle, info, elfHeader) {
    let filePointer = elfHeader.phoff;
    let headers = [];
    for (let i = 0; i < elfHeader.phnum; ++i) {
        const source = createBufferView(elfHeader.phentsize);
        const { bytesRead } = await handle.read(source.uint8, 0, elfHeader.phentsize, Number(filePointer));
        if (bytesRead < elfHeader.phentsize) {
            throw new ParseError('e.phoff');
        }

        addWordRead(source.data, info.bit64);
        const header = Object.create(null);
        let ptr = 0;
        header._offset = filePointer;
        header._size = elfHeader.phentsize;

        header.type = source.data.getUint32(ptr, info.littleEndian);
        ptr += 4;

        if (info.bit64) {
            header.flags = source.data.getUint32(ptr, info.littleEndian);
            ptr += 4;
        }

        header.offset = source.data.getUintWord(ptr, info.littleEndian);
        ptr += info.wordSize;
        if (header.offset > Number.MAX_SAFE_INTEGER) {
            throw new ParseError('ph.offset');
        }
        header.offset = Number(header.offset);

        header.vaddr = source.data.getUintWord(ptr, info.littleEndian);
        ptr += info.wordSize;

        header.paddr = source.data.getUintWord(ptr, info.littleEndian);
        ptr += info.wordSize;

        header.filesz = source.data.getUintWord(ptr, info.littleEndian);
        ptr += info.wordSize;
        if (header.filesz > Number.MAX_SAFE_INTEGER) {
            throw new ParseError('ph.filesz');
        }
        header.filesz = Number(header.filesz);

        header.memsz = source.data.getUintWord(ptr, info.littleEndian);
        ptr += info.wordSize;

        if (!info.bit64) {
            header.flags = source.data.getUint32(ptr, info.littleEndian);
            ptr += 4;
        }

        header.align = source.data.getUintWord(ptr, info.littleEndian);
        ptr += 8;

        headers.push(header);
        filePointer += ptr;
    }
    return headers;
}

/**
 * @param {fs.FileHandle} handle
 * @param {ElfInformation} info
 * @param {ElfHeader} elfHeader
 * @returns {Promise<ElfSectionHeader>}
 */
export async function parseSectionHeaders(handle, info, elfHeader) {
    let filePointer = elfHeader.shoff;
    let headers = [];
    for (let i = 0; i < elfHeader.shnum; ++i) {
        const source = createBufferView(elfHeader.shentsize);
        const { bytesRead } = await handle.read(source.uint8, 0, elfHeader.shentsize, Number(filePointer));
        if (bytesRead < elfHeader.shentsize) {
            throw new ParseError('e.shoff');
        }

        addWordRead(source.data, info.bit64);
        const header = Object.create(null);
        let ptr = 0;
        header._offset = filePointer;
        header._size = elfHeader.shentsize;
        header._index = i;

        header.name = source.data.getUint32(ptr, info.littleEndian);
        ptr += 4;

        header.type = source.data.getUint32(ptr, info.littleEndian);
        ptr += 4;

        header.flags = source.data.getUintWord(ptr, info.littleEndian);
        ptr += info.wordSize;

        header.addr = source.data.getUintWord(ptr, info.littleEndian);
        ptr += info.wordSize;

        header.offset = source.data.getUintWord(ptr, info.littleEndian);
        ptr += info.wordSize;
        if (header.offset > Number.MAX_SAFE_INTEGER) {
            throw new ParseError('sh.offset');
        }
        header.offset = Number(header.offset);

        header.size = source.data.getUintWord(ptr, info.littleEndian);
        ptr += info.wordSize;
        if (header.size > Number.MAX_SAFE_INTEGER) {
            throw new ParseError('sh.size');
        }
        header.size = Number(header.size);

        header.link = source.data.getUint32(ptr, info.littleEndian);
        ptr += 4;

        header.info = source.data.getUint32(ptr, info.littleEndian);
        ptr += 4;

        header.addralign = source.data.getUintWord(ptr, info.littleEndian);
        ptr += info.wordSize;

        header.entsize = source.data.getUintWord(ptr, info.littleEndian);
        ptr += info.wordSize;
        if (header.entsize > Number.MAX_SAFE_INTEGER) {
            throw new ParseError('sh.entsize');
        }
        header.entsize = Number(header.entsize);

        // Align must be power of 2
        let align = header.addralign;
        if (align > 0n) {
            // If align is non-zero (and positive) we shirt to the right, until we find the first non-zero bit.
            while ((align & 1n) === 0n) {
                align >>= 1n;
            }
            // When non-zero bit is found, the remaining bits must be zero (i.e. the value will have only one bit set ot 1).
            if (align !== 1n) {
                throw new Error('sh.addralign');
            }
        }

        headers.push(header);
        filePointer += ptr;
    }
    return headers;
}

/**
 * @param {fs.FileHandle} handle
 * @param {Array<ElfSectionHeader>} sectionList
 * @param {ElfHeader} elfHeader
 * @returns {Promise<void>}
 */
export async function parseSections(handle, sectionList, elfHeader) {
    if (elfHeader.shstrndx >= sectionList.length) {
        throw new ParseError('e.shstrndx');
    }
    const shStringTable = sectionList[elfHeader.shstrndx];
    const stat = handle.stat({ bigint: true });
    if (shStringTable.offset + shStringTable.size > stat.size) {
        throw new ParseError('sh.offset');
    }
    const shStringData = createBufferView(shStringTable.size);
    const { bytesRead } = await handle.read(shStringData.uint8, 0, Number(shStringTable.size), Number(shStringTable.offset));
    if (bytesRead < shStringTable.size) {
        throw new ParseError('sh.offset');
    }
    const sections = Object.create(null);

    for (let i = 0; i < sectionList.length; ++i) {
        const sectionHeader = sectionList[i];
        if (sectionHeader.type === 0) {
            continue;
        }
        if (sectionHeader.name > shStringData.uint8.byteLength) {
            throw new ParseError('sh.name');
        }
        const name = getNullTerminatedString(shStringData.uint8, sectionHeader.name);
        if (!name) {
            throw new ParseError('sh.name');
        }
        if (name in sections) {
            // Duplicate section?
            throw new ParseError('sh.name');
        }
        const section = sections[name] = Object.create(null);
        section.header = sectionHeader;
        Object.defineProperties(section, {
            load: {
                configurable: true,
                writable: true,
                value: loadSection
            }
        });
        section._name = section.header._name = name;
        sections[name] = section;
        if (i === elfHeader.shstrndx) {
            section.content = shStringData;
        }
    }
    return sections;
}

export async function parseSymbols(handle, info, headers, sections) {
    const list = [];
    const map = {};
    const jobs = [];
    const stat = await handle.stat({ bigint: true });
    for (let sectionIndex = 0; sectionIndex < headers.length; ++sectionIndex) {
        const sectionHeader = headers[sectionIndex];
        if (sectionHeader.type !== 2 && sectionHeader.type !== 11) {
            continue;
        }
        const section = sections[sectionHeader._name];
        jobs.push(loadSymbols(section));
    }
    await Promise.all(jobs);
    return { list, map };

    async function loadSymbols(symbolSection) {
        const stringHeader = headers[symbolSection.header.link];
        if (stringHeader.type !== 3) {
            throw new ParseError(`Symbol section [${symbolSection.header._name}] links to non-string section [${stringHeader._name}]`);
        }
        const stringSection = sections[stringHeader._name];
        const stringData = await stringSection.load(handle);
        let filePointer = symbolSection.header.offset;
        let index = 0;
        const sectionEnd = filePointer + symbolSection.header.size;
        const entrySize = 4 + 1 + 1 + 2 + info.wordSize + info.wordSize;
        {
            const nullEntry = new Uint8Array(new ArrayBuffer(Number(entrySize)));
            if (filePointer + entrySize > sectionEnd) {
                throw new FileBlockError('Insufficient data for symbol[0]', filePointer, entrySize, sectionEnd);
            }
            const { bytesRead } = await handle.read(nullEntry, 0, Number(entrySize), Number(filePointer));
            if (bytesRead < entrySize) {
                throw new FileBlockError('Insufficient data for symbol[0]', filePointer, entrySize, sectionEnd);
            }
            for (let i = 0; i < entrySize; ++i) {
                if (nullEntry[i] !== 0) {
                    throw new ParseError(`Section [${symbolSection._name}] contains non-zero byte in the null entry`);
                }
            }
        }
        filePointer += entrySize;
        const jobs = [];
        while (filePointer < sectionEnd) {
            const symbolInfo = Object.create(null);
            symbolInfo._offset = Number(filePointer);
            symbolInfo._size = Number(entrySize);
            symbolInfo._index = list.length;
            symbolInfo._section = symbolSection;
            list.push(symbolInfo);
            jobs.push(loadSymbol(symbolInfo));
            filePointer += entrySize;
        }
        return Promise.all(jobs);

        async function loadSymbol(symbolInfo) {
            if (symbolInfo._offset + symbolInfo._size > sectionEnd) {
                throw new FileBlockError('Insufficient data for symbol[0]', symbolInfo._offset, entrySize, sectionEnd);
            }
            const source = createBufferView(entrySize);
            const { bytesRead } = await handle.read(source.uint8, 0, Number(entrySize), symbolInfo._offset);
            if (bytesRead < entrySize) {
                throw new FileBlockError('Insufficient data for symbol[0]', symbolInfo._offset, entrySize, sectionEnd);
            }

            addWordRead(source.data, info.bit64);
            let ptr = 0;

            symbolInfo.name = source.data.getUint32(ptr, info.littleEndian);
            ptr += 4;
            if (!info.bit64) {
                symbolInfo.value = source.data.getUintWord(ptr, info.littleEndian);
                ptr += info.wordSize;
                symbolInfo.size = source.data.getUintWord(ptr, info.littleEndian);
                ptr += info.wordSize;
            }
            symbolInfo.info = source.data.getUint8(ptr++);
            symbolInfo.other = source.data.getUint8(ptr++);
            symbolInfo.shndx = source.data.getUint16(ptr, info.littleEndian);
            ptr += 2;
            if (info.bit64) {
                symbolInfo.value = source.data.getUintWord(ptr, info.littleEndian);
                ptr += info.wordSize;
                symbolInfo.size = source.data.getUintWord(ptr, info.littleEndian);
                ptr += info.wordSize;
            }
            if (ptr !== entrySize) {
                throw new Error(`Bug: Section [${symbolSection._name}], symbol entry is ${entrySize} bytes, but only ${ptr} bytes read at ${symbolInfo._index}`);
            }
            if (symbolInfo.name > stringData.uint8.length) {
                throw new ParseError(`Section [${symbolSection._name}]: symbol entry name ${symbolInfo.name} out of the bounds of [${stringSection._name}] section ${stringData.uint8.length}`);
            }
            if (symbolInfo.name === 0) {
                symbolInfo._name = null;
            } else {
                symbolInfo._name = getNullTerminatedString(stringData.uint8, symbolInfo.name);
                if (symbolInfo._name in map) {
                    if (!Array.isArray(map[symbolInfo._name])) {
                        map[symbolInfo._name] = [map[symbolInfo._name]];
                    }
                    map[symbolInfo._name].push(symbolInfo);
                } else {
                    map[symbolInfo._name] = symbolInfo;
                }
            }
        }
    }
}

/*export async function parseSymbols(handle, info, sections) {
    const list = [];
    const map = {};
    for (const sectionName in sections) {
        const section = sections[sectionName];
        if (section.header.type !== 2 && section.header.type !== 11) {
            continue;
        }
    }
    if (symbolSection == null) {
        return { list, map };
    }
    if (stringSection == null) {
        throw new ParseError(`Missing string section symbol names in [${symbolSection._name}]`);
    }
    const stringData = await stringSection.load(handle);
    const stat = await handle.stat({ bigint: true });
    let filePointer = symbolSection.header.offset;
    let index = 0;
    const sectionEnd = filePointer + symbolSection.header.size;
    const entrySize = 4 + 1 + 1 + 2 + info.wordSize + info.wordSize;
    {
        const nullEntry = new Uint8Array(new ArrayBuffer(Number(entrySize)));
        if (filePointer + entrySize > sectionEnd) {
            throw new FileBlockError('Insufficient data for symbol[0]', filePointer, entrySize, sectionEnd);
        }
        const { bytesRead } = await handle.read(nullEntry, 0, Number(entrySize), Number(filePointer));
        if (bytesRead < entrySize) {
            throw new FileBlockError('Insufficient data for symbol[0]', filePointer, entrySize, sectionEnd);
        }
        for (let i = 0; i < entrySize; ++i) {
            if (nullEntry[i] !== 0) {
                throw new ParseError(`Section ${symbolSection._name}, null entry is not cleared`);
            }
        }
    }
    filePointer += entrySize;
    const jobs = [];
    while (filePointer < sectionEnd) {
        const symbolInfo = Object.create(null);
        symbolInfo._offset = Number(filePointer);
        symbolInfo._size = Number(entrySize);
        symbolInfo._index = list.length;
        list.push(symbolInfo);
        jobs.push(loadSymbol(symbolInfo));
        filePointer += entrySize;
    }
    await Promise.all(jobs);
    return { list, map };

    async function loadSymbol(symbolInfo) {
        if (symbolInfo._offset + symbolInfo._size > sectionEnd) {
            throw new FileBlockError('Insufficient data for symbol[0]', symbolInfo._offset, entrySize, sectionEnd);
        }
        const source = createBufferView(entrySize);
        const { bytesRead } = await handle.read(source.uint8, 0, Number(entrySize), symbolInfo._offset);
        if (bytesRead < entrySize) {
            throw new FileBlockError('Insufficient data for symbol[0]', symbolInfo._offset, entrySize, sectionEnd);
        }

        addWordRead(source.data, info.bit64);
        let ptr = 0;

        symbolInfo.name = source.data.getUint32(ptr, info.littleEndian);
        ptr += 4;
        if (!info.bit64) {
            symbolInfo.value = source.data.getUintWord(ptr, info.littleEndian);
            ptr += info.wordSize;
            symbolInfo.size = source.data.getUintWord(ptr, info.littleEndian);
            ptr += info.wordSize;
        }
        symbolInfo.info = source.data.getUint8(ptr++);
        symbolInfo.other = source.data.getUint8(ptr++);
        symbolInfo.shndx = source.data.getUint16(ptr, info.littleEndian);
        ptr += 2;
        if (info.bit64) {
            symbolInfo.value = source.data.getUintWord(ptr, info.littleEndian);
            ptr += info.wordSize;
            symbolInfo.size = source.data.getUintWord(ptr, info.littleEndian);
            ptr += info.wordSize;
        }
        if (ptr !== entrySize) {
            throw new Error(`Bug: Section [${symbolSection._name}], symbol entry is ${entrySize} bytes, but only ${ptr} bytes read at ${symbolInfo._index}`);
        }
        if (symbolInfo.name > stringData.uint8.length) {
            throw new ParseError(`Section [${symbolSection._name}]: symbol entry name ${symbolInfo.name} out of the bounds of [${stringSection._name}] section ${stringData.uint8.length}`);
        }
        if (symbolInfo.name === 0) {
            symbolInfo._name = null;
        } else {
            symbolInfo._name = getNullTerminatedString(stringData.uint8, symbolInfo.name);
            if (symbolInfo._name in map) {
                if (!Array.isArray(map[symbolInfo._name])) {
                    map[symbolInfo._name] = [map[symbolInfo._name]];
                }
                map[symbolInfo._name].push(symbolInfo);
            } else {
                map[symbolInfo._name] = symbolInfo;
            }
        }
    }
}*/

/**
 * @param {fs.FileHandle} handle
 */
async function loadSection(handle) {
    if (this.content != null) {
        return this.content;
    }
    const stat = await handle.stat({ bigint: true });
    if (this.header.offset + this.header.size > stat.size) {
        throw new ParseError('sh.offset');
    }
    const content = createBufferView(this.header.size);
    const { bytesRead } = await handle.read(content.uint8, 0, Number(this.header.size), Number(this.header.offset));
    if (bytesRead < this.header.size) {
        throw new ParseError('sh.offset');
    }
    return this.content = content;
}

function getNullTerminatedString(buffer, offset) {
    let chars = [];
    let ptr = offset;
    while (true) {
        if (ptr >= buffer.byteLength) {
            throw new ParseError('string.length');
        }
        if (buffer[ptr] === 0) {
            break;
        }
        chars.push(buffer[ptr++]);
    }
    return Buffer.from(chars).toString();
}

function createBufferView(size) {
    const buffer = new ArrayBuffer(Number(size));
    return {
        buffer,
        uint8: new Uint8Array(buffer),
        data: new DataView(buffer)
    };
}

function addWordRead(bufferView, bit64) {
    bufferView.getUintWord = bit64 ? bufferView.getBigUint64 : function (...args) {
        return BigInt(this.getUint32(...args));
    };

    bufferView.getIntWord = bit64 ? bufferView.getBigInt64 : function (...args) {
        return BigInt(this.getInt32(...args));
    };
}

export class ParseError extends Error {
}

export class FileBlockError extends ParseError {
    constructor(message, offset, size, limit) {
        super();
        for (let i = 1; i < Math.min(arguments.length, 4); ++i) {
            if (typeof arguments[i] === 'number') {
                arguments[i] = BigInt(arguments[i]);
            }
        }
        const errorMessage = `${message}: block [0x${arguments[1].toString(16)}; 0x${(arguments[1] + arguments[2]).toString(16)}] exceeds [${arguments[3].toString(
            16)}}]`;
        Object.defineProperties(this, {
            offset: {
                configurable: true,
                writable: true,
                value: offset
            },
            size: {
                configurable: true,
                writable: true,
                value: size
            },
            limit: {
                configurable: true,
                writable: true,
                value: limit
            }
        });
    }
}

export const DynamicTableNames = {
    DT_NULL: 0,
    DT_NEEDED: 1,
    DT_PLTRELSZ: 2
};

/**
 * @typedef ElfIdentificationHeader
 * @property {number} MAGIC
 * @property {number} CLASS
 * @property {number} DATA
 * @property {number} VERSION
 * @property {number} OSABI
 * @property {number} OSABIVERSION
 */

/**
 * @typedef ElfInformation
 * @property {boolean} bit64
 * @property {number} wordSize
 * @property {bigint} maxPointerValue
 * @property {boolean} littleEndian
 * @property {fs.StatsBase<bigint>} stat
 */

/**
 * @typedef ElfHeader
 * @property {number} type
 * @property {number} machine
 * @property {number} version
 * @property {bigint} entry
 * @property {bigint} phoff
 * @property {bigint} shoff
 * @property {number} flags
 * @property {number} phentsize
 * @property {number} phnum
 * @property {number} shentsize
 * @property {number} shnum
 * @property {number} shstrndx
 */

/**
 * @typedef ElfProgramHeader
 * @property {bigint} _offset
 * @property {size} _size
 * @property {number} type
 * @property {number} flags
 * @property {bigint} offset
 * @property {bigint} vaddr
 * @property {bigint} paddr
 * @property {bigint} filesz
 * @property {bigint} memsz
 * @property {bigint} align
 */

/**
 * @typedef ElfSectionHeader
 * @property {number} name
 * @property {number} type
 * @property {bigint} flags
 * @property {bigint} addr
 * @property {bigint} offset
 * @property {bigint} size
 * @property {number} link
 * @property {number} info
 * @property {bigint} addralign
 * @property {bigint} entsize
 */
