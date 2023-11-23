export function isHexString(hexString: string): boolean {
    const re = new RegExp('^(0x|0X)?[a-fA-F0-9]+$');
    return re.test(hexString);
}

// https://coolaj86.com/articles/convert-decimal-to-hex-with-js-bigints/
export function bigIntToHexString(bn: bigint): string {
    var pos = true;
    bn = BigInt(bn);

    // I've noticed that for some operations BigInts can
    // only be compared to other BigInts (even small ones).
    // However, <, >, and == allow mix and match
    if (bn < 0) {
        pos = false;
        bn = bitnot(bn);
    }

    var base = 16;
    var hex = bn.toString(base);
    if (hex.length % 2) {
        hex = '0' + hex;
    }

    // Check the high byte _after_ proper hex padding
    var highbyte = parseInt(hex.slice(0, 2), 16);
    var highbit = (0x80 & highbyte);

    if (pos && highbit) {
        // A 32-byte positive integer _may_ be
        // represented in memory as 33 bytes if needed
        hex = '00' + hex;
    }

    return hex;
}

export function bitnot(bn: bigint): bigint {
    // JavaScript's bitwise not doesn't work on negative BigInts (bn = ~bn; // WRONG!)
    // so we manually implement our own two's compliment (flip bits, add one)
    bn = -bn;
    var bin = (bn).toString(2)
    var prefix = '';
    while (bin.length % 8) {
        bin = '0' + bin;
    }
    if ('1' === bin[0] && -1 !== bin.slice(1).indexOf('1')) {
        prefix = '11111111';
    }
    bin = bin.split('').map(function (i) {
        return '0' === i ? '1' : '0';
    }).join('');
    return BigInt('0b' + prefix + bin) + BigInt(1);
}

export function hexStringToDecimal(hexString: string): string {
    if (!isHexString(hexString))
        throw (`Error: Hex ${hexString} should be hexadecimal with or without '0x' at the beginning.`);
    // Remove 0x from string if necessary
    hexString = hexString.replace('0x', '');

    var i, j, digits = [0],
        carry;
    for (i = 0; i < hexString.length; i += 1) {
        carry = parseInt(hexString.charAt(i), 16);
        for (j = 0; j < digits.length; j += 1) {
            digits[j] = digits[j] * 16 + carry;
            carry = digits[j] / 10 | 0;
            digits[j] %= 10;
        }
        while (carry > 0) {
            digits.push(carry % 10);
            carry = carry / 10 | 0;
        }
    }
    return digits.reverse().join('');
}

export function hexStringToBigInt(hexString: string): bigint {
    return BigInt(hexStringToDecimal(hexString));
}

/**
 * Returns a random integer between min (inclusive) and max (inclusive).
 * The value is no lower than min (or the next integer greater than min
 * if min isn't an integer) and no greater than max (or the next integer
 * lower than max if max isn't an integer).
 * Using Math.round() will give you a non-uniform distribution!
 */
export function getRandomInt(min: number, max: number): number {
    min = Math.ceil(min);
    max = Math.floor(max);
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

// Random hex string generator
export function getRandomHexString(len: number): string {
    let output = '';
    for (let i = 0; i < len; ++i) {
        output += (Math.floor(Math.random() * 16)).toString(16);
    }
    return output;
}

export function bigIntAbsoluteValue(value: bigint): bigint {
    return value > 0n ? value : -value
}

export function toBufferBE(
    num: bigint | number,
    size: number | undefined = undefined,
) {
    const hex = num.toString(16);
    const byteLength = Math.max(size || 0, Math.ceil(hex.length / 2));
    return Buffer.from(hex.padStart(byteLength * 2, '0'), 'hex');
}

export function toBufferLE(
    num: bigint | number,
    size: number | undefined = undefined,
) {
    return toBufferBE(num, size).reverse();
}
