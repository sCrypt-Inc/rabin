// Helper functions
function checkIfValidHexString(hexString) {
    if(typeof hexString !== 'string')
        return false;
    let re = new RegExp('^(0x|0X)?[a-fA-F0-9]+$');
    return re.test(hexString);
}

function decimalToHexString(number) {
    if(typeof(number) !== 'bigint' && isNaN(number))
        throw ("Error: Argument %s should be a Number or BigInt", number);

    if (number < 0) {
        number = 0xFFFFFFFF + number + 1;
    }
    return '0x'+number.toString(16);
}

function hexStringToDecimal(hexString) {
    if (!checkIfValidHexString(hexString))
        throw ("Error: Hex %s should be hexadecimal with or without '0x' at the beginning.", hexString);
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

function hexStringToBigInt(hexString){
    return BigInt(hexStringToDecimal(hexString));
}
// Test functions
let getRandomInt = function(max) {
    return Math.floor(Math.random() * max);
}

// Random hex string generator
let getRandomHex = function(len) {
    let maxlen = 16,
        min = Math.pow(16, Math.min(len, maxlen) - 1),
        max = Math.pow(16, Math.min(len, maxlen)) - 1,
        n = Math.floor(Math.random() * (max - min + 1)) + min,
        r = n.toString(16);
    while (r.length < len) {
        r = r + getRandomHex(len - maxlen);
    }
    return r;
}

module.exports = {
    checkIfValidHexString,
    decimalToHexString,
    hexStringToDecimal,
    hexStringToBigInt,
    getRandomInt,
    getRandomHex
}
