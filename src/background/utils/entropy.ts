export function calculateShannonEntropy(input: string): number {
    const chars: Map<string, number> = new Map();
    const length = input.length;

    for (const char of input) {
        const count = chars.get(char) || 0;
        chars.set(char, count + 1);
    }

    let entropy = 0;
    const inverseTotal = 1 / length;

    for (const count of chars.values()) {
        const probability = count * inverseTotal;
        entropy += probability * Math.log2(probability);
    }

    return -entropy;
}