import { calculateShannonEntropy } from './entropy';

describe('calculateShannonEntropy', () => {
    test('calculates entropy for uniform distribution', () => {
        // "abcd" has 4 unique characters, each appearing once
        // Expected entropy: log2(4) = 2
        const result = calculateShannonEntropy('abcd');
        expect(result).toBeCloseTo(2, 10);
    });

    test('calculates entropy for string with repeated characters', () => {
        // "aabb" has 2 unique characters, each appearing twice
        // Expected entropy: log2(2) = 1
        const result = calculateShannonEntropy('aabb');
        expect(result).toBeCloseTo(1, 10);
    });

    test('calculates entropy for single character string', () => {
        // "aaaa" has 1 unique character
        // Expected entropy: 0 (no uncertainty)
        const result = calculateShannonEntropy('aaaa');
        expect(result).toBeCloseTo(0, 10);
    });

    test('calculates entropy for mixed distribution', () => {
        // "aaab" - 'a' appears 3 times (3/4 probability), 'b' appears 1 time (1/4 probability)
        // Expected entropy: -(3/4 * log2(3/4) + 1/4 * log2(1/4))
        const result = calculateShannonEntropy('aaab');
        const expected = -(3 / 4 * Math.log2(3 / 4) + 1 / 4 * Math.log2(1 / 4));
        expect(result).toBeCloseTo(expected, 10);
    });

    test('handles empty string', () => {
        // Empty string should return 0 entropy
        const result = calculateShannonEntropy('');
        expect(result).toBe(-0);
    });

    test('handles single character', () => {
        // Single character has no uncertainty
        const result = calculateShannonEntropy('a');
        expect(result).toBeCloseTo(0, 10);
    });

    test('calculates entropy for binary string', () => {
        // "0101" has 2 unique characters, each appearing twice
        // Expected entropy: log2(2) = 1
        const result = calculateShannonEntropy('0101');
        expect(result).toBeCloseTo(1, 10);
    });

    test('calculates entropy for longer uniform string', () => {
        // "abcdefgh" has 8 unique characters, each appearing once
        // Expected entropy: log2(8) = 3
        const result = calculateShannonEntropy('abcdefgh');
        expect(result).toBeCloseTo(3, 10);
    });

    test('handles special characters and spaces', () => {
        // Test with special characters and spaces
        const result = calculateShannonEntropy('a b!@');
        // 5 unique characters: 'a', ' ', 'b', '!', '@' - each appearing once
        // Expected entropy: log2(5) ≈ 2.321928
        expect(result).toBeCloseTo(Math.log2(5), 10);
    });

    test('calculates entropy for skewed distribution', () => {
        // "aaaaaaaab" - 'a' appears 8 times, 'b' appears 1 time
        const input = 'aaaaaaaab';
        const result = calculateShannonEntropy(input);
        const expected = -(8 / 9 * Math.log2(8 / 9) + 1 / 9 * Math.log2(1 / 9));
        expect(result).toBeCloseTo(expected, 10);
    });

    test('entropy is always non-negative', () => {
        const testCases = ['a', 'ab', 'abc', 'aaab', 'hello world', '12345'];
        testCases.forEach(testCase => {
            const result = calculateShannonEntropy(testCase);
            expect(result).toBeGreaterThanOrEqual(0);
        });
    });

    test('entropy increases with more uniform distributions', () => {
        // More uniform distributions should have higher entropy
        const skewed = calculateShannonEntropy('aaaaaaaab'); // Very skewed
        const balanced = calculateShannonEntropy('aaaabbbb'); // Balanced
        const uniform = calculateShannonEntropy('abcdefgh'); // Uniform

        expect(skewed).toBeLessThan(balanced);
        expect(balanced).toBeLessThan(uniform);
    });

    test('handles unicode characters', () => {
        // Test with unicode characters
        const result = calculateShannonEntropy('αβγδ');
        expect(result).toBeCloseTo(2, 10); // 4 unique characters
    });

    test('order independence', () => {
        // Entropy should be the same regardless of character order
        const result1 = calculateShannonEntropy('abcd');
        const result2 = calculateShannonEntropy('dcba');
        const result3 = calculateShannonEntropy('cadb');

        expect(result1).toBeCloseTo(result2, 10);
        expect(result1).toBeCloseTo(result3, 10);
    });
})