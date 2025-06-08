import {
    DefaultFalsePositives,
    falsePositiveSecretPattern,
    isKnownFalsePositive,
    isLikelyUUID
} from './falsePositives';

describe('DefaultFalsePositives', () => {
    test('contains expected default terms', () => {
        expect(DefaultFalsePositives.has('example')).toBe(true);
        expect(DefaultFalsePositives.has('xxxxxx')).toBe(true);
        expect(DefaultFalsePositives.has('aaaaaa')).toBe(true);
        expect(DefaultFalsePositives.has('abcde')).toBe(true);
        expect(DefaultFalsePositives.has('00000')).toBe(true);
        expect(DefaultFalsePositives.has('sample')).toBe(true);
        expect(DefaultFalsePositives.has('*****')).toBe(true);
    });

    test('has expected size', () => {
        expect(DefaultFalsePositives.size).toBe(7);
    });
});

describe('falsePositiveSecretPattern', () => {
    test('matches 40-character hexadecimal strings', () => {
        const validHex40 = 'a1b2c3d4e5f6789012345678901234567890abcd';
        expect(falsePositiveSecretPattern.test(validHex40)).toBe(true);
    });

    test('matches lowercase hex only', () => {
        const lowercaseHex = 'abcdef1234567890abcdef1234567890abcdef12';
        const uppercaseHex = 'ABCDEF1234567890ABCDEF1234567890ABCDEF12';

        expect(falsePositiveSecretPattern.test(lowercaseHex)).toBe(true);
        expect(falsePositiveSecretPattern.test(uppercaseHex)).toBe(false);
    });

    test('rejects strings of wrong length', () => {
        const tooShort = 'a1b2c3d4e5f6789012345678901234567890abc';  // 39 chars
        const tooLong = 'a1b2c3d4e5f6789012345678901234567890abcde'; // 41 chars

        expect(falsePositiveSecretPattern.test(tooShort)).toBe(false);
        expect(falsePositiveSecretPattern.test(tooLong)).toBe(false);
    });

    test('rejects empty string', () => {
        expect(falsePositiveSecretPattern.test('')).toBe(false);
    });
});

describe('isLikelyUUID', () => {
    test('identifies valid UUID v4 format', () => {
        const validUUIDs = [
            '550e8400-e29b-41d4-a716-446655440000',
            '6ba7b810-9dad-11d1-80b4-00c04fd430c8',
            '12345678-1234-1234-1234-123456789abc'
        ];

        validUUIDs.forEach(uuid => {
            expect(isLikelyUUID(uuid)).toBe(true);
        });
    });

    test('handles case insensitivity', () => {
        const mixedCase = '550E8400-E29B-41D4-A716-446655440000';
        const lowercase = '550e8400-e29b-41d4-a716-446655440000';

        expect(isLikelyUUID(mixedCase)).toBe(true);
        expect(isLikelyUUID(lowercase)).toBe(true);
    });

    test('rejects invalid UUID formats', () => {
        const invalidUUIDs = [
            '550e8400-e29b-41d4-a716-44665544000',   // Missing one character
            '550e8400-e29b-41d4-a716-44665544000g',  // Invalid character
            '550e8400e29b41d4a716446655440000',       // Missing hyphens
            '550e8400-e29b-41d4-a716',               // Too short
            '550e8400-e29b-41d4-a716-446655440000-extra', // Too long
            ''
        ];

        invalidUUIDs.forEach(uuid => {
            expect(isLikelyUUID(uuid)).toBe(false);
        });
    });
});

describe('isKnownFalsePositive', () => {
    describe('UTF-8 validation', () => {
        test('handles valid UTF-8 strings', () => {
            const [isFalsePositive] = isKnownFalsePositive('validstring');
            expect(isFalsePositive).toBe(false);
        });

        test('detects invalid UTF-8 encoding issues', () => {
            // This test might be tricky since JavaScript handles most UTF-8 well
            // We're testing the try-catch logic around encodeURIComponent
            const validString = 'test string';
            const [isFalsePositive, reason] = isKnownFalsePositive(validString);
            // This should not trigger the UTF-8 error for normal strings
            expect(reason).not.toBe('invalid utf8');
        });
    });

    describe('exact match detection', () => {
        test('detects exact matches from default false positives', () => {
            const [isFalsePositive, reason] = isKnownFalsePositive('example');
            expect(isFalsePositive).toBe(true);
            expect(reason).toBe('matches term: example');
        });

        test('handles case insensitive exact matches', () => {
            const [isFalsePositive, reason] = isKnownFalsePositive('EXAMPLE');
            expect(isFalsePositive).toBe(true);
            expect(reason).toBe('matches term: example');
        });

        test('detects all default false positives', () => {
            const testCases = ['example', 'xxxxxx', 'aaaaaa', 'abcde', '00000', 'sample', '*****'];

            testCases.forEach(term => {
                const [isFalsePositive, reason] = isKnownFalsePositive(term);
                expect(isFalsePositive).toBe(true);
                expect(reason).toBe(`matches term: ${term}`);
            });
        });
    });

    describe('substring detection', () => {
        test('detects substrings of false positives', () => {
            const [isFalsePositive, reason] = isKnownFalsePositive('this-is-an-example-string');
            expect(isFalsePositive).toBe(true);
            expect(reason).toBe('contains term: example');
        });

        test('detects multiple possible substrings', () => {
            const [isFalsePositive, reason] = isKnownFalsePositive('example-sample');
            expect(isFalsePositive).toBe(true);
            // Should match the first one found in the iteration
            expect(['contains term: example', 'contains term: sample']).toContain(reason);
        });

        test('handles case insensitive substring matches', () => {
            const [isFalsePositive, reason] = isKnownFalsePositive('THIS-IS-AN-EXAMPLE-STRING');
            expect(isFalsePositive).toBe(true);
            expect(reason).toBe('contains term: example');
        });
    });

    describe('hash pattern detection', () => {
        test('detects 40-character hex patterns', () => {
            const hashPattern = 'a1b2c3d4e5f6789012345678901234567890abcd';
            const [isFalsePositive, reason] = isKnownFalsePositive(hashPattern);
            expect(isFalsePositive).toBe(true);
            expect(reason).toBe('matches hash pattern');
        });

        test('ignores uppercase hex patterns', () => {
            const uppercaseHash = 'A1B2C3D4E5F6789012345678901234567890ABCD';
            const [isFalsePositive, reason] = isKnownFalsePositive(uppercaseHash);
            expect(isFalsePositive).toBe(false);
            expect(reason).toBe('');
        });
    });

    describe('UUID pattern detection', () => {
        test('detects valid UUID patterns', () => {
            const uuid = '550e8400-e29b-41d4-a716-446655440000';
            const [isFalsePositive, reason] = isKnownFalsePositive(uuid);
            expect(isFalsePositive).toBe(true);
            expect(reason).toBe('matches UUID pattern');
        });

        test('detects UUIDs regardless of case', () => {
            const upperUuid = '550E8400-E29B-41D4-A716-446655440000';
            const [isFalsePositive, reason] = isKnownFalsePositive(upperUuid);
            expect(isFalsePositive).toBe(true);
            expect(reason).toBe('matches UUID pattern');
        });
    });

    describe('custom false positives', () => {
        test('uses custom false positive set when provided', () => {
            const customFalsePositives = new Set(['custom', 'test']);
            const [isFalsePositive, reason] = isKnownFalsePositive('custom', customFalsePositives);
            expect(isFalsePositive).toBe(true);
            expect(reason).toBe('matches term: custom');
        });

        test('ignores default false positives when custom set provided', () => {
            const customFalsePositives = new Set(['custom']);
            const [isFalsePositive] = isKnownFalsePositive('example', customFalsePositives);
            expect(isFalsePositive).toBe(false);
        });
    });

    describe('priority order', () => {
        test('exact match takes priority over substring', () => {
            const customSet = new Set(['test', 'testing']);
            const [isFalsePositive, reason] = isKnownFalsePositive('test', customSet);
            expect(isFalsePositive).toBe(true);
            expect(reason).toBe('matches term: test');
        });

        test('false positive terms checked before patterns', () => {
            // Create a string that matches both a false positive term and hash pattern
            const customSet = new Set(['a1b2c3d4e5f6789012345678901234567890abcd']);
            const [isFalsePositive, reason] = isKnownFalsePositive('a1b2c3d4e5f6789012345678901234567890abcd', customSet);
            expect(isFalsePositive).toBe(true);
            expect(reason).toBe('matches term: a1b2c3d4e5f6789012345678901234567890abcd');
        });
    });

    describe('negative cases', () => {
        test('returns false for legitimate secrets', () => {
            const legitimateSecret = 'sk-1234567890mnopqrstuvwxyzghijkl';
            const [isFalsePositive, reason] = isKnownFalsePositive(legitimateSecret);
            expect(isFalsePositive).toBe(false);
            expect(reason).toBe('');
        });

        test('returns false for random strings', () => {
            const randomString = 'randomsecretkey123';
            const [isFalsePositive, reason] = isKnownFalsePositive(randomString);
            expect(isFalsePositive).toBe(false);
            expect(reason).toBe('');
        });

        test('returns false for empty string', () => {
            const [isFalsePositive, reason] = isKnownFalsePositive('');
            expect(isFalsePositive).toBe(false);
            expect(reason).toBe('');
        });
    });

    describe('edge cases', () => {
        test('handles strings with special characters', () => {
            const specialString = '!@#$%^&*()';
            const [isFalsePositive, reason] = isKnownFalsePositive(specialString);
            expect(isFalsePositive).toBe(false);
            expect(reason).toBe('');
        });

        test('handles very long strings', () => {
            const longString = 'a'.repeat(1000);
            const [isFalsePositive, reason] = isKnownFalsePositive(longString);
            expect(isFalsePositive).toBe(true);
            expect(reason).toBe('contains term: aaaaaa');
        });

        test('handles unicode characters', () => {
            const unicodeString = '测试字符串αβγδ';
            const [isFalsePositive, reason] = isKnownFalsePositive(unicodeString);
            expect(isFalsePositive).toBe(false);
            expect(reason).toBe('');
        });
    });

    describe('UTF-8 validation', () => {
        test('handles valid UTF-8 strings', () => {
            const [isFalsePositive] = isKnownFalsePositive('validstring');
            expect(isFalsePositive).toBe(false);
        });

        test('detects strings with unpaired surrogates that cause encoding errors', () => {
            // Create a string with an unpaired high surrogate
            // This should cause encodeURIComponent to throw
            const invalidString = 'test\uD800invalid'; // High surrogate without low surrogate
            const [isFalsePositive, reason] = isKnownFalsePositive(invalidString);
            expect(isFalsePositive).toBe(true);
            expect(reason).toBe('invalid utf8');
        });

        test('detects strings with unpaired low surrogates', () => {
            // Create a string with an unpaired low surrogate
            const invalidString = 'test\uDC00invalid'; // Low surrogate without high surrogate
            const [isFalsePositive, reason] = isKnownFalsePositive(invalidString);
            expect(isFalsePositive).toBe(true);
            expect(reason).toBe('invalid utf8');
        });

        test('handles valid surrogate pairs correctly', () => {
            // Valid surrogate pair (emoji)
            const validString = 'test🌟valid'; // This contains a valid surrogate pair
            const [isFalsePositive, reason] = isKnownFalsePositive(validString);
            expect(isFalsePositive).toBe(false);
            expect(reason).toBe('');
        });

        test('detects malformed UTF-8 sequences', () => {
            // Test various malformed sequences that might cause issues
            const malformedSequences = [
                'test\uD800\uD800invalid', // Two high surrogates
                'test\uDC00\uDC00invalid', // Two low surrogates
                'test\uDC00\uD800invalid', // Wrong order surrogates
            ];

            malformedSequences.forEach(seq => {
                const [isFalsePositive, reason] = isKnownFalsePositive(seq);
                expect(isFalsePositive).toBe(true);
                expect(reason).toBe('invalid utf8');
            });
        });
    });
});