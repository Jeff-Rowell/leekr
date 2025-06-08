import {
    deserializeFindings,
    deserializePatterns,
    findSecretPosition,
    getExistingFindings,
    getExistingPatterns,
    getSourceMapUrl,
    retrieveFindings,
    retrievePatterns,
    serializeFindings,
    serializePatterns,
    storeFindings,
    storePatterns
} from './common';

import { AWSOccurrence } from '../../types/aws.types';
import { Finding, Occurrence } from '../../types/findings.types';
import { PatternsObj } from '../../types/patterns.types';

const mockChromeStorage = {
    local: {
        get: jest.fn(),
        set: jest.fn()
    }
};

(global as any).chrome = {
    storage: {
        local: mockChromeStorage.local
    }
};

describe('Findings Utilities', () => {
    const mockOccurrenceOne: AWSOccurrence = {
        accountId: "123456789876",
        arn: "arn:aws:iam::123456789876:user/leekr",
        filePath: "main.foobar.js",
        fingerprint: "fp1",
        resourceType: "Access Key",
        secretType: "AWS Access & Secret Keys",
        secretValue: {
            match: { access_key_id: "lol", secret_key_id: "wut" }
        },
        sourceContent: {
            content: "foobar",
            contentEndLineNum: 35,
            contentFilename: "App.js",
            contentStartLineNum: 18,
            exactMatchNumbers: [23, 30]
        },
        url: "http://localhost:3000/static/js/main.foobar.js",
    };

    const mockOccurrenceTwo: AWSOccurrence = {
        accountId: "876123456789",
        arn: "arn:aws:iam::876123456789:user/leekr",
        filePath: "main.foobar.js",
        fingerprint: "fp1",
        resourceType: "Access Key",
        secretType: "AWS Access & Secret Keys",
        secretValue: {
            match: { access_key_id: "lol", secret_key_id: "wut" }
        },
        sourceContent: {
            content: "foobar",
            contentEndLineNum: 35,
            contentFilename: "App.js",
            contentStartLineNum: 18,
            exactMatchNumbers: [23, 30]
        },
        url: "http://localhost:3000/static/js/main.foobar.js",
    };

    const mockOccurrencesOne: Set<Occurrence> = new Set([mockOccurrenceOne]);
    const mockOccurrencesTwo: Set<Occurrence> = new Set([mockOccurrenceOne, mockOccurrenceTwo]);

    const mockFindings: Finding[] = [
        {
            fingerprint: "fp1",
            numOccurrences: mockOccurrencesOne.size,
            occurrences: mockOccurrencesOne,
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "AWS Access & Secret Keys",
            secretValue: {
                match: { access_key_id: "lol", secret_key_id: "wut" },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        },
        {
            fingerprint: "fp2",
            numOccurrences: mockOccurrencesTwo.size,
            occurrences: mockOccurrencesTwo,
            validity: "invalid",
            secretType: "AWS Access & Secret Keys",
            secretValue: {
                match: { access_key_id: "test", secret_key_id: "test" },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "invalid"
            }
        }
    ];

    beforeEach(() => {
        jest.clearAllMocks();
    });

    describe('serializeFindings', () => {
        test('should convert Set occurrences to Array', () => {
            const result = serializeFindings(mockFindings);

            expect(result).toHaveLength(2);
            expect(Array.isArray(result[0].occurrences)).toBe(true);
            expect(Array.isArray(result[1].occurrences)).toBe(true);
            expect(result[0].occurrences).toHaveLength(1);
            expect(result[1].occurrences).toHaveLength(2);
        });

        test('should preserve all other properties', () => {
            const result = serializeFindings(mockFindings);

            expect(result[0].fingerprint).toBe("fp1");
            expect(result[0].validity).toBe("valid");
            expect(result[0].secretType).toBe("AWS Access & Secret Keys");
        });

        test('should handle empty findings array', () => {
            const result = serializeFindings([]);
            expect(result).toEqual([]);
        });
    });

    describe('deserializeFindings', () => {
        test('should convert Array occurrences to Set', () => {
            const serialized = serializeFindings(mockFindings);
            const result = deserializeFindings(serialized);

            expect(result).toHaveLength(2);
            expect(result[0].occurrences instanceof Set).toBe(true);
            expect(result[1].occurrences instanceof Set).toBe(true);
            expect(result[0].occurrences.size).toBe(1);
            expect(result[1].occurrences.size).toBe(2);
        });

        test('should preserve all other properties', () => {
            const serialized = serializeFindings(mockFindings);
            const result = deserializeFindings(serialized);

            expect(result[0].fingerprint).toBe("fp1");
            expect(result[0].validity).toBe("valid");
            expect(result[0].secretType).toBe("AWS Access & Secret Keys");
        });

        test('should handle empty serialized array', () => {
            const result = deserializeFindings([]);
            expect(result).toEqual([]);
        });
    });

    describe('storeFindings', () => {
        test('should serialize and store findings in chrome storage', async () => {
            mockChromeStorage.local.set.mockImplementation((data, callback) => {
                callback();
            });

            await storeFindings(mockFindings);

            expect(mockChromeStorage.local.set).toHaveBeenCalledWith(
                { findings: serializeFindings(mockFindings) },
                expect.any(Function)
            );

            const [[storedObj]] = mockChromeStorage.local.set.mock.calls;
            expect(storedObj.findings).toEqual(serializeFindings(mockFindings));
        });

        test('should not crash if chrome storage fails to set', async () => {
            const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => { });

            mockChromeStorage.local.set.mockImplementationOnce((data, callback) => {
                throw new Error('Failed to store');
            });

            await expect(storeFindings(mockFindings)).resolves.toBeUndefined();

            expect(consoleSpy).toHaveBeenCalledWith('storeFindings failed:', new Error('Failed to store'));

            consoleSpy.mockRestore();
        });

        test('should handle chrome.runtime.lastError and not crash', async () => {
            (global as any).chrome.runtime = { lastError: new Error('Storage failed') };

            mockChromeStorage.local.set.mockImplementation((data, callback) => {
                callback();
            });

            const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => { });

            await storeFindings(mockFindings);

            expect(consoleSpy).toHaveBeenCalledWith('storeFindings failed:', new Error('Storage failed'));

            consoleSpy.mockRestore();
            (global as any).chrome.runtime = undefined;
        });
    });

    describe('retrieveFindings', () => {
        test('should retrieve and deserialize findings from chrome storage', async () => {
            const serializedFindings = serializeFindings(mockFindings);
            mockChromeStorage.local.get.mockImplementation((keys, callback) => {
                callback({ findings: serializedFindings });
            });

            const result = await retrieveFindings();

            expect(mockChromeStorage.local.get).toHaveBeenCalledWith(['findings'], expect.any(Function));
            expect(result).toHaveLength(2);
            expect(result[0].occurrences instanceof Set).toBe(true);
        });

        test('should return empty array when no findings in storage', async () => {
            mockChromeStorage.local.get.mockImplementation((keys, callback) => {
                callback({ findings: [] });
            });

            const result = await retrieveFindings();

            expect(result).toEqual([]);
        });
    });

    describe('getExistingFindings', () => {
        test('should return findings from storage', async () => {
            const serializedFindings = serializeFindings(mockFindings);
            mockChromeStorage.local.get.mockImplementation((keys, callback) => {
                callback({ findings: serializedFindings });
            });

            const result = await getExistingFindings();

            expect(result).toHaveLength(2);
            expect(result[0].occurrences instanceof Set).toBe(true);
        });

        test('should return empty array when no findings exist', async () => {
            mockChromeStorage.local.get.mockImplementation((keys, callback) => {
                callback({});
            });

            const result = await getExistingFindings();

            expect(result).toEqual([]);
        });
    });
});

describe('Source Map Utilities', () => {
    describe('getSourceMapUrl', () => {
        test('should extract relative source map URL and resolve it', () => {
            const bundleUrl = 'http://localhost:3000/static/js/main.js';
            const bundleContent = 'console.log("test");\n//# sourceMappingURL=main.js.map';

            const result = getSourceMapUrl(bundleUrl, bundleContent);

            expect(result).toBeInstanceOf(URL);
            expect(result?.toString()).toBe('http://localhost:3000/static/js/main.js.map');
        });

        test('should handle absolute source map URLs', () => {
            const bundleUrl = 'http://localhost:3000/static/js/main.js';
            const bundleContent = 'console.log("test");\n//# sourceMappingURL=https://example.com/maps/main.js.map';

            const result = getSourceMapUrl(bundleUrl, bundleContent);

            expect(result).toBeInstanceOf(URL);
            expect(result?.toString()).toBe('https://example.com/maps/main.js.map');
        });

        test('should handle root-relative source map URLs', () => {
            const bundleUrl = 'http://localhost:3000/static/js/main.js';
            const bundleContent = 'console.log("test");\n//# sourceMappingURL=/maps/main.js.map';

            const result = getSourceMapUrl(bundleUrl, bundleContent);

            expect(result).toBeInstanceOf(URL);
            expect(result?.toString()).toBe('http://localhost:3000/maps/main.js.map');
        });

        test('should handle data URLs', () => {
            const bundleUrl = 'http://localhost:3000/static/js/main.js';
            const bundleContent = 'console.log("test");\n//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ==';

            const result = getSourceMapUrl(bundleUrl, bundleContent);

            expect(result).toBeInstanceOf(URL);
            expect(result?.toString()).toBe('data:application/json;base64,eyJ2ZXJzaW9uIjozfQ==');
        });

        test('should return null when no source map URL is found', () => {
            const bundleUrl = 'http://localhost:3000/static/js/main.js';
            const bundleContent = 'console.log("test");';

            const result = getSourceMapUrl(bundleUrl, bundleContent);

            expect(result).toBeNull();
        });

        test('should handle malformed URLs gracefully', () => {
            const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => { });

            const bundleUrl = 'invalid-url';
            const bundleContent = 'console.log("test");\n//# sourceMappingURL=main.js.map';

            const result = getSourceMapUrl(bundleUrl, bundleContent);

            expect(result).toBeNull();

            expect(consoleSpy).toHaveBeenCalledWith('Error resolving source map URL:', expect.objectContaining({
                message: 'Invalid URL: invalid-url'
            }));
            consoleSpy.mockRestore();
        });
    });

    describe('findSecretPosition', () => {
        test('should find secret position in single line content', () => {
            const content = 'const secret = "mysecret123";';
            const secret = 'mysecret123';

            const result = findSecretPosition(content, secret);

            expect(result).toEqual({ line: 1, column: 17 });
        });

        test('should find secret position in multi-line content', () => {
            const content = 'const config = {\n  apiKey: "secret123",\n  baseUrl: "https://api.example.com"\n};';
            const secret = 'secret123';

            const result = findSecretPosition(content, secret);

            expect(result).toEqual({ line: 2, column: 12 });
        });

        test('should return -1 for line and column when secret not found', () => {
            const content = 'const config = { apiKey: "public" };';
            const secret = 'secret123';

            const result = findSecretPosition(content, secret);

            expect(result).toEqual({ line: -1, column: -1 });
        });

        test('should handle empty content', () => {
            const content = '';
            const secret = 'secret123';

            const result = findSecretPosition(content, secret);

            expect(result).toEqual({ line: -1, column: -1 });
        });

        test('should find first occurrence when secret appears multiple times', () => {
            const content = 'secret123 and secret123 again';
            const secret = 'secret123';

            const result = findSecretPosition(content, secret);

            expect(result).toEqual({ line: 1, column: 1 });
        });
    });
});

describe('Patterns Utilities', () => {
    const mockPatterns: PatternsObj = {
        "AWS Access Key": {
            name: "AWS Access Key",
            familyName: "AWS Access & Secret Keys",
            pattern: /\b((?:AKIA|ABIA|ACCA|AIDA)[A-Z0-9]{16})\b/g,
            entropy: 3.0,
            isValidityCustomizable: false,
            hasCustomValidity: false,
            validityEndpoints: [],
            global: true
        },
        "AWS Secret Key": {
            name: "AWS Secret Key",
            familyName: "AWS Access & Secret Keys",
            pattern: /"([A-Za-z0-9+/]{40})"|(?:[^A-Za-z0-9+/]|^)([A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]|$)/g,
            entropy: 4.25,
            isValidityCustomizable: false,
            hasCustomValidity: false,
            validityEndpoints: [],
            global: true
        }
    };

    describe('serializePatterns', () => {
        test('should convert RegExp patterns to strings', () => {
            const result = serializePatterns(mockPatterns);

            expect(result["AWS Access Key"].pattern).toBe("\\b((?:AKIA|ABIA|ACCA|AIDA)[A-Z0-9]{16})\\b");
            expect(result["AWS Access Key"].global).toBe(true);
        });

        test('should preserve all other properties', () => {
            const result = serializePatterns(mockPatterns);
            expect(result["AWS Access Key"].name).toBe('AWS Access Key');
        });

        test('should handle empty patterns object', () => {
            const result = serializePatterns({});
            expect(result).toEqual({});
        });
    });

    describe('deserializePatterns', () => {
        test('should convert string patterns to RegExp', () => {
            const serialized = serializePatterns(mockPatterns);
            const result = deserializePatterns(serialized);

            expect(result["AWS Access Key"].pattern instanceof RegExp).toBe(true);
            expect(result["AWS Access Key"].pattern.global).toBe(true);
        });

        test('should preserve all other properties', () => {
            const serialized = serializePatterns(mockPatterns);
            const result = deserializePatterns(serialized);

            expect(result["AWS Access Key"].name).toBe('AWS Access Key');
        });

        test('should handle empty serialized patterns', () => {
            const result = deserializePatterns({});
            expect(result).toEqual({});
        });

        test('should create RegExp without "g" flag when global is false', () => {
            const nonGlobalSerialized = {
                "Test Pattern": {
                    name: "Test Pattern",
                    familyName: "Test Family",
                    pattern: "\\d+",
                    entropy: 1.5,
                    isValidityCustomizable: false,
                    hasCustomValidity: false,
                    validityEndpoints: [],
                    global: false
                }
            };

            const result = deserializePatterns(nonGlobalSerialized);

            expect(result["Test Pattern"].pattern instanceof RegExp).toBe(true);
            expect(result["Test Pattern"].pattern.global).toBe(false);
            expect(result["Test Pattern"].pattern.source).toBe("\\d+");
        });
    });

    describe('storePatterns', () => {
        test('should serialize and store patterns in chrome storage', async () => {
            mockChromeStorage.local.set.mockImplementation((data, callback) => {
                callback();
            });

            await storePatterns(mockPatterns);

            expect(mockChromeStorage.local.set).toHaveBeenCalledWith(
                { patterns: serializePatterns(mockPatterns) },
                expect.any(Function)
            );
        });
    });

    describe('retrievePatterns', () => {
        test('should retrieve and deserialize patterns from chrome storage', async () => {
            const serializedPatterns = serializePatterns(mockPatterns);
            mockChromeStorage.local.get.mockImplementation((keys, callback) => {
                callback({ patterns: serializedPatterns });
            });

            const result = await retrievePatterns();

            expect(mockChromeStorage.local.get).toHaveBeenCalledWith(['patterns'], expect.any(Function));
            expect(result["AWS Access Key"].pattern instanceof RegExp).toBe(true);
        });

        test('should return empty object when no patterns in storage', async () => {
            mockChromeStorage.local.get.mockImplementation((keys, callback) => {
                callback({});
            });

            const result = await retrievePatterns();

            expect(result).toEqual({});
        });
    });

    describe('getExistingPatterns', () => {
        test('should return patterns from storage', async () => {
            const serializedPatterns = serializePatterns(mockPatterns);
            mockChromeStorage.local.get.mockImplementation((keys, callback) => {
                callback({ patterns: serializedPatterns });
            });

            const result = await getExistingPatterns();

            expect(result["AWS Access Key"].pattern instanceof RegExp).toBe(true);
        });

        test('should return empty object when no patterns exist', async () => {
            mockChromeStorage.local.get.mockImplementation((keys, callback) => {
                callback({});
            });

            const result = await getExistingPatterns();

            expect(result).toEqual({});
        });
    });
});