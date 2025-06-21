import { AnthropicOccurrence, AnthropicSecretValue } from 'src/types/anthropic';
import { Finding, Occurrence } from 'src/types/findings.types';
import * as common from '../../../utils/helpers/common';
import * as helpers from '../../../utils/helpers/computeFingerprint';
import * as anthropicValidator from '../../../utils/validators/anthropic/anthropic';
import { detectAnthropicKeys } from './anthropic';

jest.mock('../../../utils/validators/anthropic/anthropic');
jest.mock('../../../utils/helpers/common');
jest.mock('../../../utils/helpers/computeFingerprint');
jest.mock('../../../../external/source-map');

global.fetch = jest.fn();
global.chrome = {
    runtime: {
        getURL: jest.fn((path: string) => `chrome-extension://extension-id/${path}`)
    }
} as any;

describe('detectAnthropicKeys', () => {
    const fakeApiKey = 'sk-ant-api03-' + 'A'.repeat(93) + 'AA';
    const fakeAdminKey = 'sk-ant-admin01-' + 'B'.repeat(93) + 'AA';
    const fakeUrl = 'https://example.com/app.js';

    const mockAnthropicOccurrence: AnthropicOccurrence = {
        filePath: "app.js",
        fingerprint: "fp1",
        type: "API Key",
        secretType: "Anthropic AI",
        secretValue: {
            match: { api_key: fakeApiKey }
        },
        sourceContent: {
            content: JSON.stringify({ api_key: fakeApiKey }),
            contentEndLineNum: -1,
            contentFilename: "app.js",
            contentStartLineNum: -1,
            exactMatchNumbers: [-1]
        },
        url: fakeUrl,
        validity: "valid"
    };

    const mockOccurrences: Set<Occurrence> = new Set([mockAnthropicOccurrence]);

    const mockFindings: Finding[] = [
        {
            fingerprint: "fp1",
            numOccurrences: mockOccurrences.size,
            occurrences: mockOccurrences,
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "Anthropic AI",
            secretValue: {
                match: { api_key: fakeApiKey },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        }
    ];

    beforeEach(() => {
        jest.clearAllMocks();
        jest.spyOn(common, 'getExistingFindings').mockResolvedValue([]);
        jest.spyOn(common, 'findSecretPosition').mockReturnValue({ line: 10, column: 5 });
        jest.spyOn(common, 'getSourceMapUrl').mockReturnValue(null);
        jest.spyOn(helpers, 'computeFingerprint').mockResolvedValue('mocked-fingerprint');
        jest.spyOn(anthropicValidator, 'validateAnthropicCredentials').mockResolvedValue({
            valid: true,
            type: 'USER',
            error: ''
        });
    });

    test('returns empty array if no Anthropic API keys are found', async () => {
        const result = await detectAnthropicKeys('no keys here', fakeUrl);
        expect(result).toEqual([]);
    });

    test('returns empty array if API key does not match pattern', async () => {
        const content = 'invalid-key-format';
        const result = await detectAnthropicKeys(content, fakeUrl);
        expect(result).toEqual([]);
    });

    test('filters out keys already in existing findings', async () => {
        jest.spyOn(common, 'getExistingFindings').mockResolvedValue([{
            secretType: 'Anthropic AI',
            secretValue: {
                match: { api_key: fakeApiKey }
            },
            numOccurrences: 1,
            fingerprint: 'existing-fp',
            validity: 'valid',
            occurrences: new Set()
        }]);

        const content = `const apiKey = "${fakeApiKey}";`;
        const result = await detectAnthropicKeys(content, fakeUrl);
        expect(result).toEqual([]);
    });

    test('returns empty array when credentials validation fails', async () => {
        jest.spyOn(anthropicValidator, 'validateAnthropicCredentials').mockResolvedValue({
            valid: false,
            type: 'unknown',
            error: 'Invalid API key'
        });

        const content = `const apiKey = "${fakeApiKey}";`;
        const result = await detectAnthropicKeys(content, fakeUrl);
        expect(result).toEqual([]);
    });

    test('returns valid occurrence when credentials are valid and not in existing findings', async () => {
        const content = `const apiKey = "${fakeApiKey}";`;

        jest.spyOn(anthropicValidator, 'validateAnthropicCredentials').mockResolvedValue({
            valid: true,
            type: 'USER',
            error: ''
        });

        const result = await detectAnthropicKeys(content, fakeUrl);

        expect(result).toHaveLength(1);
        expect(result[0]).toMatchObject({
            secretType: 'Anthropic AI',
            secretValue: {
                match: {
                    api_key: fakeApiKey
                }
            },
            validity: 'valid',
            type: 'API Key',
            filePath: 'app.js',
            url: fakeUrl,
            fingerprint: 'mocked-fingerprint'
        });
    });

    test('returns valid occurrence with ADMIN type for admin keys', async () => {
        const content = `const adminKey = "${fakeAdminKey}";`;

        jest.spyOn(anthropicValidator, 'validateAnthropicCredentials').mockResolvedValue({
            valid: true,
            type: 'ADMIN',
            error: ''
        });

        const result = await detectAnthropicKeys(content, fakeUrl);

        expect(result).toHaveLength(1);
        expect(result[0]).toMatchObject({
            secretType: 'Anthropic AI',
            secretValue: {
                match: {
                    api_key: fakeAdminKey
                }
            },
            validity: 'valid',
            type: 'Admin API Key',
            filePath: 'app.js',
            url: fakeUrl
        });
    });

    test('handles multiple API keys in content', async () => {
        const anotherApiKey = 'sk-ant-api03-' + 'C'.repeat(93) + 'AA';
        const content = `
            const apiKey1 = "${fakeApiKey}";
            const apiKey2 = "${anotherApiKey}";
        `;

        jest.spyOn(anthropicValidator, 'validateAnthropicCredentials')
            .mockResolvedValueOnce({
                valid: true,
                type: 'USER',
                error: ''
            })
            .mockResolvedValueOnce({
                valid: true,
                type: 'USER',
                error: ''
            });

        const result = await detectAnthropicKeys(content, fakeUrl);

        expect(result).toHaveLength(2);
        expect((result[0].secretValue as AnthropicSecretValue).match.api_key).toBe(fakeApiKey);
        expect((result[1].secretValue as AnthropicSecretValue).match.api_key).toBe(anotherApiKey);
    });

    test('handles source map processing when source map is available', async () => {
        const content = `const apiKey = "${fakeApiKey}";`;
        const mockSourceMapUrl = new URL('https://example.com/app.js.map');

        jest.spyOn(common, 'getSourceMapUrl').mockReturnValue(mockSourceMapUrl);
        jest.spyOn(common, 'findSecretPosition').mockReturnValue({ line: 25, column: 10 });

        (global.fetch as jest.Mock).mockResolvedValue({
            text: () => Promise.resolve('{"version":3,"sources":["App.tsx"],"sourcesContent":["console.log(\\"hello\\");"]}'),
        });

        const sourceContent = 'console.log("hello");';
        const withMock = jest.fn((_content, _null, callback) => {
            callback({
                originalPositionFor: jest.fn(() => ({
                    source: 'App.tsx',
                    line: 100,
                    column: 15
                })),
                sourceContentFor: jest.fn().mockReturnValue(sourceContent),
            });
        });

        const sourceMapModule = require('../../../../external/source-map');
        sourceMapModule.SourceMapConsumer.with = withMock;
        sourceMapModule.SourceMapConsumer.initialize = jest.fn();

        const result = await detectAnthropicKeys(content, fakeUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent).toMatchObject({
            content: sourceContent,
            contentFilename: 'App.tsx',
            exactMatchNumbers: [100],
            contentStartLineNum: 95,
            contentEndLineNum: 105,
        });
        expect(sourceMapModule.SourceMapConsumer.initialize).toHaveBeenCalledWith({
            'lib/mappings.wasm': 'chrome-extension://extension-id/libs/mappings.wasm'
        });
    });

    test('handles source map processing when originalPosition source is null', async () => {
        const content = `const apiKey = "${fakeApiKey}";`;
        const mockSourceMapUrl = new URL('https://example.com/app.js.map');

        jest.spyOn(common, 'getSourceMapUrl').mockReturnValue(mockSourceMapUrl);

        (global.fetch as jest.Mock).mockResolvedValue({
            text: () => Promise.resolve('{"version":3,"sources":["App.tsx"]}'),
        });

        const withMock = jest.fn((_content, _null, callback) => {
            callback({
                originalPositionFor: jest.fn(() => ({
                    source: null,
                    line: null,
                    column: null
                })),
                sourceContentFor: jest.fn(),
            });
        });

        const sourceMapModule = require('../../../../external/source-map');
        sourceMapModule.SourceMapConsumer.with = withMock;
        sourceMapModule.SourceMapConsumer.initialize = jest.fn();

        const result = await detectAnthropicKeys(content, fakeUrl);

        expect(result).toHaveLength(1);
        // Should use default source content when originalPosition.source is null
        expect(result[0].sourceContent).toMatchObject({
            content: JSON.stringify({ api_key: fakeApiKey }),
            contentFilename: 'app.js',
            contentStartLineNum: -1,
            contentEndLineNum: -1,
            exactMatchNumbers: [-1]
        });
    });

    test('sets contentFilename to empty string when url is empty', async () => {
        const url = '';
        const content = `const apiKey = "${fakeApiKey}";`;

        const result = await detectAnthropicKeys(content, url);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe('');
        expect(result[0].filePath).toBe('');
    });

    test('handles complex filtering scenario with mixed valid and existing keys', async () => {
        const existingKey = fakeApiKey;
        const newValidKey = 'sk-ant-api03-' + 'D'.repeat(93) + 'AA';
        const invalidKey = 'sk-ant-api03-' + 'E'.repeat(93) + 'AA';

        const content = `
            const existingKey = "${existingKey}";
            const newValidKey = "${newValidKey}";
            const invalidKey = "${invalidKey}";
        `;

        // Mock existing findings to include the first key
        jest.spyOn(common, 'getExistingFindings').mockResolvedValue([{
            secretType: 'Anthropic AI',
            secretValue: {
                match: { api_key: existingKey }
            },
            numOccurrences: 1,
            fingerprint: 'existing-fp',
            validity: 'valid',
            occurrences: new Set()
        }]);

        // Mock validation responses
        jest.spyOn(anthropicValidator, 'validateAnthropicCredentials')
            .mockImplementation(async (apiKey: string) => {
                if (apiKey === newValidKey) {
                    return { valid: true, type: 'USER', error: '' };
                } else if (apiKey === invalidKey) {
                    return { valid: false, type: 'unknown', error: 'Invalid key' };
                }
                return { valid: false, type: 'unknown', error: 'Unknown key' };
            });

        const result = await detectAnthropicKeys(content, fakeUrl);

        expect(result).toHaveLength(1);
        expect((result[0].secretValue as AnthropicSecretValue).match.api_key).toBe(newValidKey);
        expect(anthropicValidator.validateAnthropicCredentials).toHaveBeenCalledTimes(2); // Called for newValidKey and invalidKey, but not existingKey
    });

    test('handles edge case with no valid occurrences', async () => {
        const content = `const apiKey = "${fakeApiKey}";`;

        jest.spyOn(anthropicValidator, 'validateAnthropicCredentials').mockResolvedValue({
            valid: false,
            type: 'unknown',
            error: 'All keys invalid'
        });

        const result = await detectAnthropicKeys(content, fakeUrl);

        expect(result).toEqual([]);
    });
});