import { detectTelegramBotTokens } from './telegram_bot_token';
import { validateTelegramBotTokenCredentials } from '../../../utils/validators/telegram_bot_token/telegram_bot_token';
import { getExistingFindings, findSecretPosition, getSourceMapUrl } from '../../../utils/helpers/common';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';
import * as sourceMap from '../../../../external/source-map';

jest.mock('../../../utils/validators/telegram_bot_token/telegram_bot_token');
jest.mock('../../../utils/helpers/common');
jest.mock('../../../utils/helpers/computeFingerprint');
jest.mock('../../../../external/source-map', () => ({
    SourceMapConsumer: {
        initialize: jest.fn(),
        with: jest.fn()
    }
}));

const mockValidateTelegramBotTokenCredentials = validateTelegramBotTokenCredentials as jest.MockedFunction<typeof validateTelegramBotTokenCredentials>;
const mockGetExistingFindings = getExistingFindings as jest.MockedFunction<typeof getExistingFindings>;
const mockFindSecretPosition = findSecretPosition as jest.MockedFunction<typeof findSecretPosition>;
const mockGetSourceMapUrl = getSourceMapUrl as jest.MockedFunction<typeof getSourceMapUrl>;
const mockComputeFingerprint = computeFingerprint as jest.MockedFunction<typeof computeFingerprint>;

global.fetch = jest.fn();
global.chrome = {
    runtime: {
        getURL: jest.fn().mockReturnValue('chrome-extension://test/libs/mappings.wasm')
    }
} as any;

describe('detectTelegramBotTokens', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        mockGetExistingFindings.mockResolvedValue([]);
        mockComputeFingerprint.mockResolvedValue('test-fingerprint');
        mockFindSecretPosition.mockReturnValue({ line: 1, column: 0 });
        mockGetSourceMapUrl.mockReturnValue(null);
    });

    it('should return empty array when no matches found', async () => {
        const content = 'const config = { apiKey: "not-a-telegram-token" };';
        const url = 'https://example.com/test.js';

        const result = await detectTelegramBotTokens(content, url);

        expect(result).toEqual([]);
    });

    it('should detect valid telegram bot token', async () => {
        const content = 'const botToken = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";';
        const url = 'https://example.com/test.js';

        mockValidateTelegramBotTokenCredentials.mockResolvedValue({
            valid: true,
            type: 'BOT_TOKEN',
            error: null,
            username: 'testbot'
        });

        const result = await detectTelegramBotTokens(content, url);

        expect(result).toHaveLength(1);
        expect(result[0]).toEqual({
            secretType: 'Telegram Bot Token',
            fingerprint: 'test-fingerprint',
            secretValue: {
                match: {
                    bot_token: '123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi'
                }
            },
            filePath: 'test.js',
            url: 'https://example.com/test.js',
            type: 'Bot Token',
            sourceContent: {
                content: JSON.stringify({
                    bot_token: '123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi'
                }),
                contentFilename: 'test.js',
                contentStartLineNum: -1,
                contentEndLineNum: -1,
                exactMatchNumbers: [-1]
            },
            validity: 'valid'
        });

        expect(mockValidateTelegramBotTokenCredentials).toHaveBeenCalledWith(
            '123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi'
        );
    });

    it('should skip invalid telegram bot tokens', async () => {
        const content = 'const botToken = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";';
        const url = 'https://example.com/test.js';

        mockValidateTelegramBotTokenCredentials.mockResolvedValue({
            valid: false,
            type: 'BOT_TOKEN',
            error: 'Invalid token'
        });

        const result = await detectTelegramBotTokens(content, url);

        expect(result).toEqual([]);
        expect(mockValidateTelegramBotTokenCredentials).toHaveBeenCalledWith(
            '123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi'
        );
    });

    it('should handle duplicate tokens', async () => {
        const content = `
            const botToken1 = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";
            const botToken2 = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";
        `;
        const url = 'https://example.com/test.js';

        mockValidateTelegramBotTokenCredentials.mockResolvedValue({
            valid: true,
            type: 'BOT_TOKEN',
            error: null,
            username: 'testbot'
        });

        const result = await detectTelegramBotTokens(content, url);

        expect(result).toHaveLength(1);
        expect(mockValidateTelegramBotTokenCredentials).toHaveBeenCalledTimes(1);
    });

    it('should skip already found tokens', async () => {
        const content = 'const botToken = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";';
        const url = 'https://example.com/test.js';

        mockGetExistingFindings.mockResolvedValue([
            {
                fingerprint: 'existing-fingerprint',
                secretType: 'Telegram Bot Token',
                numOccurrences: 1,
                validity: 'valid',
                discoveredAt: '2023-01-01T00:00:00Z',
                occurrences: new Set(),
                secretValue: {
                    '0': {
                        bot_token: '123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi'
                    }
                }
            }
        ]);

        const result = await detectTelegramBotTokens(content, url);

        expect(result).toEqual([]);
        expect(mockValidateTelegramBotTokenCredentials).not.toHaveBeenCalled();
    });

    it('should handle multiple different tokens', async () => {
        const content = `
            const botToken1 = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";
            const botToken2 = "987654321:ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsr";
        `;
        const url = 'https://example.com/test.js';

        mockValidateTelegramBotTokenCredentials.mockResolvedValue({
            valid: true,
            type: 'BOT_TOKEN',
            error: null,
            username: 'testbot'
        });

        const result = await detectTelegramBotTokens(content, url);

        expect(result).toHaveLength(2);
        expect(mockValidateTelegramBotTokenCredentials).toHaveBeenCalledTimes(2);
    });

    it('should handle source map processing', async () => {
        const content = 'const botToken = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";';
        const url = 'https://example.com/test.js';
        const sourceMapUrl = 'https://example.com/test.js.map';
        const sourceMapContent = '{"version":3,"sources":["original.js"],"mappings":"AAAA"}';
        const originalSource = 'const botToken = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";';

        mockGetSourceMapUrl.mockReturnValue(new URL(sourceMapUrl));
        mockFindSecretPosition.mockReturnValue({ line: 1, column: 20 });

        const mockResponse = {
            text: jest.fn().mockResolvedValue(sourceMapContent)
        };
        (fetch as jest.Mock).mockImplementation((url) => {
            if (typeof url === 'string' || url instanceof URL) {
                return Promise.resolve(mockResponse);
            }
            return Promise.reject(new Error('Invalid URL'));
        });

        const mockConsumer = {
            originalPositionFor: jest.fn().mockReturnValue({
                source: 'original.js',
                line: 1,
                column: 20
            }),
            sourceContentFor: jest.fn().mockReturnValue(originalSource)
        };

        (sourceMap.SourceMapConsumer.with as jest.Mock).mockImplementation((content, options, callback) => {
            callback(mockConsumer);
        });

        mockValidateTelegramBotTokenCredentials.mockResolvedValue({
            valid: true,
            type: 'BOT_TOKEN',
            error: null,
            username: 'testbot'
        });

        const result = await detectTelegramBotTokens(content, url);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent).toEqual({
            content: originalSource,
            contentFilename: 'original.js',
            contentStartLineNum: -4,
            contentEndLineNum: 6,
            exactMatchNumbers: [1]
        });

        expect(sourceMap.SourceMapConsumer.initialize).toHaveBeenCalledWith({
            'lib/mappings.wasm': 'chrome-extension://test/libs/mappings.wasm'
        });
    });

    it('should handle source map processing with null source', async () => {
        const content = 'const botToken = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";';
        const url = 'https://example.com/test.js';
        const sourceMapUrl = 'https://example.com/test.js.map';
        const sourceMapContent = '{"version":3,"sources":["original.js"],"mappings":"AAAA"}';

        mockGetSourceMapUrl.mockReturnValue(new URL(sourceMapUrl));
        mockFindSecretPosition.mockReturnValue({ line: 1, column: 20 });

        const mockResponse = {
            text: jest.fn().mockResolvedValue(sourceMapContent)
        };
        (fetch as jest.Mock).mockImplementation((url) => {
            if (typeof url === 'string' || url instanceof URL) {
                return Promise.resolve(mockResponse);
            }
            return Promise.reject(new Error('Invalid URL'));
        });

        const mockConsumer = {
            originalPositionFor: jest.fn().mockReturnValue({
                source: null,
                line: 1,
                column: 20
            }),
            sourceContentFor: jest.fn().mockReturnValue(null)
        };

        (sourceMap.SourceMapConsumer.with as jest.Mock).mockImplementation((content, options, callback) => {
            callback(mockConsumer);
        });

        mockValidateTelegramBotTokenCredentials.mockResolvedValue({
            valid: true,
            type: 'BOT_TOKEN',
            error: null,
            username: 'testbot'
        });

        const result = await detectTelegramBotTokens(content, url);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent).toEqual({
            content: JSON.stringify({
                bot_token: '123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi'
            }),
            contentFilename: 'test.js',
            contentStartLineNum: -1,
            contentEndLineNum: -1,
            exactMatchNumbers: [-1]
        });
    });

    it('should handle URLs without filename', async () => {
        const content = 'const botToken = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";';
        const url = 'https://example.com/';

        mockValidateTelegramBotTokenCredentials.mockResolvedValue({
            valid: true,
            type: 'BOT_TOKEN',
            error: null,
            username: 'testbot'
        });

        const result = await detectTelegramBotTokens(content, url);

        expect(result).toHaveLength(1);
        expect(result[0].filePath).toBe('');
        expect(result[0].sourceContent.contentFilename).toBe('');
    });

    it('should handle empty URLs', async () => {
        const content = 'const botToken = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";';
        const url = '';

        mockValidateTelegramBotTokenCredentials.mockResolvedValue({
            valid: true,
            type: 'BOT_TOKEN',
            error: null,
            username: 'testbot'
        });

        const result = await detectTelegramBotTokens(content, url);

        expect(result).toHaveLength(1);
        expect(result[0].filePath).toBe('');
        expect(result[0].sourceContent.contentFilename).toBe('');
    });

    it('should handle URLs that split to empty array', async () => {
        const content = 'const botToken = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";';
        // Mock url.split to return empty array to test the || "" fallback
        const originalSplit = String.prototype.split;
        String.prototype.split = jest.fn().mockReturnValue([]);
        
        const url = 'test-url';

        mockValidateTelegramBotTokenCredentials.mockResolvedValue({
            valid: true,
            type: 'BOT_TOKEN',
            error: null,
            username: 'testbot'
        });

        const result = await detectTelegramBotTokens(content, url);

        expect(result).toHaveLength(1);
        expect(result[0].filePath).toBe('');
        expect(result[0].sourceContent.contentFilename).toBe('');
        
        // Restore original split
        String.prototype.split = originalSplit;
    });

    it('should handle regex pattern matching correctly', async () => {
        const testCases = [
            { token: '123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi', shouldMatch: true },
            { token: '1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi', shouldMatch: true },
            { token: '12345678:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi', shouldMatch: true },
            { token: '1234567:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh', shouldMatch: false },
            { token: '12345678901:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg', shouldMatch: false },
            { token: '123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg', shouldMatch: false },
            { token: '123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij', shouldMatch: false }
        ];

        for (const testCase of testCases) {
            const content = `const botToken = "${testCase.token}";`;
            const url = 'https://example.com/test.js';

            mockValidateTelegramBotTokenCredentials.mockResolvedValue({
                valid: true,
                type: 'BOT_TOKEN',
                error: null,
                username: 'testbot'
            });

            const result = await detectTelegramBotTokens(content, url);

            if (testCase.shouldMatch) {
                expect(result).toHaveLength(1);
                expect((result[0] as any).secretValue.match.bot_token).toBe(testCase.token);
            } else {
                expect(result).toHaveLength(0);
            }
        }
    });
});