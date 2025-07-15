import { TelegramBotTokenDetector } from './TelegramBotTokenDetector';
import { detectTelegramBotTokens } from './telegram_bot_token';
import { patterns } from '../../../config/patterns';

jest.mock('./telegram_bot_token');

const mockDetectTelegramBotTokens = detectTelegramBotTokens as jest.MockedFunction<typeof detectTelegramBotTokens>;

describe('TelegramBotTokenDetector', () => {
    let detector: TelegramBotTokenDetector;

    beforeEach(() => {
        detector = new TelegramBotTokenDetector();
        jest.clearAllMocks();
    });

    it('should have correct type', () => {
        expect(detector.type).toBe('telegram_bot_token');
    });

    it('should have correct name from patterns', () => {
        expect(detector.name).toBe(patterns['Telegram Bot Token'].familyName);
    });

    it('should call detectTelegramBotTokens with correct parameters', async () => {
        const content = 'const botToken = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";';
        const url = 'https://example.com/test.js';

        const expectedResult = [
            {
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
            }
        ];

        mockDetectTelegramBotTokens.mockResolvedValue(expectedResult);

        const result = await detector.detect(content, url);

        expect(mockDetectTelegramBotTokens).toHaveBeenCalledWith(content, url);
        expect(result).toEqual(expectedResult);
    });

    it('should return empty array when no tokens found', async () => {
        const content = 'const config = { apiKey: "not-a-telegram-token" };';
        const url = 'https://example.com/test.js';

        mockDetectTelegramBotTokens.mockResolvedValue([]);

        const result = await detector.detect(content, url);

        expect(mockDetectTelegramBotTokens).toHaveBeenCalledWith(content, url);
        expect(result).toEqual([]);
    });

    it('should handle multiple tokens', async () => {
        const content = `
            const botToken1 = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";
            const botToken2 = "987654321:ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrq";
        `;
        const url = 'https://example.com/test.js';

        const expectedResult = [
            {
                secretType: 'Telegram Bot Token',
                fingerprint: 'test-fingerprint-1',
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
            },
            {
                secretType: 'Telegram Bot Token',
                fingerprint: 'test-fingerprint-2',
                secretValue: {
                    match: {
                        bot_token: '987654321:ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrq'
                    }
                },
                filePath: 'test.js',
                url: 'https://example.com/test.js',
                type: 'Bot Token',
                sourceContent: {
                    content: JSON.stringify({
                        bot_token: '987654321:ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrq'
                    }),
                    contentFilename: 'test.js',
                    contentStartLineNum: -1,
                    contentEndLineNum: -1,
                    exactMatchNumbers: [-1]
                },
                validity: 'valid'
            }
        ];

        mockDetectTelegramBotTokens.mockResolvedValue(expectedResult);

        const result = await detector.detect(content, url);

        expect(mockDetectTelegramBotTokens).toHaveBeenCalledWith(content, url);
        expect(result).toEqual(expectedResult);
    });

    it('should handle errors thrown by detectTelegramBotTokens', async () => {
        const content = 'const botToken = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";';
        const url = 'https://example.com/test.js';

        const error = new Error('Network error');
        mockDetectTelegramBotTokens.mockRejectedValue(error);

        await expect(detector.detect(content, url)).rejects.toThrow('Network error');
        expect(mockDetectTelegramBotTokens).toHaveBeenCalledWith(content, url);
    });
});