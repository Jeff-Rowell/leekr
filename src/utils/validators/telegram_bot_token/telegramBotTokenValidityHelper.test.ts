import { telegramBotTokenValidityHelper } from './telegramBotTokenValidityHelper';
import { validateTelegramBotTokenCredentials } from './telegram_bot_token';
import { retrieveFindings, storeFindings } from '../../helpers/common';
import { Finding } from '../../../types/findings.types';

jest.mock('./telegram_bot_token');
jest.mock('../../helpers/common');

const mockValidateTelegramBotTokenCredentials = validateTelegramBotTokenCredentials as jest.MockedFunction<typeof validateTelegramBotTokenCredentials>;
const mockRetrieveFindings = retrieveFindings as jest.MockedFunction<typeof retrieveFindings>;
const mockStoreFindings = storeFindings as jest.MockedFunction<typeof storeFindings>;

describe('telegramBotTokenValidityHelper', () => {
    const mockFinding: Finding = {
        fingerprint: 'test-fingerprint',
        secretType: 'Telegram Bot Token',
        numOccurrences: 1,
        validity: 'unknown',
        discoveredAt: '2023-01-01T00:00:00Z',
        occurrences: new Set(),
        secretValue: {
            '0': {
                bot_token: '123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi'
            }
        }
    };

    const mockExistingFindings: Finding[] = [
        {
            fingerprint: 'test-fingerprint',
            secretType: 'Telegram Bot Token',
            numOccurrences: 1,
            validity: 'unknown',
            discoveredAt: '2023-01-01T00:00:00Z',
            occurrences: new Set(),
            secretValue: {
                '0': {
                    bot_token: '123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi'
                }
            }
        }
    ];

    beforeEach(() => {
        jest.clearAllMocks();
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);
        mockStoreFindings.mockResolvedValue();
    });

    it('should mark finding as invalid when validation fails', async () => {
        mockValidateTelegramBotTokenCredentials.mockResolvedValue({
            valid: false,
            type: 'BOT_TOKEN',
            error: 'Invalid token'
        });

        await telegramBotTokenValidityHelper(mockFinding);

        expect(mockValidateTelegramBotTokenCredentials).toHaveBeenCalledWith(
            '123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi'
        );
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...mockExistingFindings[0],
                validity: 'invalid',
                validatedAt: expect.any(String)
            }
        ]);
    });

    it('should mark finding as valid when validation succeeds and finding was previously invalid', async () => {
        const invalidFinding = {
            ...mockFinding,
            validity: 'invalid' as const
        };

        mockValidateTelegramBotTokenCredentials.mockResolvedValue({
            valid: true,
            type: 'BOT_TOKEN',
            error: null,
            username: 'testbot'
        });

        await telegramBotTokenValidityHelper(invalidFinding);

        expect(mockValidateTelegramBotTokenCredentials).toHaveBeenCalledWith(
            '123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi'
        );
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...mockExistingFindings[0],
                validity: 'valid',
                validatedAt: expect.any(String)
            }
        ]);
    });

    it('should mark finding as valid when validation succeeds and finding was not previously invalid', async () => {
        mockValidateTelegramBotTokenCredentials.mockResolvedValue({
            valid: true,
            type: 'BOT_TOKEN',
            error: null,
            username: 'testbot'
        });

        await telegramBotTokenValidityHelper(mockFinding);

        expect(mockValidateTelegramBotTokenCredentials).toHaveBeenCalledWith(
            '123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi'
        );
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...mockExistingFindings[0],
                validity: 'valid',
                validatedAt: expect.any(String)
            }
        ]);
    });

    it('should skip validation when bot_token is not present', async () => {
        const findingWithoutToken = {
            ...mockFinding,
            secretValue: {
                '0': {}
            }
        };

        await telegramBotTokenValidityHelper(findingWithoutToken);

        expect(mockValidateTelegramBotTokenCredentials).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    it('should handle multiple secret values', async () => {
        const multiSecretFinding = {
            ...mockFinding,
            secretValue: {
                '0': {
                    bot_token: '123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi'
                },
                '1': {
                    bot_token: '987654321:ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrq'
                }
            }
        };

        mockValidateTelegramBotTokenCredentials.mockResolvedValue({
            valid: false,
            type: 'BOT_TOKEN',
            error: 'Invalid token'
        });

        await telegramBotTokenValidityHelper(multiSecretFinding);

        expect(mockValidateTelegramBotTokenCredentials).toHaveBeenCalledWith(
            '123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi'
        );
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...mockExistingFindings[0],
                validity: 'invalid',
                validatedAt: expect.any(String)
            }
        ]);
    });

    it('should handle case where finding is not found in existing findings', async () => {
        mockRetrieveFindings.mockResolvedValue([]);
        mockValidateTelegramBotTokenCredentials.mockResolvedValue({
            valid: false,
            type: 'BOT_TOKEN',
            error: 'Invalid token'
        });

        await telegramBotTokenValidityHelper(mockFinding);

        expect(mockValidateTelegramBotTokenCredentials).toHaveBeenCalledWith(
            '123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi'
        );
        expect(mockRetrieveFindings).toHaveBeenCalled();
        // Should not call storeFindings when finding is not found
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });
});