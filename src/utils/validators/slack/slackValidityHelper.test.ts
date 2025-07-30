import { slackValidityHelper } from './slackValidityHelper';
import { validateSlackToken } from './slack';
import { retrieveFindings, storeFindings } from '../../helpers/common';
import { Finding } from '../../../types/findings.types';

jest.mock('./slack');
jest.mock('../../helpers/common');

const mockValidateSlackToken = validateSlackToken as jest.MockedFunction<typeof validateSlackToken>;
const mockRetrieveFindings = retrieveFindings as jest.MockedFunction<typeof retrieveFindings>;
const mockStoreFindings = storeFindings as jest.MockedFunction<typeof storeFindings>;

describe('slackValidityHelper', () => {
    const mockFinding: Finding = {
        secretType: 'Slack',
        fingerprint: 'test-fingerprint',
        secretValue: {
            'token1': {
                token: 'xoxb-1234567890-1234567890-test-token'
            }
        },
        numOccurrences: 1,
        occurrences: new Set(),
        validity: 'unknown'
    };

    const mockExistingFindings: Finding[] = [
        {
            ...mockFinding,
            validity: 'unknown'
        }
    ];

    beforeEach(() => {
        jest.clearAllMocks();
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);
    });

    it('should mark finding as invalid when validation fails', async () => {
        mockValidateSlackToken.mockResolvedValue({
            valid: false,
            error: 'Invalid token'
        });

        await slackValidityHelper(mockFinding);

        expect(mockValidateSlackToken).toHaveBeenCalledWith('xoxb-1234567890-1234567890-test-token');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...mockFinding,
                validity: 'invalid',
                validatedAt: expect.any(String)
            }
        ]);
    });

    it('should mark finding as valid when validation succeeds and was previously invalid', async () => {
        const invalidFinding = { ...mockFinding, validity: 'invalid' as const };
        mockRetrieveFindings.mockResolvedValue([invalidFinding]);
        mockValidateSlackToken.mockResolvedValue({
            valid: true,
            team: 'Test Team',
            user: 'test-user'
        });

        await slackValidityHelper(invalidFinding);

        expect(mockValidateSlackToken).toHaveBeenCalledWith('xoxb-1234567890-1234567890-test-token');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...invalidFinding,
                validity: 'valid',
                validatedAt: expect.any(String)
            }
        ]);
    });

    it('should update timestamp when validation succeeds and was already valid', async () => {
        const validFinding = { ...mockFinding, validity: 'valid' as const };
        mockRetrieveFindings.mockResolvedValue([validFinding]);
        mockValidateSlackToken.mockResolvedValue({
            valid: true,
            team: 'Test Team',
            user: 'test-user'
        });

        await slackValidityHelper(validFinding);

        expect(mockValidateSlackToken).toHaveBeenCalledWith('xoxb-1234567890-1234567890-test-token');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...validFinding,
                validity: 'valid',
                validatedAt: expect.any(String)
            }
        ]);
    });

    it('should handle multiple secret values and stop on first invalid', async () => {
        const multiSecretFinding: Finding = {
            ...mockFinding,
            secretValue: {
                'token1': {
                    token: 'xoxb-1234567890-1234567890-test-token1'
                },
                'token2': {
                    token: 'xoxb-1234567890-1234567890-test-token2'
                }
            }
        };
        mockRetrieveFindings.mockResolvedValue([multiSecretFinding]);
        mockValidateSlackToken.mockResolvedValue({
            valid: false,
            error: 'Invalid token'
        });

        await slackValidityHelper(multiSecretFinding);

        expect(mockValidateSlackToken).toHaveBeenCalledTimes(1);
        expect(mockValidateSlackToken).toHaveBeenCalledWith('xoxb-1234567890-1234567890-test-token1');
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...multiSecretFinding,
                validity: 'invalid',
                validatedAt: expect.any(String)
            }
        ]);
    });

    it('should handle case when finding is not found in existing findings', async () => {
        mockRetrieveFindings.mockResolvedValue([]);
        mockValidateSlackToken.mockResolvedValue({
            valid: false,
            error: 'Invalid token'
        });

        await slackValidityHelper(mockFinding);

        expect(mockValidateSlackToken).toHaveBeenCalledWith('xoxb-1234567890-1234567890-test-token');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    it('should handle multiple secret values and continue to valid processing', async () => {
        const multiSecretFinding: Finding = {
            ...mockFinding,
            secretValue: {
                'token1': {
                    token: 'xoxb-1234567890-1234567890-test-token1'
                }
            }
        };
        mockRetrieveFindings.mockResolvedValue([multiSecretFinding]);
        mockValidateSlackToken.mockResolvedValue({
            valid: true,
            team: 'Test Team'
        });

        await slackValidityHelper(multiSecretFinding);

        expect(mockValidateSlackToken).toHaveBeenCalledTimes(1);
        expect(mockValidateSlackToken).toHaveBeenCalledWith('xoxb-1234567890-1234567890-test-token1');
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...multiSecretFinding,
                validity: 'valid',
                validatedAt: expect.any(String)
            }
        ]);
    });
});