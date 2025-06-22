import { Finding } from '../../../types/findings.types';
import { openaiValidityHelper } from './openaiValidityHelper';
import * as validateOpenAI from './openai';
import * as common from '../../helpers/common';

jest.mock('./openai');
jest.mock('../../helpers/common');

describe('openaiValidityHelper', () => {
    const mockRetrieveFindings = common.retrieveFindings as jest.MockedFunction<typeof common.retrieveFindings>;
    const mockStoreFindings = common.storeFindings as jest.MockedFunction<typeof common.storeFindings>;
    const mockValidateOpenAICredentials = validateOpenAI.validateOpenAICredentials as jest.MockedFunction<typeof validateOpenAI.validateOpenAICredentials>;

    const mockFinding: Finding = {
        fingerprint: 'test-fingerprint',
        numOccurrences: 1,
        secretType: 'OpenAI',
        secretValue: {
            match: { api_key: 'sk-test123T3BlbkFJtest456' }
        },
        validity: 'valid',
        validatedAt: '2025-05-17T18:16:16.870Z',
        occurrences: new Set()
    };

    const mockExistingFindings: Finding[] = [
        {
            ...mockFinding,
            fingerprint: 'test-fingerprint'
        }
    ];

    beforeEach(() => {
        jest.clearAllMocks();
        mockRetrieveFindings.mockResolvedValue(mockExistingFindings);
    });

    test('marks finding as invalid when validation fails', async () => {
        mockValidateOpenAICredentials.mockResolvedValue({
            valid: false,
            type: 'unknown',
            error: 'Invalid API key'
        });

        await openaiValidityHelper(mockFinding);

        expect(mockValidateOpenAICredentials).toHaveBeenCalledWith('sk-test123T3BlbkFJtest456');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        
        // Wait for the promise to resolve
        await new Promise(process.nextTick);
        
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...mockFinding,
                validity: 'invalid',
                validatedAt: expect.any(String)
            }
        ]);
    });

    test('re-activates previously invalid finding when validation succeeds', async () => {
        const invalidFinding = {
            ...mockFinding,
            validity: 'invalid' as const
        };

        mockValidateOpenAICredentials.mockResolvedValue({
            valid: true,
            type: 'USER',
            error: '',
            id: 'user-123'
        });

        await openaiValidityHelper(invalidFinding);

        expect(mockValidateOpenAICredentials).toHaveBeenCalledWith('sk-test123T3BlbkFJtest456');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        
        // Wait for the promise to resolve
        await new Promise(process.nextTick);
        
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...mockFinding,
                validity: 'valid',
                validatedAt: expect.any(String)
            }
        ]);
    });

    test('updates timestamp for valid finding that remains valid', async () => {
        mockValidateOpenAICredentials.mockResolvedValue({
            valid: true,
            type: 'USER',
            error: '',
            id: 'user-456'
        });

        await openaiValidityHelper(mockFinding);

        expect(mockValidateOpenAICredentials).toHaveBeenCalledWith('sk-test123T3BlbkFJtest456');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        
        // Wait for the promise to resolve
        await new Promise(process.nextTick);
        
        expect(mockStoreFindings).toHaveBeenCalledWith([
            {
                ...mockFinding,
                validity: 'valid',
                validatedAt: expect.any(String)
            }
        ]);
    });

    test('skips validation when secretValue has no api_key', async () => {
        const findingWithoutApiKey: Finding = {
            ...mockFinding,
            secretValue: {
                match: { other_key: 'some-value' }
            }
        };

        await openaiValidityHelper(findingWithoutApiKey);

        expect(mockValidateOpenAICredentials).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    test('handles multiple secretValue entries and processes first valid one', async () => {
        const findingWithMultipleSecrets: Finding = {
            ...mockFinding,
            secretValue: {
                match1: { other_key: 'no-api-key' },
                match2: { api_key: 'sk-valid123T3BlbkFJtest789' },
                match3: { api_key: 'sk-another123T3BlbkFJtest000' }
            }
        };

        mockValidateOpenAICredentials.mockResolvedValue({
            valid: false,
            type: 'unknown',
            error: 'Invalid API key'
        });

        await openaiValidityHelper(findingWithMultipleSecrets);

        expect(mockValidateOpenAICredentials).toHaveBeenCalledWith('sk-valid123T3BlbkFJtest789');
        expect(mockValidateOpenAICredentials).toHaveBeenCalledTimes(1); // Should break after first failure
    });

    test('handles case when finding is not found in existing findings', async () => {
        mockRetrieveFindings.mockResolvedValue([]);
        
        mockValidateOpenAICredentials.mockResolvedValue({
            valid: false,
            type: 'unknown',
            error: 'Invalid API key'
        });

        await openaiValidityHelper(mockFinding);

        expect(mockValidateOpenAICredentials).toHaveBeenCalledWith('sk-test123T3BlbkFJtest456');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        
        // Wait for the promise to resolve
        await new Promise(process.nextTick);
        
        // Should not call storeFindings since finding wasn't found
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    test('handles empty secretValue object', async () => {
        const findingWithEmptySecretValue: Finding = {
            ...mockFinding,
            secretValue: {}
        };

        await openaiValidityHelper(findingWithEmptySecretValue);

        expect(mockValidateOpenAICredentials).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });
});