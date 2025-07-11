import { deepaiValidityHelper } from './deepaiValidityHelper';
import { validateDeepAIApiKey } from './deepai';
import { retrieveFindings, storeFindings } from '../../helpers/common';
import { Finding } from '../../../types/findings.types';
import { DeepAIOccurrence } from '../../../types/deepai';

jest.mock('./deepai');
jest.mock('../../helpers/common');

const mockValidateDeepAIApiKey = validateDeepAIApiKey as jest.MockedFunction<typeof validateDeepAIApiKey>;
const mockRetrieveFindings = retrieveFindings as jest.MockedFunction<typeof retrieveFindings>;
const mockStoreFindings = storeFindings as jest.MockedFunction<typeof storeFindings>;

describe('deepaiValidityHelper', () => {
    const mockDate = '2023-01-01T00:00:00.000Z';
    
    beforeEach(() => {
        jest.clearAllMocks();
        jest.spyOn(Date.prototype, 'toISOString').mockReturnValue(mockDate);
        jest.spyOn(console, 'error').mockImplementation(() => {});
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    const createMockFinding = (validity?: string): Finding => ({
        fingerprint: 'test-fingerprint',
        secretType: 'DeepAI' as any,
        numOccurrences: 1,
        validity: validity as any,
        validatedAt: undefined,
        secretValue: {
            match: {
                apiKey: 'abcd1234-5678-90ab-cdef-123456789012'
            }
        } as DeepAIOccurrence['secretValue'],
        occurrences: new Set([])
    });

    test('should handle valid API key validation', async () => {
        const finding = createMockFinding();
        const existingFindings = [finding];

        mockValidateDeepAIApiKey.mockResolvedValue({
            valid: true,
            response: { id: 'test-id', output: { tag: 'positive' } }
        });
        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await deepaiValidityHelper(finding);

        expect(mockValidateDeepAIApiKey).toHaveBeenCalledWith('abcd1234-5678-90ab-cdef-123456789012');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([{
            ...finding,
            validity: 'valid',
            validatedAt: mockDate,
            secretValue: {
                ...finding.secretValue,
                validity: 'valid',
                validatedAt: mockDate
            }
        }]);
    });

    test('should handle invalid API key validation', async () => {
        const finding = createMockFinding();
        const existingFindings = [finding];

        mockValidateDeepAIApiKey.mockResolvedValue({
            valid: false,
            error: 'Invalid API key'
        });
        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await deepaiValidityHelper(finding);

        expect(mockValidateDeepAIApiKey).toHaveBeenCalledWith('abcd1234-5678-90ab-cdef-123456789012');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([{
            ...finding,
            validity: 'invalid',
            validatedAt: mockDate,
            secretValue: {
                ...finding.secretValue,
                validity: 'invalid',
                validatedAt: mockDate
            }
        }]);
    });

    test('should update previously invalid finding to valid', async () => {
        const finding = createMockFinding('invalid');
        const existingFindings = [finding];

        mockValidateDeepAIApiKey.mockResolvedValue({
            valid: true,
            response: { id: 'test-id', output: { tag: 'positive' } }
        });
        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await deepaiValidityHelper(finding);

        expect(mockValidateDeepAIApiKey).toHaveBeenCalledWith('abcd1234-5678-90ab-cdef-123456789012');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([{
            ...finding,
            validity: 'valid',
            validatedAt: mockDate,
            secretValue: {
                ...finding.secretValue,
                validity: 'valid',
                validatedAt: mockDate
            }
        }]);
    });

    test('should handle validation error', async () => {
        const finding = createMockFinding();
        const existingFindings = [finding];

        mockValidateDeepAIApiKey.mockRejectedValue(new Error('Network error'));
        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await deepaiValidityHelper(finding);

        expect(mockValidateDeepAIApiKey).toHaveBeenCalledWith('abcd1234-5678-90ab-cdef-123456789012');
        expect(console.error).toHaveBeenCalledWith('Error validating DeepAI API key:', expect.any(Error));
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([{
            ...finding,
            validity: 'failed_to_check',
            validatedAt: mockDate,
            secretValue: {
                ...finding.secretValue,
                validity: 'failed_to_check',
                validatedAt: mockDate
            }
        }]);
    });

    test('should handle missing API key in finding', async () => {
        const finding = createMockFinding();
        finding.secretValue = { match: {} } as any;

        await deepaiValidityHelper(finding);

        expect(console.error).toHaveBeenCalledWith('No API key found in finding');
        expect(mockValidateDeepAIApiKey).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    test('should handle finding not found in existing findings', async () => {
        const finding = createMockFinding();
        const existingFindings: Finding[] = [];

        mockValidateDeepAIApiKey.mockResolvedValue({
            valid: true,
            response: { id: 'test-id', output: { tag: 'positive' } }
        });
        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await deepaiValidityHelper(finding);

        expect(mockValidateDeepAIApiKey).toHaveBeenCalledWith('abcd1234-5678-90ab-cdef-123456789012');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    test('should handle multiple findings with same fingerprint', async () => {
        const finding = createMockFinding();
        const otherFinding = createMockFinding();
        otherFinding.fingerprint = 'other-fingerprint';
        const existingFindings = [otherFinding, finding];

        mockValidateDeepAIApiKey.mockResolvedValue({
            valid: false,
            error: 'Invalid API key'
        });
        mockRetrieveFindings.mockResolvedValue(existingFindings);

        await deepaiValidityHelper(finding);

        expect(mockValidateDeepAIApiKey).toHaveBeenCalledWith('abcd1234-5678-90ab-cdef-123456789012');
        expect(mockRetrieveFindings).toHaveBeenCalled();
        expect(mockStoreFindings).toHaveBeenCalledWith([
            otherFinding,
            {
                ...finding,
                validity: 'invalid',
                validatedAt: mockDate,
                secretValue: {
                    ...finding.secretValue,
                    validity: 'invalid',
                    validatedAt: mockDate
                }
            }
        ]);
    });

    test('should handle null API key in match', async () => {
        const finding = createMockFinding();
        finding.secretValue = { match: { apiKey: null } } as any;

        await deepaiValidityHelper(finding);

        expect(console.error).toHaveBeenCalledWith('No API key found in finding');
        expect(mockValidateDeepAIApiKey).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });

    test('should handle undefined match in secret value', async () => {
        const finding = createMockFinding();
        finding.secretValue = {} as any;

        await deepaiValidityHelper(finding);

        expect(console.error).toHaveBeenCalledWith('No API key found in finding');
        expect(mockValidateDeepAIApiKey).not.toHaveBeenCalled();
        expect(mockRetrieveFindings).not.toHaveBeenCalled();
        expect(mockStoreFindings).not.toHaveBeenCalled();
    });
});