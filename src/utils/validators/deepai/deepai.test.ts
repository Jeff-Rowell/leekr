import { validateDeepAIApiKey, DeepAIValidationResult } from './deepai';
import { deepaiConfig } from '../../../config/detectors/deepai/deepai';

global.fetch = jest.fn();
global.FormData = jest.fn().mockImplementation(() => ({
    append: jest.fn()
}));

describe('validateDeepAIApiKey', () => {
    const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;
    const mockFormData = global.FormData as jest.MockedFunction<any>;
    let mockFormDataInstance: any;

    beforeEach(() => {
        jest.clearAllMocks();
        jest.useFakeTimers();
        
        mockFormDataInstance = {
            append: jest.fn()
        };
        mockFormData.mockReturnValue(mockFormDataInstance);
    });

    afterEach(() => {
        jest.useRealTimers();
    });

    test('should return valid result for successful API response', async () => {
        const mockResponse = {
            status: 200,
            json: () => Promise.resolve({
                id: 'test-id',
                output: { tag: 'positive' }
            })
        };
        mockFetch.mockResolvedValue(mockResponse as any);

        const result = await validateDeepAIApiKey('valid-api-key');

        expect(result.valid).toBe(true);
        expect(result.response).toEqual({
            id: 'test-id',
            output: { tag: 'positive' }
        });
        expect(result.error).toBeUndefined();
    });

    test('should return invalid result for 401 unauthorized', async () => {
        const mockResponse = {
            status: 401
        };
        mockFetch.mockResolvedValue(mockResponse as any);

        const result = await validateDeepAIApiKey('invalid-api-key');

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Invalid API key');
        expect(result.response).toBeUndefined();
    });

    test('should return invalid result for 403 forbidden', async () => {
        const mockResponse = {
            status: 403
        };
        mockFetch.mockResolvedValue(mockResponse as any);

        const result = await validateDeepAIApiKey('forbidden-api-key');

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Invalid API key');
        expect(result.response).toBeUndefined();
    });

    test('should return invalid result for unexpected status code', async () => {
        const mockResponse = {
            status: 500
        };
        mockFetch.mockResolvedValue(mockResponse as any);

        const result = await validateDeepAIApiKey('test-api-key');

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Unexpected status code: 500');
        expect(result.response).toBeUndefined();
    });

    test('should handle network error', async () => {
        const networkError = new Error('Network error');
        mockFetch.mockRejectedValue(networkError);

        const result = await validateDeepAIApiKey('test-api-key');

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Network error');
        expect(result.response).toBeUndefined();
    });

    test('should handle timeout error', async () => {
        const abortError = new Error('Request timeout');
        abortError.name = 'AbortError';
        mockFetch.mockRejectedValue(abortError);

        const result = await validateDeepAIApiKey('test-api-key');

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Request timeout');
        expect(result.response).toBeUndefined();
    });

    test('should handle unknown error', async () => {
        mockFetch.mockRejectedValue('unknown error');

        const result = await validateDeepAIApiKey('test-api-key');

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Unknown error occurred');
        expect(result.response).toBeUndefined();
    });

    test('should make correct API request', async () => {
        const mockResponse = {
            status: 200,
            json: () => Promise.resolve({ id: 'test-id' })
        };
        mockFetch.mockResolvedValue(mockResponse as any);

        await validateDeepAIApiKey('test-api-key');

        expect(mockFormData).toHaveBeenCalled();
        expect(mockFormDataInstance.append).toHaveBeenCalledWith('text', 'test');
        expect(mockFetch).toHaveBeenCalledWith(
            `${deepaiConfig.api.baseUrl}${deepaiConfig.api.endpoints.textTagging}`,
            {
                method: 'POST',
                headers: {
                    'api-key': 'test-api-key'
                },
                body: mockFormDataInstance,
                signal: expect.any(AbortSignal)
            }
        );
    });

    test('should abort request after timeout', async () => {
        let abortController: AbortController;
        const originalAbortController = global.AbortController;
        
        global.AbortController = jest.fn().mockImplementation(() => {
            abortController = new originalAbortController();
            jest.spyOn(abortController, 'abort');
            return abortController;
        });

        const mockResponse = {
            status: 200,
            json: () => Promise.resolve({ id: 'test-id' })
        };
        mockFetch.mockResolvedValue(mockResponse as any);

        const validationPromise = validateDeepAIApiKey('test-api-key');
        
        jest.advanceTimersByTime(deepaiConfig.api.timeout);
        
        await validationPromise;

        expect(abortController!.abort).toHaveBeenCalled();
        
        global.AbortController = originalAbortController;
    });

    test('should handle response status 201', async () => {
        const mockResponse = {
            status: 201,
            json: () => Promise.resolve({
                id: 'test-id',
                output: { tag: 'neutral' }
            })
        };
        mockFetch.mockResolvedValue(mockResponse as any);

        const result = await validateDeepAIApiKey('valid-api-key');

        expect(result.valid).toBe(true);
        expect(result.response).toEqual({
            id: 'test-id',
            output: { tag: 'neutral' }
        });
    });

    test('should handle response status 299', async () => {
        const mockResponse = {
            status: 299,
            json: () => Promise.resolve({
                id: 'test-id',
                output: { tag: 'negative' }
            })
        };
        mockFetch.mockResolvedValue(mockResponse as any);

        const result = await validateDeepAIApiKey('valid-api-key');

        expect(result.valid).toBe(true);
        expect(result.response).toEqual({
            id: 'test-id',
            output: { tag: 'negative' }
        });
    });
});