import { findSecrets } from './scanner';
import { detectAwsAccessKeys } from './detectors/aws/access_keys/access_keys';
import { AWSOccurrence } from '../types/aws.types';

jest.mock('./detectors/aws/access_keys/access_keys');
const mockDetectAwsAccessKeys = detectAwsAccessKeys as jest.MockedFunction<typeof detectAwsAccessKeys>;

describe('findSecrets', () => {
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
        fingerprint: "fp2",
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

    const mockOccurrenceThree: AWSOccurrence = {
        accountId: "987654321876",
        arn: "arn:aws:iam::987654321876:user/leekr",
        filePath: "main.foobar.js",
        fingerprint: "fp3",
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

    beforeEach(() => {
        jest.clearAllMocks();
        jest.spyOn(Date.prototype, 'toISOString').mockReturnValue('2025-05-17T18:16:16.870Z');
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    test('should return empty array when no AWS access keys are detected', async () => {
        const content = 'This is some content without secrets';
        const url = 'https://example.com';
        mockDetectAwsAccessKeys.mockResolvedValue([]);

        const result = await findSecrets(content, url);

        expect(result).toEqual([]);
        expect(mockDetectAwsAccessKeys).toHaveBeenCalledWith(content, url);
        expect(mockDetectAwsAccessKeys).toHaveBeenCalledTimes(1);
    });

    test('should return findings when AWS access keys are detected', async () => {
        const content = 'AWS access keys detected';
        const url = 'http://localhost:3000/static/js/main.foobar.js';
        const mockOccurrences: AWSOccurrence[] = [mockOccurrenceOne];
        mockDetectAwsAccessKeys.mockResolvedValue(mockOccurrences);

        const result = await findSecrets(content, url);

        expect(result).toHaveLength(1);
        expect(result[0]).toEqual({
            numOccurrences: 1,
            secretType: 'AWS Access & Secret Keys',
            secretValue: {
                match: { access_key_id: "lol", secret_key_id: "wut" }
            },
            validity: 'valid',
            validatedAt: '2025-05-17T18:16:16.870Z',
            fingerprint: 'fp1',
            occurrences: new Set([mockOccurrenceOne]),
            isNew: true,
            discoveredAt: '2025-05-17T18:16:16.870Z',
        });
        expect(mockDetectAwsAccessKeys).toHaveBeenCalledWith(content, url);
    });

    test('should handle multiple AWS access key occurrences', async () => {
        const content = 'Multiple AWS keys detected';
        const url = 'http://localhost:3000/static/js/main.foobar.js';
        const mockOccurrences: AWSOccurrence[] = [mockOccurrenceOne, mockOccurrenceTwo];
        mockDetectAwsAccessKeys.mockResolvedValue(mockOccurrences);

        const result = await findSecrets(content, url);

        expect(result).toHaveLength(2);
        expect(result[0]).toEqual({
            numOccurrences: 1,
            secretType: 'AWS Access & Secret Keys',
            secretValue: {
                match: { access_key_id: "lol", secret_key_id: "wut" }
            },
            validity: 'valid',
            validatedAt: '2025-05-17T18:16:16.870Z',
            fingerprint: 'fp1',
            occurrences: new Set([mockOccurrenceOne]),
            isNew: true,
            discoveredAt: '2025-05-17T18:16:16.870Z',
        });
        expect(result[1]).toEqual({
            numOccurrences: 1,
            secretType: 'AWS Access & Secret Keys',
            secretValue: {
                match: { access_key_id: "lol", secret_key_id: "wut" }
            },
            validity: 'valid',
            validatedAt: '2025-05-17T18:16:16.870Z',
            fingerprint: 'fp2',
            occurrences: new Set([mockOccurrenceTwo]),
            isNew: true,
            discoveredAt: '2025-05-17T18:16:16.870Z',
        });
    });

    test('should handle empty content string', async () => {
        const content = '';
        const url = 'https://example.com';
        mockDetectAwsAccessKeys.mockResolvedValue([]);

        const result = await findSecrets(content, url);

        expect(result).toEqual([]);
        expect(mockDetectAwsAccessKeys).toHaveBeenCalledWith('', url);
    });

    test('should handle empty URL string', async () => {
        const content = 'Some content';
        const url = '';
        mockDetectAwsAccessKeys.mockResolvedValue([]);

        const result = await findSecrets(content, url);

        expect(result).toEqual([]);
        expect(mockDetectAwsAccessKeys).toHaveBeenCalledWith(content, '');
    });

    test('should handle complex secretValue structure', async () => {
        const content = 'AWS content with complex structure';
        const url = 'http://localhost:3000/static/js/main.foobar.js';
        const complexOccurrence: AWSOccurrence = {
            ...mockOccurrenceOne,
            fingerprint: 'complex-fp',
            secretValue: {
                match: {
                    access_key_id: "AKIAIOSFODNN7EXAMPLE",
                    secret_key_id: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                }
            }
        };
        mockDetectAwsAccessKeys.mockResolvedValue([complexOccurrence]);

        const result = await findSecrets(content, url);

        expect(result).toHaveLength(1);
        expect(result[0].secretValue).toEqual({
            match: {
                access_key_id: "AKIAIOSFODNN7EXAMPLE",
                secret_key_id: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            }
        });
        expect(result[0].fingerprint).toBe('complex-fp');
    });

    test('should preserve all occurrence properties in the Set', async () => {
        const content = 'AWS access key content';
        const url = 'http://localhost:3000/static/js/main.foobar.js';
        mockDetectAwsAccessKeys.mockResolvedValue([mockOccurrenceThree]);

        const result = await findSecrets(content, url);

        expect(result[0].occurrences.has(mockOccurrenceThree)).toBe(true);
        const occurrenceFromSet = Array.from(result[0].occurrences)[0] as AWSOccurrence;
        expect(occurrenceFromSet).toEqual(mockOccurrenceThree);
        expect(occurrenceFromSet.accountId).toBe('987654321876');
        expect(occurrenceFromSet.arn).toBe('arn:aws:iam::987654321876:user/leekr');
        expect(occurrenceFromSet.sourceContent.contentFilename).toBe('App.js');
        expect(occurrenceFromSet.sourceContent.exactMatchNumbers).toEqual([23, 30]);
    });

    test('should handle detector throwing an error', async () => {
        const content = 'Some content';
        const url = 'https://example.com';
        const error = new Error('Detector failed');
        mockDetectAwsAccessKeys.mockRejectedValue(error);

        await expect(findSecrets(content, url)).rejects.toThrow('Detector failed');
        expect(mockDetectAwsAccessKeys).toHaveBeenCalledWith(content, url);
    });
});