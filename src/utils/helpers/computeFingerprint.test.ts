import { computeFingerprint } from './computeFingerprint';
import * as objectSha from 'object-sha';


jest.mock('object-sha');
const mockObjectSha = objectSha as jest.Mocked<typeof objectSha>;

describe('computeFingerprint', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        jest.spyOn(console, 'error').mockImplementation(() => { });
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    describe('successful digest computation', () => {
        test('should compute SHA-512 fingerprint with default algorithm', async () => {
            const target = {
                match: {
                    access_key_id: "lol",
                    secret_key_id: "wut"
                }
            }
            const expectedDigest = '96f3ee816515ddeac897c9c0af49ca020eb8eb50aabfd68bdab046e791323dac78fb2241f2d3ad642b906bd65a3d41a594779c63d9c417661b56fab09bde9f64';
            mockObjectSha.digest.mockResolvedValue(expectedDigest);

            const result = await computeFingerprint(target);

            expect(result).toBe(expectedDigest);
            expect(mockObjectSha.digest).toHaveBeenCalledWith(target, 'SHA-512');
            expect(mockObjectSha.digest).toHaveBeenCalledTimes(1);
        });

        test('should handle empty objects', async () => {
            const target = {};
            const expectedDigest = '27c74670adb75075fad058d5ceaf7b20c4e7786c83bae8a32f626f9782af34c9a33c2046ef60fd2a7878d378e29fec851806bbd9a67878f3a9f1cda4830763fd';
            mockObjectSha.digest.mockResolvedValue(expectedDigest);

            const result = await computeFingerprint(target);

            expect(result).toBe(expectedDigest);
            expect(mockObjectSha.digest).toHaveBeenCalledWith(target, 'SHA-512');
        });

    });

    describe('error handling', () => {
        test('should throw error and log when object-sha.digest fails', async () => {
            const target = { id: 1 };
            const originalError = new Error('Digest computation failed');
            mockObjectSha.digest.mockRejectedValue(originalError);
            const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

            await expect(computeFingerprint(target)).rejects.toThrow(
                'Failed to compute SHA-512 fingerprint'
            );

            expect(consoleSpy).toHaveBeenCalledWith(
                'Error computing SHA-512 fingerprint:',
                originalError
            );
            expect(mockObjectSha.digest).toHaveBeenCalledWith(target, 'SHA-512');
        });

        test('should throw error with custom algorithm name when digest fails', async () => {
            const target = { data: 'test' };
            const algorithm = 'SHA-256';
            const originalError = new Error('Custom algorithm error');
            mockObjectSha.digest.mockRejectedValue(originalError);
            const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

            await expect(computeFingerprint(target, algorithm)).rejects.toThrow(
                'Failed to compute SHA-256 fingerprint'
            );

            expect(consoleSpy).toHaveBeenCalledWith(
                'Error computing SHA-256 fingerprint:',
                originalError
            );
            expect(mockObjectSha.digest).toHaveBeenCalledWith(target, algorithm);
        });

        test('should handle undefined/null errors from object-sha', async () => {
            const target = { id: 1 };
            mockObjectSha.digest.mockRejectedValue(undefined);
            const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

            await expect(computeFingerprint(target)).rejects.toThrow(
                'Failed to compute SHA-512 fingerprint'
            );

            expect(consoleSpy).toHaveBeenCalledWith(
                'Error computing SHA-512 fingerprint:',
                undefined
            );
        });
    });

    describe('type safety', () => {
        test('should accept any object type', async () => {
            interface CustomType {
                id: number;
                name: string;
                active: boolean;
            }

            const target: CustomType = { id: 1, name: 'test', active: true };
            const expectedDigest = 'typed-object-hash';
            mockObjectSha.digest.mockResolvedValue(expectedDigest);

            const result = await computeFingerprint<CustomType>(target);

            expect(result).toBe(expectedDigest);
            expect(typeof result).toBe('string');
        });
    });
});