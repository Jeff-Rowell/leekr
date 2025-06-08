import * as objectSha from 'object-sha';

export const computeFingerprint = async <T extends object>(
    target: T,
    algorithm: string = 'SHA-512'
): Promise<string> => {
    try {
        const digest = await objectSha.digest(target, algorithm);
        return digest;
    } catch (error) {
        console.error(`Error computing ${algorithm} fingerprint:`, error);
        throw new Error(`Failed to compute ${algorithm} fingerprint`);
    }
};