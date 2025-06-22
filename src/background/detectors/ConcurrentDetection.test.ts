import { findSecrets } from '../scanner';

jest.mock('./aws/access_keys/access_keys');
jest.mock('./aws/session_keys/session_keys');
jest.mock('./anthropic/anthropic');

import { detectAwsAccessKeys } from './aws/access_keys/access_keys';
import { detectAwsSessionKeys } from './aws/session_keys/session_keys';
import { detectAnthropicKeys } from './anthropic/anthropic';

describe('Concurrent Detection', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('all detectors run concurrently', async () => {
        const executionOrder: string[] = [];
        const delay = 100;

        (detectAwsAccessKeys as jest.Mock).mockImplementation(async () => {
            executionOrder.push('aws_access_start');
            await new Promise(resolve => setTimeout(resolve, delay));
            executionOrder.push('aws_access_end');
            return [];
        });

        (detectAwsSessionKeys as jest.Mock).mockImplementation(async () => {
            executionOrder.push('aws_session_start');
            await new Promise(resolve => setTimeout(resolve, delay));
            executionOrder.push('aws_session_end');
            return [];
        });

        (detectAnthropicKeys as jest.Mock).mockImplementation(async () => {
            executionOrder.push('anthropic_start');
            await new Promise(resolve => setTimeout(resolve, delay));
            executionOrder.push('anthropic_end');
            return [];
        });

        const startTime = Date.now();
        await findSecrets('test content', 'test url');
        const endTime = Date.now();

        expect(executionOrder.slice(0, 3)).toEqual([
            'aws_access_start',
            'aws_session_start',
            'anthropic_start'
        ]);

        // Execution should take roughly the delay time, not 3x the delay (proving concurrency)
        const executionTime = endTime - startTime;
        expect(executionTime).toBeLessThan(delay * 2); // Allow some buffer for timing
        expect(executionTime).toBeGreaterThan(delay * 0.8); // But ensure it took at least the delay
    });

    test('all detectors are called', async () => {
        (detectAwsAccessKeys as jest.Mock).mockResolvedValue([]);
        (detectAwsSessionKeys as jest.Mock).mockResolvedValue([]);
        (detectAnthropicKeys as jest.Mock).mockResolvedValue([]);

        await findSecrets('test content', 'test url');

        expect(detectAwsAccessKeys).toHaveBeenCalledWith('test content', 'test url');
        expect(detectAwsSessionKeys).toHaveBeenCalledWith('test content', 'test url');
        expect(detectAnthropicKeys).toHaveBeenCalledWith('test content', 'test url');
    });
});