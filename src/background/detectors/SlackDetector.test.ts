import { SlackDetector } from './SlackDetector';
import { detectSlack } from './slack/slack';

jest.mock('./slack/slack');

const mockDetectSlack = detectSlack as jest.MockedFunction<typeof detectSlack>;

describe('SlackDetector', () => {
    let detector: SlackDetector;

    beforeEach(() => {
        detector = new SlackDetector();
        jest.clearAllMocks();
    });

    it('should have correct type and name', () => {
        expect(detector.type).toBe('slack');
        expect(detector.name).toBe('Slack');
    });

    it('should call detectSlack with correct parameters', async () => {
        const content = 'test content';
        const url = 'https://example.com/test.js';
        const expectedResult = [
            {
                secretType: 'Slack',
                fingerprint: 'test-fingerprint',
                secretValue: {
                    match: {
                        token: 'xoxb-1234567890-1234567890-test-token',
                        token_type: 'Slack Bot Token'
                    }
                },
                filePath: 'test.js',
                url: 'https://example.com/test.js',
                sourceContent: {
                    content: '{}',
                    contentFilename: 'test.js',
                    contentStartLineNum: -1,
                    contentEndLineNum: -1,
                    exactMatchNumbers: [-1]
                },
                validity: 'valid'
            }
        ];

        mockDetectSlack.mockResolvedValue(expectedResult);

        const result = await detector.detect(content, url);

        expect(mockDetectSlack).toHaveBeenCalledWith(content, url);
        expect(result).toEqual(expectedResult);
    });

    it('should return empty array when no tokens detected', async () => {
        const content = 'const key = "not-a-slack-token";';
        const url = 'https://example.com/test.js';

        mockDetectSlack.mockResolvedValue([]);

        const result = await detector.detect(content, url);

        expect(mockDetectSlack).toHaveBeenCalledWith(content, url);
        expect(result).toEqual([]);
    });

    it('should handle multiple occurrences', async () => {
        const content = `
            const botToken = "xoxb-1234567890-1234567890-test-token";
            const userToken = "xoxp-9876543210-9876543210-another-token";
        `;
        const url = 'https://example.com/test.js';
        const expectedResult = [
            {
                secretType: 'Slack',
                fingerprint: 'test-fingerprint-1',
                secretValue: {
                    match: {
                        token: 'xoxb-1234567890-1234567890-test-token',
                        token_type: 'Slack Bot Token'
                    }
                },
                filePath: 'test.js',
                url: 'https://example.com/test.js',
                sourceContent: {
                    content: '{}',
                    contentFilename: 'test.js',
                    contentStartLineNum: -1,
                    contentEndLineNum: -1,
                    exactMatchNumbers: [-1]
                },
                validity: 'valid'
            },
            {
                secretType: 'Slack',
                fingerprint: 'test-fingerprint-2',
                secretValue: {
                    match: {
                        token: 'xoxp-9876543210-9876543210-another-token',
                        token_type: 'Slack User Token'
                    }
                },
                filePath: 'test.js',
                url: 'https://example.com/test.js',
                sourceContent: {
                    content: '{}',
                    contentFilename: 'test.js',
                    contentStartLineNum: -1,
                    contentEndLineNum: -1,
                    exactMatchNumbers: [-1]
                },
                validity: 'valid'
            }
        ];

        mockDetectSlack.mockResolvedValue(expectedResult);

        const result = await detector.detect(content, url);

        expect(mockDetectSlack).toHaveBeenCalledWith(content, url);
        expect(result).toEqual(expectedResult);
    });
});