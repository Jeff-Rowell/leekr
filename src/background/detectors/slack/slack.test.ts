import { detectSlack } from './slack';
import { SlackOccurrence } from '../../../types/slack';
import { validateSlackToken } from '../../../utils/validators/slack/slack';
import { calculateShannonEntropy } from '../../../utils/accuracy/entropy';
import { isKnownFalsePositive } from '../../../utils/accuracy/falsePositives';
import { getExistingFindings, getSourceMapUrl, findSecretPosition } from '../../../utils/helpers/common';
import { computeFingerprint } from '../../../utils/helpers/computeFingerprint';
import * as sourceMap from '../../../../external/source-map';

jest.mock('../../../utils/validators/slack/slack');
jest.mock('../../../utils/accuracy/entropy');
jest.mock('../../../utils/accuracy/falsePositives');
jest.mock('../../../utils/helpers/common');
jest.mock('../../../utils/helpers/computeFingerprint');
jest.mock('../../../../external/source-map');

const mockValidateSlackToken = validateSlackToken as jest.MockedFunction<typeof validateSlackToken>;
const mockCalculateShannonEntropy = calculateShannonEntropy as jest.MockedFunction<typeof calculateShannonEntropy>;
const mockIsKnownFalsePositive = isKnownFalsePositive as jest.MockedFunction<typeof isKnownFalsePositive>;
const mockGetExistingFindings = getExistingFindings as jest.MockedFunction<typeof getExistingFindings>;
const mockGetSourceMapUrl = getSourceMapUrl as jest.MockedFunction<typeof getSourceMapUrl>;
const mockComputeFingerprint = computeFingerprint as jest.MockedFunction<typeof computeFingerprint>;
const mockFindSecretPosition = findSecretPosition as jest.MockedFunction<typeof findSecretPosition>;

global.fetch = jest.fn();
global.chrome = {
    runtime: {
        getURL: jest.fn(() => 'chrome-extension://test/libs/mappings.wasm')
    }
} as any;

describe('detectSlack', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        mockCalculateShannonEntropy.mockReturnValue(5);
        mockIsKnownFalsePositive.mockReturnValue([false, '']);
        mockGetExistingFindings.mockResolvedValue([]);
        mockComputeFingerprint.mockResolvedValue('test-fingerprint');
    });

    it('should return empty array when no Slack tokens found', async () => {
        const content = 'const apiKey = "some-other-key";';
        const url = 'https://example.com/test.js';

        const result = await detectSlack(content, url);

        expect(result).toEqual([]);
    });

    it('should detect and validate Slack bot token', async () => {
        const content = 'const slackToken = "xoxb-1234567890-1234567890-test-token-here";';
        const url = 'https://example.com/test.js';

        mockValidateSlackToken.mockResolvedValue({
            valid: true,
            team: 'Test Team',
            user: 'test-user',
            teamId: 'T1234567',
            userId: 'U1234567',
            botId: 'B1234567'
        });

        const result = await detectSlack(content, url);

        expect(result).toHaveLength(1);
        expect(result[0]).toMatchObject({
            secretType: 'Slack',
            validity: 'valid',
            team: 'Test Team',
            user: 'test-user',
            teamId: 'T1234567',
            userId: 'U1234567',
            botId: 'B1234567',
            secretValue: {
                match: {
                    token: 'xoxb-1234567890-1234567890-test-token-here',
                    token_type: 'Slack Bot Token'
                }
            }
        });
    });

    it('should detect and validate Slack user token', async () => {
        const content = 'const slackToken = "xoxp-1234567890-1234567890-test-token-here";';
        const url = 'https://example.com/test.js';

        mockValidateSlackToken.mockResolvedValue({
            valid: true,
            team: 'Test Team',
            user: 'test-user'
        });

        const result = await detectSlack(content, url);

        expect(result).toHaveLength(1);
        expect((result[0] as SlackOccurrence).secretValue.match.token_type).toBe('Slack User Token');
    });

    it('should detect and validate Slack workspace access token', async () => {
        const content = 'const slackToken = "xoxe.xoxp-1-Mi0yLTg0QzYzOLgxMjkxTjgtODQxMzU3MzYyMzQxMC05jjczMjk2Njk3ODU5LTkyNjIzMDg3MTc3OTktZGZjNmRmYjA1MThmOTAxZGEwYjM1NmQ1OTMxMTJmMzI3ZjhlYmRhMWEwMDliZjc5ODM0MTIwNjM0NGViNzIwMg";';
        const url = 'https://example.com/test.js';

        mockValidateSlackToken.mockResolvedValue({
            valid: true,
            team: 'Test Team'
        });

        const result = await detectSlack(content, url);

        expect(result).toHaveLength(1);
        expect((result[0] as SlackOccurrence).secretValue.match.token_type).toBe('Slack Workspace Access Token');
    });

    it('should detect and validate Slack workspace refresh token', async () => {
        const content = 'const slackToken = "xoxe-1-My0xLTg0MzYzODgxMjkxNjgtOTI3MzI5NjY5Nzg1OS05yjMyQzA4NzI5MDMxLWRjMmU2ZmZhZDY0ZWNkNWNjMGQzYTdhZWNiYWRmNjdhLWJkOWIwNjliNje2ZjQ1YjgwNjE5MDJhMGI0MGQ4ODM";';
        const url = 'https://example.com/test.js';

        mockValidateSlackToken.mockResolvedValue({
            valid: true,
            team: 'Test Team'
        });

        const result = await detectSlack(content, url);

        expect(result).toHaveLength(1);
        expect((result[0] as SlackOccurrence).secretValue.match.token_type).toBe('Slack Workspace Refresh Token');
    });

    it('should filter out tokens with low entropy', async () => {
        const content = 'const slackToken = "xoxb-1234567890-1234567890-test-token-here";';
        const url = 'https://example.com/test.js';

        mockCalculateShannonEntropy.mockReturnValue(-1);
        mockValidateSlackToken.mockResolvedValue({
            valid: true,
            team: 'Test Team'
        });

        const result = await detectSlack(content, url);

        expect(result).toEqual([]);
    });

    it('should filter out known false positives', async () => {
        const content = 'const slackToken = "xoxb-1234567890-1234567890-test-token-here";';
        const url = 'https://example.com/test.js';

        mockIsKnownFalsePositive.mockReturnValue([true, 'test reason']);

        const result = await detectSlack(content, url);

        expect(result).toEqual([]);
    });

    it('should filter out existing findings', async () => {
        const content = 'const slackToken = "xoxb-1234567890-1234567890-test-token-here";';
        const url = 'https://example.com/test.js';

        mockGetExistingFindings.mockResolvedValue([
            {
                secretType: 'Slack',
                fingerprint: 'existing-fingerprint',
                secretValue: {
                    match: {
                        token: 'xoxb-1234567890-1234567890-test-token-here'
                    }
                },
                numOccurrences: 1,
                occurrences: new Set(),
                validity: 'valid'
            }
        ]);

        const result = await detectSlack(content, url);

        expect(result).toEqual([]);
    });

    it('should return empty for invalid tokens', async () => {
        const content = 'const slackToken = "xoxb-1234567890-1234567890-test-token-here";';
        const url = 'https://example.com/test.js';

        mockValidateSlackToken.mockResolvedValue({
            valid: false,
            error: 'Invalid token'
        });

        const result = await detectSlack(content, url);

        expect(result).toEqual([]);
    });

    it('should handle multiple tokens', async () => {
        const content = `
            const botToken = "xoxb-1234567890-1234567890-test-token-here";
            const userToken = "xoxp-9876543210-9876543210-another-token";
        `;
        const url = 'https://example.com/test.js';

        mockValidateSlackToken
            .mockResolvedValueOnce({
                valid: true,
                team: 'Test Team 1'
            })
            .mockResolvedValueOnce({
                valid: true,
                team: 'Test Team 2'
            });

        const result = await detectSlack(content, url);

        expect(result).toHaveLength(2);
        expect((result[0] as SlackOccurrence).secretValue.match.token_type).toBe('Slack Bot Token');
        expect((result[1] as SlackOccurrence).secretValue.match.token_type).toBe('Slack User Token');
    });

    it('should handle source map processing', async () => {
        const content = 'const slackToken = "xoxb-1234567890-1234567890-test-token-here";';
        const url = 'https://example.com/test.js';

        mockValidateSlackToken.mockResolvedValue({
            valid: true,
            team: 'Test Team'
        });

        mockGetSourceMapUrl.mockReturnValue(new URL('https://example.com/test.js.map'));
        mockFindSecretPosition.mockReturnValue({ line: 10, column: 5 });

        const mockConsumer = {
            originalPositionFor: jest.fn().mockReturnValue({
                source: 'original.js',
                line: 15,
                column: 10
            }),
            sourceContentFor: jest.fn().mockReturnValue('original source content')
        };

        const mockSourceMapWith = jest.fn().mockImplementation((content, encoding, callback) => {
            callback(mockConsumer);
            return Promise.resolve();
        });

        jest.spyOn(sourceMap.SourceMapConsumer, 'initialize').mockImplementation(jest.fn());
        jest.spyOn(sourceMap.SourceMapConsumer, 'with').mockImplementation(mockSourceMapWith);

        (global.fetch as jest.Mock).mockResolvedValue({
            text: () => Promise.resolve('source map content')
        });

        const result = await detectSlack(content, url);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent).toMatchObject({
            content: 'original source content',
            contentFilename: 'original.js',
            contentStartLineNum: 10,
            contentEndLineNum: 20,
            exactMatchNumbers: [15]
        });
    });

    it('should handle source map processing without source', async () => {
        const content = 'const slackToken = "xoxb-1234567890-1234567890-test-token-here";';
        const url = 'https://example.com/test.js';

        mockValidateSlackToken.mockResolvedValue({
            valid: true,
            team: 'Test Team'
        });

        mockGetSourceMapUrl.mockReturnValue(new URL('https://example.com/test.js.map'));
        mockFindSecretPosition.mockReturnValue({ line: 10, column: 5 });

        const mockConsumer = {
            originalPositionFor: jest.fn().mockReturnValue({
                source: null,
                line: null,
                column: null
            })
        };

        const mockSourceMapWith = jest.fn().mockImplementation((content, encoding, callback) => {
            callback(mockConsumer);
            return Promise.resolve();
        });

        jest.spyOn(sourceMap.SourceMapConsumer, 'initialize').mockImplementation(jest.fn());
        jest.spyOn(sourceMap.SourceMapConsumer, 'with').mockImplementation(mockSourceMapWith);

        (global.fetch as jest.Mock).mockResolvedValue({
            text: () => Promise.resolve('source map content')
        });

        const result = await detectSlack(content, url);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent).toMatchObject({
            content: JSON.stringify({
                token: 'xoxb-1234567890-1234567890-test-token-here',
                token_type: 'Slack Bot Token'
            }),
            contentFilename: 'test.js',
            contentStartLineNum: -1,
            contentEndLineNum: -1,
            exactMatchNumbers: [-1]
        });
    });

    it('should handle unknown token type', async () => {
        const content = 'const slackToken = "xoxz-1234567890-1234567890-test-token-here";';
        const url = 'https://example.com/test.js';

        const result = await detectSlack(content, url);

        expect(result).toEqual([]);
    });

    describe('URL filename extraction', () => {
        it('should extract filename from standard URL', async () => {
            const content = 'const slackToken = "xoxb-1234567890-1234567890-test-token-here";';
            const url = 'https://example.com/path/to/script.js';

            mockValidateSlackToken.mockResolvedValue({
                valid: true,
                team: 'Test Team'
            });

            const result = await detectSlack(content, url);

            expect(result).toHaveLength(1);
            expect(result[0].filePath).toBe('script.js');
            expect(result[0].sourceContent.contentFilename).toBe('script.js');
        });

        it('should handle URL without filename (ending with slash)', async () => {
            const content = 'const slackToken = "xoxb-1234567890-1234567890-test-token-here";';
            const url = 'https://example.com/path/to/';

            mockValidateSlackToken.mockResolvedValue({
                valid: true,
                team: 'Test Team'
            });

            const result = await detectSlack(content, url);

            expect(result).toHaveLength(1);
            expect(result[0].filePath).toBe('');
            expect(result[0].sourceContent.contentFilename).toBe('');
        });

        it('should handle URL without path', async () => {
            const content = 'const slackToken = "xoxb-1234567890-1234567890-test-token-here";';
            const url = 'https://example.com';

            mockValidateSlackToken.mockResolvedValue({
                valid: true,
                team: 'Test Team'
            });

            const result = await detectSlack(content, url);

            expect(result).toHaveLength(1);
            expect(result[0].filePath).toBe('example.com');
            expect(result[0].sourceContent.contentFilename).toBe('example.com');
        });

        it('should handle empty URL', async () => {
            const content = 'const slackToken = "xoxb-1234567890-1234567890-test-token-here";';
            const url = '';

            mockValidateSlackToken.mockResolvedValue({
                valid: true,
                team: 'Test Team'
            });

            const result = await detectSlack(content, url);

            expect(result).toHaveLength(1);
            expect(result[0].filePath).toBe('');
            expect(result[0].sourceContent.contentFilename).toBe('');
        });

        it('should handle URL with special characters in filename', async () => {
            const content = 'const slackToken = "xoxb-1234567890-1234567890-test-token-here";';
            const url = 'https://example.com/my-file_name.test.js';

            mockValidateSlackToken.mockResolvedValue({
                valid: true,
                team: 'Test Team'
            });

            const result = await detectSlack(content, url);

            expect(result).toHaveLength(1);
            expect(result[0].filePath).toBe('my-file_name.test.js');
            expect(result[0].sourceContent.contentFilename).toBe('my-file_name.test.js');
        });

        it('should handle URL with query parameters', async () => {
            const content = 'const slackToken = "xoxb-1234567890-1234567890-test-token-here";';
            const url = 'https://example.com/script.js?version=1.0&debug=true';

            mockValidateSlackToken.mockResolvedValue({
                valid: true,
                team: 'Test Team'
            });

            const result = await detectSlack(content, url);

            expect(result).toHaveLength(1);
            expect(result[0].filePath).toBe('script.js?version=1.0&debug=true');
            expect(result[0].sourceContent.contentFilename).toBe('script.js?version=1.0&debug=true');
        });

        it('should handle URL with hash fragment', async () => {
            const content = 'const slackToken = "xoxb-1234567890-1234567890-test-token-here";';
            const url = 'https://example.com/app.js#section1';

            mockValidateSlackToken.mockResolvedValue({
                valid: true,
                team: 'Test Team'
            });

            const result = await detectSlack(content, url);

            expect(result).toHaveLength(1);
            expect(result[0].filePath).toBe('app.js#section1');
            expect(result[0].sourceContent.contentFilename).toBe('app.js#section1');
        });

        it('should handle data URL', async () => {
            const content = 'const slackToken = "xoxb-1234567890-1234567890-test-token-here";';
            const url = 'data:text/javascript;base64,Y29uc29sZS5sb2coImhlbGxvIik=';

            mockValidateSlackToken.mockResolvedValue({
                valid: true,
                team: 'Test Team'
            });

            const result = await detectSlack(content, url);

            expect(result).toHaveLength(1);
            expect(result[0].filePath).toBe('javascript;base64,Y29uc29sZS5sb2coImhlbGxvIik=');
            expect(result[0].sourceContent.contentFilename).toBe('javascript;base64,Y29uc29sZS5sb2coImhlbGxvIik=');
        });
    });
});