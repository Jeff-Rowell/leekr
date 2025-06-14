import { AWSOccurrence } from 'src/types/aws.types';
import { Finding, Occurrence } from 'src/types/findings.types';
import * as entropyUtils from '../../../../utils/accuracy/entropy';
import * as falsePositiveUtils from '../../../../utils/accuracy/falsePositives';
import * as common from '../../../../utils/helpers/common';
import * as helpers from '../../../../utils/helpers/computeFingerprint';
import * as awsValidator from '../../../../utils/validators/aws_session_keys/aws';
import { detectAwsSessionKeys } from './session_keys';

jest.mock('../../../../utils/accuracy/entropy');
jest.mock('../../../../utils/accuracy/falsePositives');
jest.mock('../../../../utils/validators/aws_access_keys/aws');
jest.mock('../../../../utils/helpers/common');
jest.mock('../../../../../external/source-map');

global.fetch = jest.fn();

describe('detectAwsAccessKeys', () => {
    const fakeAccessKey = 'ASIAIOSFODNN7EXAMPLE';
    const fakeSecretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    const fakeSessionToken = '9KjL8mN3pQ7rS5tU2vW4xY6zA1bC9dE8fG0hI3jK5lM7nO2pQ4rS6tU8vW1xY3zA5bC7dE9fG2hI4jK6lM8nO1pQ3rS5tU7vW9xY2zA4bCYXdz';
    const fakeSessionToken2 = '9KjL8mN3pQ7rS5tU2vW4xY6zA1bC9dE8fG0hI3jK5lM7nO2pQ4rS6tU8vW1xY3zA5bC7dE9fG2hI4jK6lM8nO1pQ3rS5tU7vWJb3JpZ2luX2Vj';
    const fakeSessionToken3 = '9KjL8mN3pQ7rS5tU2vW4xY6zA1bC9dE8fG0hI3jK5lM7nO2pQ4rS6tU8vW1xY3zA5bC7dEwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    const fakeUrl = 'https://example.com/app.js';

    const mockOccurrenceOne: AWSOccurrence = {
        accountId: "123456789876",
        arn: "arn:aws:iam::123456789876:user/leekr",
        filePath: "main.foobar.js",
        fingerprint: "fp1",
        resourceType: "Access Key",
        secretType: "AWS Access & Secret Keys",
        secretValue: {
            match: { access_key_id: fakeAccessKey, secret_key_id: fakeSecretKey, session_key_id: fakeSessionToken }
        },
        sourceContent: {
            content: "foobar",
            contentEndLineNum: 35,
            contentFilename: "App.js",
            contentStartLineNum: 18,
            exactMatchNumbers: [23, 30]
        },
        url: fakeUrl,
    };

    const mockOccurrencesOne: Set<Occurrence> = new Set([mockOccurrenceOne]);

    const mockFindings: Finding[] = [
        {
            fingerprint: "fp1",
            numOccurrences: mockOccurrencesOne.size,
            occurrences: mockOccurrencesOne,
            validity: "valid",
            validatedAt: "2025-05-17T18:16:16.870Z",
            secretType: "AWS Access & Secret Keys",
            secretValue: {
                match: { access_key_id: fakeAccessKey, secret_key_id: fakeSecretKey, session_key_id: fakeSessionToken },
                validatedAt: "2025-05-17T18:16:16.870Z",
                validity: "valid"
            }
        }
    ]

    beforeEach(() => {
        jest.resetAllMocks();
        jest.spyOn(falsePositiveUtils, 'isKnownFalsePositive').mockReturnValue([false, ""]);
        jest.spyOn(common, 'getExistingFindings').mockResolvedValue([]);
        jest.spyOn(helpers, 'computeFingerprint').mockResolvedValue('mocked-fingerprint');
        jest.spyOn(awsValidator, 'validateAWSCredentials').mockResolvedValue({
            valid: true,
            accountId: 'test-account',
            arn: 'arn:aws:iam::test',
        });
        jest.spyOn(common, 'getSourceMapUrl').mockReturnValue(null);
    });

    test('returns empty array if no access, secret, and session keys are found', async () => {
        const result = await detectAwsSessionKeys('no keys here', fakeUrl);
        expect(result).toEqual([]);
    });

    test('returns empty array if no secret key or session token is found', async () => {
        const content = `${fakeAccessKey} but no secret or session token`;
        const result = await detectAwsSessionKeys(content, fakeUrl);
        expect(result).toEqual([]);
    });

    test('returns empty array if access entropy is too low', async () => {
        jest.spyOn(entropyUtils, 'calculateShannonEntropy').mockReturnValue(2.0);
        const content = `${fakeAccessKey} "${fakeSecretKey}" "${fakeSessionToken}"`;
        const result = await detectAwsSessionKeys(content, fakeUrl);
        expect(result).toEqual([]);
    });

    test('returns empty array if secret key is a false positive', async () => {
        (falsePositiveUtils.isKnownFalsePositive as jest.Mock).mockReturnValueOnce([false]).mockReturnValueOnce([true]);
        const content = `${fakeAccessKey} "${fakeSecretKey}" "${fakeSessionToken}"`;
        const result = await detectAwsSessionKeys(content, fakeUrl);
        expect(result).toEqual([]);
    });

    test('returns empty array if session token is a false positive', async () => {
        const content = `${fakeAccessKey} "${fakeSecretKey}" "${fakeSessionToken}"`;
        (falsePositiveUtils.isKnownFalsePositive as jest.Mock)
            .mockReturnValueOnce([false, ''])
            .mockReturnValueOnce([false, ''])
            .mockReturnValueOnce([true, '']);
        const result = await detectAwsSessionKeys(content, fakeUrl);
        expect(result).toEqual([]);
    });

    test('returns empty array if secret key entropy is too low', async () => {
        jest.spyOn(entropyUtils, 'calculateShannonEntropy').mockReturnValue(4.0);
        const content = `${fakeAccessKey} "GetCustomVerificationEmailTemplateResult" "${fakeSessionToken}"`;
        const result = await detectAwsSessionKeys(content, fakeUrl);
        expect(result).toEqual([]);
    });

    test('returns empty array if session token entropy is too low', async () => {
        jest.spyOn(entropyUtils, 'calculateShannonEntropy').mockReturnValue(4.0);
        const content = `${fakeAccessKey} "${fakeSecretKey}" "${'A'.repeat(101)}"`;
        const result = await detectAwsSessionKeys(content, fakeUrl);
        expect(result).toEqual([]);
    });

    test('returns empty array when session key has entropy but is missing known aws session key substrings', async () => {
        jest.spyOn(entropyUtils, 'calculateShannonEntropy').mockReturnValue(5.0);
        jest.spyOn(falsePositiveUtils, 'isKnownFalsePositive').mockReturnValue([false, '']);
        Object.defineProperty(falsePositiveUtils, 'falsePositiveSecretPattern', {
            value: /NOTHING_WILL_MATCH_THIS_PATTERN/,
            writable: true,
        });

        jest.spyOn(awsValidator, 'validateAWSCredentials').mockResolvedValue({
            valid: false,
            accountId: '123456789012',
            arn: 'arn:aws:iam::123456789012:user/TestUser',
        });
        jest.spyOn(common, 'getExistingFindings').mockResolvedValue([]);
        jest.spyOn(helpers, 'computeFingerprint').mockResolvedValue('mocked-fingerprint');
        const content = `${fakeAccessKey} "${fakeSecretKey}" "${fakeSessionToken.replace('YXdz', 'AAAA')}"`;
        const result = await detectAwsSessionKeys(content, fakeUrl);
        expect(result).toEqual([]);
    });

    test('returns occurrences only when the known session key substrings are present', async () => {

        jest.spyOn(entropyUtils, 'calculateShannonEntropy').mockReturnValue(5.0);
        jest.spyOn(falsePositiveUtils, 'isKnownFalsePositive').mockReturnValue([false, '']);
        Object.defineProperty(falsePositiveUtils, 'falsePositiveSecretPattern', {
            value: /NOTHING_WILL_MATCH_THIS_PATTERN/,
            writable: true,
        });
        jest.spyOn(awsValidator, 'validateAWSCredentials').mockResolvedValue({
            valid: true,
            accountId: '123456789012',
            arn: 'arn:aws:iam::123456789012:user/TestUser',
        });
        jest.spyOn(common, 'getExistingFindings').mockResolvedValue([]);
        jest.spyOn(helpers, 'computeFingerprint').mockResolvedValue('mocked-fingerprint');

        const content1 = `some code with "${fakeAccessKey}" and "${fakeSecretKey}" inside and "${fakeSessionToken}"`;
        const result1 = await detectAwsSessionKeys(content1, 'https://github.com/org/repo/blob/main/app.js');
        expect(result1).toHaveLength(1);

        const content2 = `some code with "${fakeAccessKey}" and "${fakeSecretKey}" inside and "${fakeSessionToken2}"`;
        const result2 = await detectAwsSessionKeys(content2, 'https://github.com/org/repo/blob/main/app.js');
        expect(result2).toHaveLength(1);

        const content3 = `some code with "${fakeAccessKey}" and "${fakeSecretKey}" inside and "${fakeSessionToken3}"`;
        const result3 = await detectAwsSessionKeys(content2, 'https://github.com/org/repo/blob/main/app.js');
        expect(result3).toHaveLength(1);
    });

    test('filters out keys already in existing findings', async () => {
        (common.getExistingFindings as jest.Mock).mockResolvedValue([{
            secretType: 'AWS Access & Secret Keys',
            secretValue: {
                match: {
                    access_key_id: fakeAccessKey,
                    secret_key_id: fakeSecretKey,
                    session_key_id: fakeSessionToken,
                }
            },
            numOccurrences: 1,
            fingerprint: 'some',
            validity: 'valid',
            occurrences: new Set()
        }]);

        const content = `${fakeAccessKey} "${fakeSecretKey}" "${fakeSessionToken}"`;
        const result = await detectAwsSessionKeys(content, fakeUrl);
        expect(result).toEqual([]);
    });

    test('returns a valid occurrence when credentials are valid and not in existing findings', async () => {
        const content = `some code with "${fakeAccessKey}" and "${fakeSecretKey}" inside and "${fakeSessionToken}"`;

        jest.spyOn(entropyUtils, 'calculateShannonEntropy').mockReturnValue(5.0);
        jest.spyOn(falsePositiveUtils, 'isKnownFalsePositive').mockReturnValue([false, '']);
        Object.defineProperty(falsePositiveUtils, 'falsePositiveSecretPattern', {
            value: /NOTHING_WILL_MATCH_THIS_PATTERN/,
            writable: true,
        });

        jest.spyOn(awsValidator, 'validateAWSCredentials').mockResolvedValue({
            valid: true,
            accountId: '123456789012',
            arn: 'arn:aws:iam::123456789012:user/TestUser',
        });

        jest.spyOn(common, 'getExistingFindings').mockResolvedValue([]);
        jest.spyOn(helpers, 'computeFingerprint').mockResolvedValue('mocked-fingerprint');

        const result = await detectAwsSessionKeys(content, 'https://github.com/org/repo/blob/main/app.js');

        expect(result).toHaveLength(1);
        expect(result[0]).toMatchObject({
            secretValue: {
                match: {
                    access_key_id: fakeAccessKey,
                    secret_key_id: fakeSecretKey,
                    session_key_id: fakeSessionToken
                }
            },
            validity: 'valid',
            accountId: '123456789012',
            arn: 'arn:aws:iam::123456789012:user/TestUser',
            fingerprint: 'mocked-fingerprint',
        });
    });

    test('returns empty array when credentials are valid and already in existing findings', async () => {
        const content = `some code with ${fakeAccessKey} and "${fakeSecretKey}" inside and "${fakeSessionToken}"`;

        jest.spyOn(entropyUtils, 'calculateShannonEntropy').mockReturnValue(5.0);
        jest.spyOn(falsePositiveUtils, 'isKnownFalsePositive').mockReturnValue([false, '']);
        Object.defineProperty(falsePositiveUtils, 'falsePositiveSecretPattern', {
            value: /NOTHING_WILL_MATCH_THIS_PATTERN/,
            writable: true,
        });

        jest.spyOn(awsValidator, 'validateAWSCredentials').mockResolvedValue({
            valid: true,
            accountId: '123456789012',
            arn: 'arn:aws:iam::123456789012:user/TestUser',
        });

        jest.spyOn(common, 'getExistingFindings').mockResolvedValue(mockFindings);
        jest.spyOn(helpers, 'computeFingerprint').mockResolvedValue('mocked-fingerprint');

        const result = await detectAwsSessionKeys(content, 'https://github.com/org/repo/blob/main/app.js');

        expect(result).toHaveLength(0);
    });

    test('returns empty array when secret key pattern returns undefined matches', async () => {
        const content = `some code with ${fakeAccessKey} and "-31/distributionsByOriginRequestPolicyId/{" inside and "${fakeSessionToken}"`;

        jest.spyOn(entropyUtils, 'calculateShannonEntropy').mockReturnValue(5.0);
        jest.spyOn(falsePositiveUtils, 'isKnownFalsePositive').mockReturnValue([false, '']);
        Object.defineProperty(falsePositiveUtils, 'falsePositiveSecretPattern', {
            value: /NOTHING_WILL_MATCH_THIS_PATTERN/,
            writable: true,
        });

        jest.spyOn(awsValidator, 'validateAWSCredentials').mockResolvedValue({
            valid: true,
            accountId: '123456789012',
            arn: 'arn:aws:iam::123456789012:user/TestUser',
        });

        jest.spyOn(common, 'getExistingFindings').mockResolvedValue(mockFindings);
        jest.spyOn(helpers, 'computeFingerprint').mockResolvedValue('mocked-fingerprint');

        const result = await detectAwsSessionKeys(content, 'https://github.com/org/repo/blob/main/app.js');

        expect(result).toHaveLength(0);
    });

    test('tests sourcemap is reversed to original js with accurate line numbers (access key line > session key line)', async () => {
        (global as any).chrome = {
            runtime: {
                getURL: jest.fn().mockImplementation((path: string) => `mocked-extension-url/${path}`)
            }
        };

        const content = `some code with ${fakeAccessKey} and "${fakeSecretKey}" inside and "${fakeSessionToken}"`;

        jest.spyOn(entropyUtils, 'calculateShannonEntropy').mockReturnValue(5.0);
        jest.spyOn(falsePositiveUtils, 'isKnownFalsePositive').mockReturnValue([false, '']);
        Object.defineProperty(falsePositiveUtils, 'falsePositiveSecretPattern', {
            value: /NOTHING_WILL_MATCH_THIS_PATTERN/,
            writable: true,
        });

        jest.spyOn(awsValidator, 'validateAWSCredentials').mockResolvedValue({
            valid: true,
            accountId: '123456789012',
            arn: 'arn:aws:iam::123456789012:user/TestUser',
        });

        jest.spyOn(common, 'getExistingFindings').mockResolvedValue([]);

        const mockSourceMapUrl = new URL(fakeUrl);
        jest.spyOn(common, 'getSourceMapUrl').mockReturnValue(mockSourceMapUrl);

        jest.spyOn(common, 'findSecretPosition').mockImplementation((content, key) => {
            if (key === fakeAccessKey) {
                return { line: 25, column: 4 }; // accessKey line > session key line
            } else {
                return { line: 20, column: 2 };
            }
        });

        (fetch as jest.Mock).mockResolvedValue({
            text: () => Promise.resolve('{"version":3,"sources":["App.tsx"],"sourcesContent":["console.log(\'hello\');"]}'),
        });

        const sourceContent = 'console.log("hello")';
        const withMock = jest.fn((_content, _null, callback) => {
            callback({
                originalPositionFor: jest.fn((position) => {
                    if (position.line === 25) {
                        return { source: 'App.tsx', line: 100, column: 5 };
                    } else if (position.line === 20) {
                        return { source: 'App.tsx', line: 90, column: 2 };
                    }
                    return { source: null, line: null, column: null };
                }),
                sourceContentFor: jest.fn().mockReturnValue(sourceContent),
            });
        });

        const sourceMapModule = require('../../../../../external/source-map');
        sourceMapModule.SourceMapConsumer.with = withMock;
        sourceMapModule.SourceMapConsumer.initialize = jest.fn();

        const result = await detectAwsSessionKeys(content, fakeUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent).toMatchObject({
            content: sourceContent,
            contentFilename: 'App.tsx',
            exactMatchNumbers: [100, 90, 90],
            contentStartLineNum: 85,
            contentEndLineNum: 105,
        });
    });

    test('tests sourcemap is reversed to original js with accurate line numbers (access key line < session key line)', async () => {
        (global as any).chrome = {
            runtime: {
                getURL: jest.fn().mockImplementation((path: string) => `mocked-extension-url/${path}`)
            }
        };

        const content = `some code with ${fakeAccessKey} and "${fakeSecretKey}" inside and "${fakeSessionToken}"`;

        jest.spyOn(entropyUtils, 'calculateShannonEntropy').mockReturnValue(5.0);
        jest.spyOn(falsePositiveUtils, 'isKnownFalsePositive').mockReturnValue([false, '']);
        Object.defineProperty(falsePositiveUtils, 'falsePositiveSecretPattern', {
            value: /NOTHING_WILL_MATCH_THIS_PATTERN/,
            writable: true,
        });

        jest.spyOn(awsValidator, 'validateAWSCredentials').mockResolvedValue({
            valid: true,
            accountId: '123456789012',
            arn: 'arn:aws:iam::123456789012:user/TestUser',
        });

        jest.spyOn(common, 'getExistingFindings').mockResolvedValue([]);

        const mockSourceMapUrl = new URL('https://example.com/app.js.map');
        jest.spyOn(common, 'getSourceMapUrl').mockReturnValue(mockSourceMapUrl);

        jest.spyOn(common, 'findSecretPosition').mockImplementation((content, key) => {
            if (key === fakeAccessKey) {
                return { line: 20, column: 4 }; // accessKey line < secretKey line
            } else {
                return { line: 25, column: 2 };
            }
        });

        (fetch as jest.Mock).mockResolvedValue({
            text: () => Promise.resolve('{"version":3,"sources":["App.tsx"],"sourcesContent":["console.log(\'hello\');"]}'),
        });

        const sourceContent = 'console.log("hello")';
        const withMock = jest.fn((_content, _null, callback) => {
            callback({
                originalPositionFor: jest.fn((position) => {
                    if (position.line === 20) {
                        return { source: 'App.tsx', line: 90, column: 5 };
                    } else if (position.line === 25) {
                        return { source: 'App.tsx', line: 100, column: 2 };
                    }
                    return { source: null, line: null, column: null };
                }),
                sourceContentFor: jest.fn().mockReturnValue(sourceContent),
            });
        });

        const sourceMapModule = require('../../../../../external/source-map');
        sourceMapModule.SourceMapConsumer.with = withMock;
        sourceMapModule.SourceMapConsumer.initialize = jest.fn();

        const result = await detectAwsSessionKeys(content, fakeUrl);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent).toMatchObject({
            content: sourceContent,
            contentFilename: 'App.tsx',
            exactMatchNumbers: [90, 100, 100],
            contentStartLineNum: 85,
            contentEndLineNum: 105,
        });
    });

    test('sets contentFilename to empty string when url is empty', async () => {
        const url = '';

        const content = `some code with ${fakeAccessKey} and "${fakeSecretKey}" inside and "${fakeSessionToken}"`;

        jest.spyOn(entropyUtils, 'calculateShannonEntropy').mockReturnValue(5.0);
        jest.spyOn(falsePositiveUtils, 'isKnownFalsePositive').mockReturnValue([false, '']);
        Object.defineProperty(falsePositiveUtils, 'falsePositiveSecretPattern', {
            value: /NOTHING_WILL_MATCH_THIS_PATTERN/,
            writable: true,
        });

        jest.spyOn(awsValidator, 'validateAWSCredentials').mockResolvedValue({
            valid: true,
            accountId: '123456789012',
            arn: 'arn:aws:iam::123456789012:user/TestUser',
        });

        jest.spyOn(common, 'getExistingFindings').mockResolvedValue([]);

        const result = await detectAwsSessionKeys(content, url);

        expect(result).toHaveLength(1);
        expect(result[0].sourceContent.contentFilename).toBe("");
    });

});
