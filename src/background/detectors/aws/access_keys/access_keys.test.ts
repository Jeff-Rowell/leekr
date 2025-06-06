import { detectAwsAccessKeys } from './access_keys';
import * as entropyUtils from '../../../../utils/accuracy/entropy';
import * as falsePositiveUtils from '../../../../utils/accuracy/falsePositives';
import * as awsValidator from '../../../../utils/validators/aws_access_keys/aws';
import * as helpers from '../../../../utils/helpers/computeFingerprint';
import * as common from '../../../../utils/helpers/common';
import { patterns } from '../../../../config/patterns';

jest.mock('../../../../utils/accuracy/entropy');
jest.mock('../../../../utils/accuracy/falsePositives');
jest.mock('../../../../utils/validators/aws_access_keys/aws');
jest.mock('../../../../utils/helpers/common');
jest.mock('../../../../../external/source-map');

global.fetch = jest.fn();

describe('detectAwsAccessKeys', () => {
    const fakeAccessKey = 'AKIAIOSFODNN7EXAMPLE';
    const fakeSecretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    const fakeUrl = 'https://example.com/app.js';

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

    test('returns empty array if no access key is found', async () => {
        const result = await detectAwsAccessKeys('no keys here', fakeUrl);
        expect(result).toEqual([]);
    });

    test('returns empty array if no secret key is found', async () => {
        const content = `${fakeAccessKey} but no secret`;
        const result = await detectAwsAccessKeys(content, fakeUrl);
        expect(result).toEqual([]);
    });

    test('returns empty array if access key entropy is too low', async () => {
        jest.spyOn(entropyUtils, 'calculateShannonEntropy').mockReturnValue(2.0);
        const content = `${fakeAccessKey} "${fakeSecretKey}"`;
        const result = await detectAwsAccessKeys(content, fakeUrl);
        expect(result).toEqual([]);
    });

    test('returns empty array if secret key is a false positive', async () => {
        (falsePositiveUtils.isKnownFalsePositive as jest.Mock).mockReturnValueOnce([false]).mockReturnValueOnce([true]);
        const content = `${fakeAccessKey} "${fakeSecretKey}"`;
        const result = await detectAwsAccessKeys(content, fakeUrl);
        expect(result).toEqual([]);
    });

    test('returns empty array if secret key entropy is too low', async () => {
        jest.spyOn(entropyUtils, 'calculateShannonEntropy').mockReturnValue(4.0);
        const content = `${fakeAccessKey} "GetCustomVerificationEmailTemplateResult"`;
        const result = await detectAwsAccessKeys(content, fakeUrl);
        expect(result).toEqual([]);
    });

    test('filters out keys already in existing findings', async () => {
        (common.getExistingFindings as jest.Mock).mockResolvedValue([{
            secretType: 'AWS Access & Secret Keys',
            secretValue: {
                match: {
                    access_key_id: fakeAccessKey,
                    secret_key_id: fakeSecretKey
                }
            },
            numOccurrences: 1,
            fingerprint: 'some',
            validity: 'valid',
            occurrences: new Set()
        }]);

        const content = `${fakeAccessKey} "${fakeSecretKey}"`;
        const result = await detectAwsAccessKeys(content, fakeUrl);
        expect(result).toEqual([]);
    });

    test('returns a valid occurrence when credentials are valid and not in existing findings', async () => {
        const content = `some code with ${fakeAccessKey} and "${fakeSecretKey}" inside`;

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

        const result = await detectAwsAccessKeys(content, 'https://github.com/org/repo/blob/main/app.js');

        expect(result).toHaveLength(1);
        expect(result[0]).toMatchObject({
            secretValue: {
                match: {
                    access_key_id: fakeAccessKey,
                    secret_key_id: fakeSecretKey,
                }
            },
            validity: 'valid',
            accountId: '123456789012',
            arn: 'arn:aws:iam::123456789012:user/TestUser',
            fingerprint: 'mocked-fingerprint',
        });
      });
});
