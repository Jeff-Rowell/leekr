import { STS } from '@aws-sdk/client-sts';

const getCallerIdentity = async (accessKeyId: string, secretAccessKey: string, retryOn403: boolean) => {
    const sts = new STS({
        credentials: {
            accessKeyId: accessKeyId.trim(),
            secretAccessKey: secretAccessKey.trim()
        },
        region: 'us-east-1',
    });

    try {
        const data = await sts.getCallerIdentity({});
        return data;
    } catch (error) {
        if (retryOn403) {
            await new Promise(r => setTimeout(r, 5000));
            return getCallerIdentity(accessKeyId, secretAccessKey, false);
        } else {
            return false;
        }
    }
};

export async function validateAWSCredentials(
    accessKeyId: string,
    secretAccessKey: string
): Promise<{
    valid: boolean;
    accountId?: string;
    arn?: string;
    error?: string;
}> {
    try {
        const data = await getCallerIdentity(accessKeyId, secretAccessKey, true);
        if (data) {
            return {
                valid: true,
                accountId: data.Account,
                arn: data.Arn
            };
        } else {
            return {
                valid: false,
                accountId: "",
                arn: ""
            };
        }
    } catch (error) {
        console.error("Error validating AWS credentials:", error);
        return {
            valid: false,
            error: error instanceof Error ? error.message : String(error)
        };
    }
};