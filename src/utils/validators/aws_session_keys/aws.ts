import CryptoJS from 'crypto-js';

const getHash = (data: string): string => {
    return CryptoJS.SHA256(data).toString(CryptoJS.enc.Hex);
};

const getHMAC = (key: CryptoJS.lib.WordArray, data: string): CryptoJS.lib.WordArray => {
    return CryptoJS.HmacSHA256(data, key);
};

const formatDate = (date: Date): { datestamp: string; amzDate: string } => {
    const pad = (n: number) => n.toString().padStart(2, '0');
    const year = date.getUTCFullYear();
    const month = pad(date.getUTCMonth() + 1);
    const day = pad(date.getUTCDate());
    const hour = pad(date.getUTCHours());
    const minute = pad(date.getUTCMinutes());
    const second = pad(date.getUTCSeconds());

    const datestamp = `${year}${month}${day}`;
    const amzDate = `${datestamp}T${hour}${minute}${second}Z`;
    return { datestamp, amzDate };
};

async function login(
    retryOn403: boolean,
    method: string,
    endpoint: string,
    canonicalQuerystring: string,
    authorizationHeader: string,
    amzDate: string,
    sessionToken: string,
    payloadHash: string): Promise<{ valid: boolean; accountId?: string; arn?: string; error?: string }> {
    const url = `${endpoint}?${canonicalQuerystring}`;
    const headers = {
        Accept: "application/json",
        Authorization: authorizationHeader,
        "x-amz-date": amzDate,
        "x-amz-security-token": sessionToken,
        "x-amz-content-sha256": payloadHash
    };

    const response = await fetch(url, {
        method,
        headers
    });

    if (response.status >= 200 && response.status < 300) {
        const identityInfo = await response.json();
        const result = identityInfo.GetCallerIdentityResponse.GetCallerIdentityResult;
        return {
            valid: true,
            accountId: result.Account,
            arn: result.Arn
        };
    } else if (retryOn403 && response.status === 403) {
        await new Promise(r => setTimeout(r, 5000));
        return login(false, method, endpoint, canonicalQuerystring, authorizationHeader, amzDate, sessionToken, payloadHash);
    } else {
        return { valid: false }
    }
}

export const validateAWSCredentials = async (
    accessKeyId: string,
    secretAccessKey: string,
    sessionToken: string
): Promise<{ valid: boolean; accountId?: string; arn?: string; error?: string }> => {
    try {
        const now = new Date();
        const { datestamp, amzDate } = formatDate(now);

        const method = "GET";
        const service = "sts";
        const host = "sts.amazonaws.com";
        const endpoint = `https://${host}`;
        const region = "us-east-1";
        const algorithm = "AWS4-HMAC-SHA256";

        const canonicalURI = "/";
        const queryParams = {
            Action: "GetCallerIdentity",
            Version: "2011-06-15"
        };

        const canonicalQuerystring = Object.keys(queryParams)
            .sort()
            .map(key => `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key as keyof typeof queryParams])}`)
            .join("&");

        const canonicalHeaders = `host:${host}\nx-amz-date:${amzDate}\nx-amz-security-token:${sessionToken}\n`;
        const signedHeaders = "host;x-amz-date;x-amz-security-token";
        const payloadHash = getHash("");

        const canonicalRequest = `${method}\n${canonicalURI}\n${canonicalQuerystring}\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;

        const credentialScope = `${datestamp}/${region}/${service}/aws4_request`;
        const stringToSign = `${algorithm}\n${amzDate}\n${credentialScope}\n${getHash(canonicalRequest)}`;

        // Corrected HMAC chaining with CryptoJS WordArray
        let signingKey = CryptoJS.enc.Utf8.parse(`AWS4${secretAccessKey}`);
        signingKey = getHMAC(signingKey, datestamp);
        signingKey = getHMAC(signingKey, region);
        signingKey = getHMAC(signingKey, service);
        signingKey = getHMAC(signingKey, "aws4_request");

        const signature = getHMAC(signingKey, stringToSign).toString(CryptoJS.enc.Hex);
        const authorizationHeader = `${algorithm} Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

        return login(true, method, endpoint, canonicalQuerystring, authorizationHeader, amzDate, sessionToken, payloadHash)

    } catch (err) {
        return {
            valid: false,
            error: err instanceof Error ? err.message : "Unknown error occurred"
        };
    }
};
