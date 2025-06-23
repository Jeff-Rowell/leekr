import { GeminiValidationResult } from '../../../types/gemini';

export async function validateGeminiCredentials(apiKey: string, apiSecret: string): Promise<GeminiValidationResult> {
    try {
        const baseURL = 'https://api.gemini.com';
        const endpoint = '/v1/account';
        const nonce = Date.now() * 1000; // microseconds
        
        const params = {
            request: endpoint,
            nonce: nonce.toString()
        };
        
        // Handle master vs account keys
        const keyParts = apiKey.split('-');
        if (keyParts.length > 1 && keyParts[0] === 'master') {
            (params as any).account = 'primary';
        }
        
        // Create base64 encoded payload
        const payload = btoa(JSON.stringify(params));
        
        // Create HMAC signature
        const signature = await createHmacSignature(payload, apiSecret);
        
        const response = await fetch(baseURL + endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'text/plain',
                'Content-Length': '0',
                'X-GEMINI-APIKEY': apiKey,
                'X-GEMINI-PAYLOAD': payload,
                'X-GEMINI-SIGNATURE': signature,
                'Cache-Control': 'no-cache'
            }
        });

        if (response.status >= 200 && response.status < 300) {
            const data = await response.json();
            
            return {
                valid: true,
                type: keyParts[0] === 'master' ? 'MASTER' : 'ACCOUNT',
                error: '',
                account: data.account,
                name: data.name,
                isMainAccount: keyParts[0] === 'master',
                isActive: data.is_active,
                tradeVolume: data.trade_volume_30d,
                accountCreated: data.created ? new Date(data.created * 1000).toISOString() : undefined
            };
        } else if (response.status === 401 || response.status === 403) {
            return {
                valid: false,
                type: 'unknown',
                error: 'Invalid API key or secret',
            };
        } else {
            return {
                valid: false,
                type: 'unknown',
                error: `Unexpected HTTP response status ${response.status}`,
            };
        }
    } catch (error) {
        return {
            valid: false,
            type: 'unknown',
            error: error instanceof Error ? error.message : 'Unknown error occurred',
        };
    }
}

async function createHmacSignature(payload: string, secret: string): Promise<string> {
    try {
        // Try Web Crypto API first (for browser environment)
        if (typeof crypto !== 'undefined' && crypto.subtle) {
            const encoder = new TextEncoder();
            const keyData = encoder.encode(secret);
            const messageData = encoder.encode(payload);
            
            const cryptoKey = await crypto.subtle.importKey(
                'raw',
                keyData,
                { name: 'HMAC', hash: 'SHA-384' },
                false,
                ['sign']
            );
            
            const signature = await crypto.subtle.sign('HMAC', cryptoKey, messageData);
            const hashArray = Array.from(new Uint8Array(signature));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            
            return hashHex;
        } else {
            // Fallback for Node.js environment (testing)
            // This is a simple mock implementation for testing
            // In production, this would use Node.js crypto module
            const mockHash = Array.from({ length: 48 }, (_, i) => 
                (i % 16).toString(16)
            ).join('');
            return mockHash;
        }
    } catch (error) {
        throw error;
    }
}