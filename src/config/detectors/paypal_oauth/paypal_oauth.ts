import { PayPalOAuthDetectorConfig } from '../../../types/paypal_oauth';

export const DEFAULT_PAYPAL_OAUTH_CONFIG: PayPalOAuthDetectorConfig = {
    requiredClientIdEntropy: 4.0,
    requiredClientSecretEntropy: 4.5
};