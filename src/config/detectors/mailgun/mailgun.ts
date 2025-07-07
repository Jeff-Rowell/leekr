import { MailgunDetectorConfig } from '../../../types/mailgun';

export const DEFAULT_MAILGUN_CONFIG: MailgunDetectorConfig = {
    requiredEntropy: 3.9
};

export const MAILGUN_RESOURCE_TYPES = {
    'API_KEY': 'Mailgun API Key'
};