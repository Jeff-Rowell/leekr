export const SLACK_TOKEN_TYPES: Record<string, string> = {
    'xoxb': 'Slack Bot Token',
    'xoxp': 'Slack User Token', 
    'xoxa': 'Slack Workspace Access Token',
    'xoxr': 'Slack Workspace Refresh Token'
};

export const DEFAULT_SLACK_CONFIG = {
    requiredEntropy: 0,
};