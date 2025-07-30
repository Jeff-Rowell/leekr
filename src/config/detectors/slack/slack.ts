export const SLACK_TOKEN_TYPES: Record<string, string> = {
    'xoxb': 'Slack Bot Token',
    'xoxp': 'Slack User Token', 
    'xoxe.xoxp': 'Slack Workspace Access Token',
    'xoxe': 'Slack Workspace Refresh Token'
};

export const DEFAULT_SLACK_CONFIG = {
    requiredEntropy: 0,
};