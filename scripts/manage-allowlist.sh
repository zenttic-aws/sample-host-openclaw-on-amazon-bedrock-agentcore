#!/bin/bash
# Manage the user allowlist in DynamoDB.
#
# Usage:
#   ./scripts/manage-allowlist.sh add telegram:123456
#   ./scripts/manage-allowlist.sh add slack:U789ABC
#   ./scripts/manage-allowlist.sh remove telegram:123456
#   ./scripts/manage-allowlist.sh list
#
# Uses the openclaw-identity DynamoDB table.
# Requires: aws cli, jq, appropriate IAM permissions.
# Set AWS_PROFILE and AWS_REGION as needed.

set -euo pipefail

TABLE_NAME="${IDENTITY_TABLE_NAME:-openclaw-identity}"
REGION="${AWS_REGION:-us-west-2}"
profile_args=()
if [ -n "${AWS_PROFILE:-}" ]; then
    profile_args=(--profile "$AWS_PROFILE")
fi

# Allowed channel prefixes. Keep in sync with the sibling setup scripts
# (scripts/setup-telegram.sh, scripts/setup-slack.sh).
ALLOWED_CHANNELS=("telegram" "slack")

# Validate the channel key: <channel>:<id> where <channel> is in the
# ALLOWED_CHANNELS list and <id> matches [A-Za-z0-9_-]{1,64}. This
# rejects embedded quotes, braces, whitespace, and any other characters
# that could break out of the DynamoDB JSON document the AWS CLI parses.
validate_channel_key() {
    local channel_key="$1"
    if ! [[ "$channel_key" =~ ^[a-z]+:[A-Za-z0-9_-]{1,64}$ ]]; then
        echo "ERROR: channel key must match ^[a-z]+:[A-Za-z0-9_-]{1,64}\$ (got: $channel_key)" >&2
        exit 1
    fi
    local channel="${channel_key%%:*}"
    local allowed=0
    local c
    for c in "${ALLOWED_CHANNELS[@]}"; do
        if [ "$c" = "$channel" ]; then
            allowed=1
            break
        fi
    done
    if [ "$allowed" -ne 1 ]; then
        echo "ERROR: channel '$channel' is not in the allowed set: ${ALLOWED_CHANNELS[*]}" >&2
        exit 1
    fi
}

require_jq() {
    if ! command -v jq >/dev/null 2>&1; then
        echo "ERROR: 'jq' is required but was not found on PATH. Install jq and retry." >&2
        exit 1
    fi
}

usage() {
    echo "Usage: $0 {add|remove|list} [channel:user_id]"
    echo ""
    echo "Commands:"
    echo "  add    <channel:user_id>  — Allow a user (e.g. telegram:123456)"
    echo "  remove <channel:user_id>  — Revoke a user's access"
    echo "  list                      — List all allowed users"
    echo ""
    echo "Environment:"
    echo "  AWS_REGION   — AWS region (default: us-west-2)"
    echo "  AWS_PROFILE  — AWS CLI profile (optional)"
    echo "  IDENTITY_TABLE_NAME — DynamoDB table (default: openclaw-identity)"
    exit 1
}

cmd_add() {
    local channel_key="$1"
    validate_channel_key "$channel_key"
    require_jq

    local now_iso
    now_iso=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    local item
    item=$(jq -n \
        --arg k "$channel_key" \
        --arg t "$now_iso" \
        '{PK:{S:("ALLOW#"+$k)},SK:{S:"ALLOW"},channelKey:{S:$k},addedAt:{S:$t}}')

    echo "Adding $channel_key to allowlist..."
    aws dynamodb put-item \
        --table-name "$TABLE_NAME" \
        --region "$REGION" \
        "${profile_args[@]}" \
        --item "$item" \
        --condition-expression 'begins_with(PK, :allow)' \
        --expression-attribute-values '{":allow": {"S": "ALLOW#"}}'
    echo "Done. $channel_key is now allowed."
}

cmd_remove() {
    local channel_key="$1"
    validate_channel_key "$channel_key"
    require_jq

    local key
    key=$(jq -n \
        --arg k "$channel_key" \
        '{PK:{S:("ALLOW#"+$k)},SK:{S:"ALLOW"}}')

    echo "Removing $channel_key from allowlist..."
    aws dynamodb delete-item \
        --table-name "$TABLE_NAME" \
        --region "$REGION" \
        "${profile_args[@]}" \
        --key "$key" \
        --condition-expression 'begins_with(PK, :allow)' \
        --expression-attribute-values '{":allow": {"S": "ALLOW#"}}'
    echo "Done. $channel_key is no longer allowed."
    echo "Note: If the user already has a session, they can still use it until it expires."
}

cmd_list() {
    echo "Allowed users in $TABLE_NAME ($REGION):"
    echo ""
    aws dynamodb scan \
        --table-name "$TABLE_NAME" \
        --region "$REGION" \
        "${profile_args[@]}" \
        --filter-expression "begins_with(PK, :prefix)" \
        --expression-attribute-values '{":prefix": {"S": "ALLOW#"}}' \
        --query 'Items[].{User: channelKey.S, AddedAt: addedAt.S}' \
        --output table
}

if [ $# -lt 1 ]; then
    usage
fi

case "$1" in
    add)
        [ $# -lt 2 ] && usage
        cmd_add "$2"
        ;;
    remove)
        [ $# -lt 2 ] && usage
        cmd_remove "$2"
        ;;
    list)
        cmd_list
        ;;
    *)
        usage
        ;;
esac
