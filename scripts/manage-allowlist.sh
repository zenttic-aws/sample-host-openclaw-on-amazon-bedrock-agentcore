#!/bin/bash
# Manage the user allowlist and operator kill switch in DynamoDB.
#
# Usage:
#   ./scripts/manage-allowlist.sh add telegram:123456
#   ./scripts/manage-allowlist.sh add slack:U789ABC
#   ./scripts/manage-allowlist.sh remove telegram:123456
#   ./scripts/manage-allowlist.sh disable <user_id>
#   ./scripts/manage-allowlist.sh enable  <user_id>
#   ./scripts/manage-allowlist.sh list
#
# Uses the openclaw-identity DynamoDB table.
# Requires: aws cli, jq, appropriate IAM permissions.
# Set AWS_PROFILE and AWS_REGION as needed.
#
# Revocation now takes effect on the user's next webhook turn:
#   * `remove <channel:user_id>` deletes the ALLOW# record. The router
#     re-checks the allowlist on every turn (lambda/router/index.py
#     resolve_user / _is_currently_authorized), so the next message is
#     rejected with the "this bot is private" reply.
#   * `disable <user_id>` sets USER#<user_id>/PROFILE.status = DISABLED and
#     flips the SESSION record routeStatus to DRAINING. Both the router
#     and the cron Lambda check the status flag before resolving a route,
#     so scheduled messages and ad-hoc turns stop immediately.
#   * `enable <user_id>` clears the kill switch (status attribute removed
#     and routeStatus restored to ACTIVE).

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
    echo "Usage: $0 {add|remove|disable|enable|list} [channel:user_id|user_id]"
    echo ""
    echo "Commands:"
    echo "  add     <channel:user_id>  - Allow a user (e.g. telegram:123456)"
    echo "  remove  <channel:user_id>  - Revoke a channel identity's access"
    echo "                               (takes effect on next webhook turn)"
    echo "  disable <user_id>          - Operator kill switch: mark the user"
    echo "                               DISABLED and drain their route"
    echo "  enable  <user_id>          - Clear the kill switch for a user"
    echo "  list                       - List all allowed users"
    echo ""
    echo "Environment:"
    echo "  AWS_REGION   - AWS region (default: us-west-2)"
    echo "  AWS_PROFILE  - AWS CLI profile (optional)"
    echo "  IDENTITY_TABLE_NAME - DynamoDB table (default: openclaw-identity)"
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
    echo "The router re-checks the allowlist on every turn, so the next"
    echo "message from this identity is rejected with the \"this bot is"
    echo "private\" reply. For users with multiple linked channels, run"
    echo "'disable <user_id>' to halt all of them with a single kill switch."
}

cmd_disable() {
    local user_id="$1"
    local now_iso
    now_iso=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    echo "Disabling user $user_id (kill switch)..."
    aws dynamodb update-item \
        --table-name "$TABLE_NAME" \
        --region "$REGION" \
        $PROFILE_ARG \
        --key "{
            \"PK\": {\"S\": \"USER#${user_id}\"},
            \"SK\": {\"S\": \"PROFILE\"}
        }" \
        --update-expression "SET #status = :disabled, disabledAt = :now" \
        --condition-expression "attribute_exists(PK)" \
        --expression-attribute-names '{"#status": "status"}' \
        --expression-attribute-values "{
            \":disabled\": {\"S\": \"DISABLED\"},
            \":now\":      {\"S\": \"${now_iso}\"}
        }"

    # Best-effort flip the live SESSION record to DRAINING so admit_route
    # refuses new invocations even if a stale cache still routes to it.
    aws dynamodb update-item \
        --table-name "$TABLE_NAME" \
        --region "$REGION" \
        $PROFILE_ARG \
        --key "{
            \"PK\": {\"S\": \"USER#${user_id}\"},
            \"SK\": {\"S\": \"SESSION\"}
        }" \
        --update-expression "SET routeStatus = :draining" \
        --condition-expression "attribute_exists(PK) AND routeStatus = :active" \
        --expression-attribute-values "{
            \":draining\": {\"S\": \"DRAINING\"},
            \":active\":   {\"S\": \"ACTIVE\"}
        }" >/dev/null 2>&1 || echo "(SESSION not ACTIVE or missing; status flag still applied)"

    echo "Done. User $user_id is DISABLED. Router and cron refuse to route"
    echo "for this user on the next turn. Remove the matching ALLOW# records"
    echo "separately to also prevent re-enrollment on a new channel."
}

cmd_enable() {
    local user_id="$1"

    echo "Re-enabling user $user_id..."
    aws dynamodb update-item \
        --table-name "$TABLE_NAME" \
        --region "$REGION" \
        $PROFILE_ARG \
        --key "{
            \"PK\": {\"S\": \"USER#${user_id}\"},
            \"SK\": {\"S\": \"PROFILE\"}
        }" \
        --update-expression "REMOVE #status, disabledAt" \
        --condition-expression "attribute_exists(PK)" \
        --expression-attribute-names '{"#status": "status"}'

    aws dynamodb update-item \
        --table-name "$TABLE_NAME" \
        --region "$REGION" \
        $PROFILE_ARG \
        --key "{
            \"PK\": {\"S\": \"USER#${user_id}\"},
            \"SK\": {\"S\": \"SESSION\"}
        }" \
        --update-expression "SET routeStatus = :active" \
        --condition-expression "attribute_exists(PK) AND routeStatus = :draining" \
        --expression-attribute-values "{
            \":active\":   {\"S\": \"ACTIVE\"},
            \":draining\": {\"S\": \"DRAINING\"}
        }" >/dev/null 2>&1 || true

    echo "Done. User $user_id kill switch cleared."
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
    disable)
        [ $# -lt 2 ] && usage
        cmd_disable "$2"
        ;;
    enable)
        [ $# -lt 2 ] && usage
        cmd_enable "$2"
        ;;
    list)
        cmd_list
        ;;
    *)
        usage
        ;;
esac
